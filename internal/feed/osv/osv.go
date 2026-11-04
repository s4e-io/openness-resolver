// Package osv ingests OSV PyPI vulnerability data.
package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/version/pep440"
)

const ParserVersion = "1.0.0"

// DefaultEndpoint is the public OSV query API.
const DefaultEndpoint = "https://api.osv.dev/v1/query"

// Endpoint is where package queries go: DefaultEndpoint, or a mirror with the same
// request and answer (feed sync --osv-url, or OPENNESS_OSV_URL).
var Endpoint = DefaultEndpoint

// Headers are sent with every query, for a mirror that wants them (OPENNESS_OSV_HEADERS:
// one "Name: value" per line, kept off the command line).
var Headers = map[string]string{}

// ParseHeaders reads "Name: value" lines; blank and malformed lines are skipped.
func ParseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if ok && name != "" && value != "" {
			out[name] = value
		}
	}
	return out
}

type queryResponse struct {
	Vulns []vulnDoc `json:"vulns"`
}

type vulnDoc struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// FetchPackage downloads OSV vulnerabilities for one PyPI package via the OSV API.
func FetchPackage(client *http.Client, pkg string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"ecosystem": "PyPI", "name": pkg},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, Endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query %s: HTTP %d", pkg, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ParsePackage normalizes OSV JSON for one PyPI package into resolver rules.
func ParsePackage(body []byte, meta rules.FeedSourceMetadata, pkgName string) ([]rules.PackageVulnerabilityRule, error) {
	var resp queryResponse
	if len(body) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		var docs []vulnDoc
		if err2 := json.Unmarshal(body, &docs); err2 != nil {
			var one vulnDoc
			if err3 := json.Unmarshal(body, &one); err3 != nil {
				return nil, err3
			}
			docs = []vulnDoc{one}
		}
		resp.Vulns = docs
	}
	norm := normalizePyPIName(pkgName)
	var out []rules.PackageVulnerabilityRule
	for _, doc := range resp.Vulns {
		cves := cveIDs(doc.ID, doc.Aliases)
		for _, aff := range doc.Affected {
			if !strings.EqualFold(aff.Package.Ecosystem, "PyPI") {
				continue
			}
			if normalizePyPIName(aff.Package.Name) != norm {
				continue
			}
			fixed := highestFixed(aff.Ranges)
			for _, cve := range cves {
				status := rules.StatusReleased
				if fixed == "" {
					status = rules.StatusNeeded
				}
				out = append(out, rules.PackageVulnerabilityRule{
					RuleID:           fmt.Sprintf("osv:pypi:%s:%s:%s", norm, cve, doc.ID),
					Ecosystem:        "pypi",
					Vendor:           "osv",
					Distribution:     "pypi",
					Release:          "",
					PackageName:      norm,
					SourcePackage:    norm,
					Status:           status,
					RawStatus:        doc.ID,
					FixedVersion:     fixed,
					Comparator:       "pep440",
					CVEID:            cve,
					AdvisoryIDs:      []string{doc.ID},
					SourcePriority:   4,
					SourceSnapshotID: meta.RawObjectID,
					RawObjectID:      meta.RawObjectID,
					SourceURL:        meta.SourceURL,
				})
			}
		}
	}
	return out, nil
}

func highestFixed(ranges []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	} `json:"events"`
}) string {
	best := ""
	for _, r := range ranges {
		for _, ev := range r.Events {
			if ev.Fixed == "" {
				continue
			}
			if best == "" {
				best = ev.Fixed
				continue
			}
			if c, err := pep440.Compare(ev.Fixed, best); err == nil && c > 0 {
				best = ev.Fixed
			}
		}
	}
	return best
}

func cveIDs(id string, aliases []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(s, "CVE-") && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(id)
	for _, a := range aliases {
		add(a)
	}
	return out
}

func normalizePyPIName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
}

// SyncPackages fetches and stores normalized PyPI rules for package names.
func SyncPackages(dataDir string, packages []string) (rules.FeedSourceMetadata, []rules.PackageVulnerabilityRule, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	meta := rules.FeedSourceMetadata{
		SourceName:    "osv-pypi",
		SourceURL:     Endpoint,
		DownloadedAt:  time.Now().UTC(),
		ParserVersion: ParserVersion,
		RawObjectID:   fmt.Sprintf("pypi-%d", time.Now().Unix()),
	}
	rawDir := filepath.Join(dataDir, "raw", "osv", meta.RawObjectID)
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return meta, nil, err
	}
	var all []rules.PackageVulnerabilityRule
	for _, pkg := range packages {
		body, err := FetchPackage(client, pkg)
		if err != nil {
			return meta, nil, fmt.Errorf("fetch %s: %w", pkg, err)
		}
		_ = os.WriteFile(filepath.Join(rawDir, pkg+".json"), body, 0o644)
		meta.SourceURL = Endpoint + " package=" + pkg
		rs, err := ParsePackage(body, meta, pkg)
		if err != nil {
			return meta, nil, err
		}
		all = append(all, rs...)
	}
	return meta, all, nil
}

// LoadCachedRules loads previously synced PyPI rules from data dir.
func LoadCachedRules(dataDir string) ([]rules.PackageVulnerabilityRule, error) {
	path := filepath.Join(dataDir, "normalized", "pypi", "rules.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ruleset rules.RuleSet
	if err := json.Unmarshal(b, &ruleset); err != nil {
		return nil, err
	}
	return ruleset.Rules, nil
}
