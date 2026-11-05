// Package osv ingests the OSV PyPI vulnerability data: the bulk archive
// (https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip, one advisory per
// file) downloaded like every other feed, normalized into the pypi/pypi rule directory.
// resolve reads that directory and never asks OSV over the network.
package osv

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/version/pep440"
)

// ParserVersion is recorded in the feed metadata. It stays 1.0.0: the rule shape is the
// one the per-package queries produced, and `rules format` hashes the parser versions, so
// a change would make every rules archive built for this format unusable.
const ParserVersion = "1.0.0"

// SourceID is the registry id of the PyPI feed.
const SourceID = "osv-pypi"

// Vendor and Release are the rule directory the feed is published to (pypi/pypi).
const (
	Vendor  = "pypi"
	Release = "pypi"
)

type queryResponse struct {
	Vulns []vulnDoc `json:"vulns"`
}

type vulnDoc struct {
	ID        string   `json:"id"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Affected  []struct {
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

// docRules normalizes one OSV record into one rule per affected PyPI package and CVE.
// Records without a CVE id or alias are not vulnerability findings here.
func docRules(doc vulnDoc, meta rules.FeedSourceMetadata) []rules.PackageVulnerabilityRule {
	cves := cveIDs(doc.ID, doc.Aliases)
	var out []rules.PackageVulnerabilityRule
	for _, aff := range doc.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, "PyPI") {
			continue
		}
		norm := normalizePyPIName(aff.Package.Name)
		if norm == "" {
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
	return out
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

// ParseResult carries the normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
}

// ParseFile parses a PyPI all.zip archive, or one advisory JSON file. Every archive entry
// must read back intact (zip CRC): a damaged download is an error and publishes nothing.
func ParseFile(path string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ParseDocuments([][]byte{data}, meta), nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("osv pypi zip: %w", err)
	}
	defer zr.Close()
	p := newParser(meta)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("osv pypi zip entry %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("osv pypi zip entry %s: %w", f.Name, err)
		}
		p.add(data)
	}
	return p.finish(), nil
}

// ParseDocuments parses raw advisory documents: one OSV record, or a query answer
// ({"vulns": [...]}) as tests and older raw snapshots hold.
func ParseDocuments(docs [][]byte, meta rules.FeedSourceMetadata) *ParseResult {
	p := newParser(meta)
	for _, d := range docs {
		p.add(d)
	}
	return p.finish()
}

type parser struct {
	meta     rules.FeedSourceMetadata
	res      *ParseResult
	seen     map[string]bool
	packages map[string]bool
	cves     map[string]bool
}

func newParser(meta rules.FeedSourceMetadata) *parser {
	return &parser{meta: meta, res: &ParseResult{}, seen: map[string]bool{}, packages: map[string]bool{}, cves: map[string]bool{}}
}

func (p *parser) add(data []byte) {
	p.res.Metrics.RecordsDownloaded++
	var docs []vulnDoc
	var wrapped queryResponse
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Vulns != nil {
		docs = wrapped.Vulns
	} else {
		var one vulnDoc
		if err := json.Unmarshal(data, &one); err != nil {
			p.res.Metrics.Reject("document_decode_error")
			return
		}
		docs = []vulnDoc{one}
	}
	p.res.Metrics.RecordsParsed++
	produced := false
	for _, doc := range docs {
		if doc.ID == "" {
			p.res.Metrics.Reject("document_without_id")
			continue
		}
		if doc.Withdrawn != "" {
			p.res.Metrics.Reject("withdrawn")
			continue
		}
		for _, r := range docRules(doc, p.meta) {
			if p.seen[r.RuleID] {
				continue
			}
			p.seen[r.RuleID] = true
			p.res.Rules = append(p.res.Rules, r)
			p.packages[r.PackageName] = true
			p.cves[r.CVEID] = true
			produced = true
		}
	}
	if produced {
		p.res.Metrics.RecordsNormalized++
	}
}

func (p *parser) finish() *ParseResult {
	sort.Slice(p.res.Rules, func(i, j int) bool { return p.res.Rules[i].RuleID < p.res.Rules[j].RuleID })
	p.res.Metrics.RulesGenerated = len(p.res.Rules)
	p.res.Metrics.PackagesSeen = len(p.packages)
	p.res.Metrics.CVEsSeen = len(p.cves)
	if len(p.res.Rules) > 0 {
		p.res.Metrics.ReleasesSeen = 1
	}
	return p.res
}

// Publish replaces the pypi/pypi rules: the archive is complete, so no earlier package
// list is kept (the metadata names no packages, which marks the data as the full feed).
func Publish(store *rules.Store, res *ParseResult, meta rules.FeedSourceMetadata) error {
	meta.PackageNames = nil
	return store.SaveRules(Vendor, Release, res.Rules, meta)
}

// Sync downloads the archive, parses it and (unless validateOnly) publishes it.
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, validateOnly bool) (*ParseResult, rules.FeedSourceMetadata, error) {
	snap, err := dl.Fetch(src)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	meta := snap.Meta
	meta.ParserVersion = ParserVersion
	res, err := ParseFile(snap.Path, meta)
	if err != nil {
		return nil, meta, fmt.Errorf("parse %s: %w", snap.Path, err)
	}
	if validateOnly {
		return res, meta, nil
	}
	if err := Publish(store, res, meta); err != nil {
		return nil, meta, err
	}
	return res, meta, nil
}
