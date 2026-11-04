// Package msrc parses Microsoft Security Response Center CVRF documents
// (https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>, JSON form) into
// normalized winbuild rules.
//
// Only "Vendor Fix" remediations (Type 2) that carry a FixedBuild are turned
// into rules, and only for operating-system products whose CPE starts with
// cpe:2.3:o:microsoft:windows. Everything else (Office, .NET, Edge, ...) is
// counted as skipped, never guessed.
package msrc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/version/winbuild"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "msrc-cvrf/1.0.0"

// Vendor and distribution identity used on every rule.
const (
	Vendor       = "microsoft"
	Distribution = "windows"
	// PackageName is the single synthetic package an OS build is modelled as.
	PackageName = "windows"
)

const remediationVendorFix = 2
const threatSeverity = 3

// Document is the subset of the CVRF JSON the parser reads.
type Document struct {
	DocumentTracking struct {
		Identification struct {
			ID struct {
				Value string `json:"Value"`
			} `json:"ID"`
		} `json:"Identification"`
		CurrentReleaseDate string `json:"CurrentReleaseDate"`
	} `json:"DocumentTracking"`
	ProductTree struct {
		FullProductName []struct {
			ProductID string `json:"ProductID"`
			CPE       string `json:"CPE"`
			Value     string `json:"Value"`
		} `json:"FullProductName"`
	} `json:"ProductTree"`
	Vulnerability []struct {
		Title struct {
			Value string `json:"Value"`
		} `json:"Title"`
		CVE         string `json:"CVE"`
		ReleaseDate string `json:"ReleaseDate"`
		Threats     []struct {
			Type        int `json:"Type"`
			Description struct {
				Value string `json:"Value"`
			} `json:"Description"`
			ProductID []string `json:"ProductID"`
		} `json:"Threats"`
		Remediations []struct {
			Type        int `json:"Type"`
			Description struct {
				Value string `json:"Value"`
			} `json:"Description"`
			URL             string   `json:"URL"`
			Supercedence    string   `json:"Supercedence"`
			ProductID       []string `json:"ProductID"`
			SubType         string   `json:"SubType"`
			FixedBuild      string   `json:"FixedBuild"`
			RestartRequired struct {
				Value string `json:"Value"`
			} `json:"RestartRequired"`
		} `json:"Remediations"`
	} `json:"Vulnerability"`
}

// product is one Windows OS product from the product tree.
type product struct {
	ID         string
	Key        string // lowercase CPE product, e.g. windows_server_2022
	Arch       string // amd64 | arm64 | 386 | "" (all)
	Name       string
	ServerCore bool
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
	Month   string
	// Products lists the Windows OS product keys seen in the document.
	Products []string
	// Skipped counts remediations that were not turned into rules, by reason.
	Skipped map[string]int
}

// ParseFile parses one monthly CVRF JSON document.
func ParseFile(path string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, meta)
}

// Parse parses a CVRF JSON stream.
func Parse(r io.Reader, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode cvrf json: %w", err)
	}
	res := &ParseResult{Month: doc.DocumentTracking.Identification.ID.Value, Skipped: map[string]int{}}

	products := map[string]product{}
	keys := map[string]bool{}
	for _, p := range doc.ProductTree.FullProductName {
		key, arch, ok := windowsProductFromCPE(p.CPE)
		if !ok {
			continue
		}
		key = fixupProductKey(key, p.Value)
		products[p.ProductID] = product{ID: p.ProductID, Key: key, Arch: arch, Name: p.Value, ServerCore: strings.Contains(p.Value, "Server Core")}
		keys[key] = true
	}
	for k := range keys {
		res.Products = append(res.Products, k)
	}
	sort.Strings(res.Products)

	published := parseTime(doc.DocumentTracking.CurrentReleaseDate)

	for _, v := range doc.Vulnerability {
		res.Metrics.RecordsDownloaded++
		cve := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !strings.HasPrefix(cve, "CVE-") {
			res.Skipped["no_cve_id"]++
			continue
		}
		res.Metrics.CVEsSeen++
		severity := map[string]string{}
		for _, t := range v.Threats {
			if t.Type != threatSeverity {
				continue
			}
			for _, pid := range t.ProductID {
				severity[pid] = strings.ToLower(strings.TrimSpace(t.Description.Value))
			}
		}
		relDate := parseTime(v.ReleaseDate)
		if relDate == nil {
			relDate = published
		}
		for _, rem := range v.Remediations {
			if rem.Type != remediationVendorFix {
				continue
			}
			res.Metrics.RecordsParsed++
			// Product filter first so skip counters describe Windows OS
			// remediations only (Office/.NET/Azure Linux carry other formats).
			var osProducts []product
			for _, pid := range rem.ProductID {
				if p, ok := products[pid]; ok {
					osProducts = append(osProducts, p)
				} else {
					res.Skipped["non_windows_os_product"]++
				}
			}
			if len(osProducts) == 0 {
				continue
			}
			if strings.TrimSpace(rem.FixedBuild) == "" {
				res.Skipped["no_fixed_build"]++
				continue
			}
			fixed, err := winbuild.Parse(rem.FixedBuild)
			if err != nil {
				res.Skipped["bad_fixed_build"]++
				res.Metrics.RecordsRejected++
				continue
			}
			if fixed.Build < minOSBuild {
				// "1.003" style values (IE Cumulative on Server 2008/2012)
				// are a component version, not an OS build.UBR.
				res.Skipped["non_os_fixed_build"]++
				continue
			}
			kb := strings.TrimSpace(rem.Description.Value)
			for _, p := range osProducts {
				pid := p.ID
				// KB is part of the id: Server 2012/2016 get both a Monthly
				// Rollup and a Security Only fix for the same CVE.
				rule := rules.PackageVulnerabilityRule{
					RuleID:           "msrc:" + cve + ":" + pid + ":KB" + kb,
					Ecosystem:        winbuild.Ecosystem,
					Vendor:           Vendor,
					Distribution:     Distribution,
					Release:          p.Key,
					Architecture:     p.Arch,
					PackageName:      PackageName,
					SourcePackage:    p.Key,
					Status:           rules.StatusReleased,
					RawStatus:        rem.SubType,
					FixedVersion:     fixed.String(),
					Comparator:       winbuild.Ecosystem,
					CVEID:            cve,
					Urgency:          severity[pid],
					VendorNotes:      v.Title.Value,
					SourcePriority:   1,
					PublishedAt:      relDate,
					UpdatedAt:        published,
					SourceSnapshotID: meta.RawObjectID,
					RawObjectID:      meta.RawObjectID,
					SourceURL:        rem.URL,
					RestartRequired:  strings.EqualFold(rem.RestartRequired.Value, "yes"),
				}
				if kb != "" {
					rule.AdvisoryIDs = []string{"KB" + kb}
				}
				if s := strings.TrimSpace(rem.Supercedence); s != "" {
					rule.Supersedes = []string{"KB" + s}
				}
				if p.ServerCore {
					rule.VendorNotes += " (Server Core installation)"
				}
				res.Rules = append(res.Rules, rule)
				res.Metrics.RulesGenerated++
			}
		}
	}
	res.Metrics.RecordsNormalized = res.Metrics.RulesGenerated
	res.Metrics.ReleasesSeen = len(res.Products)
	res.Metrics.PackagesSeen = len(res.Products)
	sort.Slice(res.Rules, func(i, j int) bool { return res.Rules[i].RuleID < res.Rules[j].RuleID })
	return res, nil
}

// minOSBuild is below every Windows NT 6.0+ build number (Server 2008 is 6003).
const minOSBuild = 6000

// productKeyFixups corrects CPE product keys MSRC published with a typo. A
// fixup applies only when the product name confirms it: the December 2025
// and February 2026 documents carry cpe ...:windows_11_2H2:... for the
// product named "Windows 11 Version 25H2 for x64-based Systems".
var productKeyFixups = map[string]struct{ nameHas, key string }{
	"windows_11_2h2": {"Version 25H2", "windows_11_25h2"},
}

func fixupProductKey(key, name string) string {
	if f, ok := productKeyFixups[key]; ok && strings.Contains(name, f.nameHas) {
		return f.key
	}
	return key
}

// windowsProductFromCPE maps cpe:2.3:o:microsoft:windows_server_2022:*:...:x64:*
// to (windows_server_2022, amd64). Non-OS and non-Windows CPEs are rejected.
func windowsProductFromCPE(cpe string) (key, arch string, ok bool) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 12 || parts[2] != "o" || parts[3] != "microsoft" || !strings.HasPrefix(parts[4], "windows") {
		return "", "", false
	}
	key = strings.ToLower(parts[4])
	switch strings.ToLower(parts[11]) {
	case "x64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	case "x86":
		arch = "386"
	default:
		arch = ""
	}
	return key, arch, true
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Year() < 1990 {
				// CVRF uses 0001-01-01T00:00:00 for "no date".
				return nil
			}
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// MergeRules lets rules from a newer month replace same-ID rules.
func MergeRules(old, fresh []rules.PackageVulnerabilityRule) []rules.PackageVulnerabilityRule {
	byID := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range old {
		byID[r.RuleID] = r
	}
	for _, r := range fresh {
		byID[r.RuleID] = r
	}
	out := make([]rules.PackageVulnerabilityRule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// Sync downloads one monthly document and merges its rules into the per
// product rule files (normalized/microsoft/<product>/rules.json).
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
	byProduct := map[string][]rules.PackageVulnerabilityRule{}
	for _, r := range res.Rules {
		byProduct[r.Release] = append(byProduct[r.Release], r)
	}
	for _, key := range res.Products {
		existing, err := store.LoadRules(Vendor, key)
		if err != nil {
			return nil, meta, err
		}
		merged := MergeRules(existing, byProduct[key])
		if err := store.SaveRules(Vendor, key, merged, meta); err != nil {
			return nil, meta, fmt.Errorf("publish rules %s: %w", key, err)
		}
	}
	return res, meta, nil
}
