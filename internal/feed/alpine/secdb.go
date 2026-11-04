// Package alpine parses Alpine's official secdb
// (https://secdb.alpinelinux.org/<branch>/{main,community}.json) into
// normalized package rules for container-scope APK packages.
package alpine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "alpine-secdb/1.0.0"

// secdbFile is the raw secdb JSON structure.
type secdbFile struct {
	DistroVersion string `json:"distroversion"` // e.g. "v3.18"
	RepoName      string `json:"reponame"`      // main | community
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			SecFixes map[string][]string `json:"secfixes"` // fixed version -> CVE ids
		} `json:"pkg"`
	} `json:"packages"`
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
	Branch  string
}

// ParseFile parses a secdb JSON file.
func ParseFile(path string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, meta)
}

// Parse consumes secdb JSON and produces normalized rules.
//
// Alpine semantics: `"<version>": [CVE...]` means the CVEs are fixed in that
// package version; the special version "0" means the package was never
// affected (normalized to not_affected).
func Parse(r io.Reader, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	var db secdbFile
	dec := json.NewDecoder(r)
	if err := dec.Decode(&db); err != nil {
		return nil, fmt.Errorf("secdb json: %w", err)
	}
	if db.DistroVersion == "" {
		return nil, fmt.Errorf("secdb file has no distroversion")
	}
	res := &ParseResult{Branch: db.DistroVersion}
	cvesSeen := map[string]bool{}
	packagesSeen := map[string]bool{}

	for _, entry := range db.Packages {
		res.Metrics.RecordsDownloaded++
		name := strings.TrimSpace(entry.Pkg.Name)
		if name == "" {
			res.Metrics.Reject("package_without_name")
			continue
		}
		res.Metrics.RecordsParsed++
		packagesSeen[name] = true
		for fixedVersion, cves := range entry.Pkg.SecFixes {
			fixedVersion = strings.TrimSpace(fixedVersion)
			if fixedVersion == "" {
				res.Metrics.Reject("empty_fixed_version")
				continue
			}
			status := rules.StatusReleased
			if fixedVersion == "0" {
				status = rules.StatusNotAffected
			}
			for _, cveRaw := range cves {
				// secdb entries can be "CVE-2023-1234" or "CVE-2023-1234 (XSA-123)".
				cve := strings.Fields(strings.TrimSpace(cveRaw))
				if len(cve) == 0 {
					res.Metrics.Reject("empty_cve_entry")
					continue
				}
				cveID := cve[0]
				cvesSeen[cveID] = true
				rule := rules.PackageVulnerabilityRule{
					RuleID:           fmt.Sprintf("alpine:%s:%s:%s:%s:%s", db.DistroVersion, db.RepoName, cveID, name, fixedVersion),
					Ecosystem:        "apk",
					Vendor:           "alpine",
					Distribution:     "alpine",
					Release:          db.DistroVersion,
					Architecture:     "",
					PackageName:      name,
					SourcePackage:    name, // secdb keys are origin (source) package names
					Status:           status,
					RawStatus:        fixedVersion,
					FixedVersion:     fixedVersion,
					Comparator:       "apk",
					CVEID:            cveID,
					SourcePriority:   1,
					VendorNotes:      strings.TrimSpace(cveRaw),
					SourceSnapshotID: meta.RawObjectID,
					RawObjectID:      db.RepoName + ":" + name,
					SourceURL:        meta.SourceURL,
				}
				if status == rules.StatusNotAffected {
					rule.FixedVersion = ""
				}
				res.Rules = append(res.Rules, rule)
				res.Metrics.RulesGenerated++
			}
		}
		res.Metrics.RecordsNormalized++
	}
	res.Metrics.PackagesSeen = len(packagesSeen)
	res.Metrics.CVEsSeen = len(cvesSeen)
	res.Metrics.ReleasesSeen = 1
	return res, nil
}

// Sync runs the pipeline for one secdb source and merges the result into the
// per-branch rule store (main + community are stored together per branch).
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, existing []rules.PackageVulnerabilityRule) (*ParseResult, rules.FeedSourceMetadata, error) {
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
	merged := mergeRules(existing, res.Rules)
	if err := store.SaveRules("alpine", res.Branch, merged, meta); err != nil {
		return nil, meta, fmt.Errorf("publish rules: %w", err)
	}
	return res, meta, nil
}

// mergeRules combines rule lists, letting newer rules replace same-ID rules.
func mergeRules(old, new_ []rules.PackageVulnerabilityRule) []rules.PackageVulnerabilityRule {
	byID := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range old {
		byID[r.RuleID] = r
	}
	for _, r := range new_ {
		byID[r.RuleID] = r
	}
	out := make([]rules.PackageVulnerabilityRule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	return out
}
