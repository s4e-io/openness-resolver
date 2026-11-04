// Package debian parses the Debian Security Tracker JSON export
// (https://security-tracker.debian.org/tracker/data/json) into normalized
// source-package rules per Debian release codename.
//
// Document shape:
//
//	{ "<source package>": { "<CVE id>": {
//	      "description": ..., "scope": ..., "debianbug": ...,
//	      "releases": { "<codename>": {
//	          "status": "resolved" | "open" | "undetermined",
//	          "fixed_version": "<dpkg version>",   // resolved only
//	          "urgency": "low" | "medium" | "high" | "unimportant" |
//	                     "end-of-life" | "not yet assigned" | ...,
//	          "nodsa": "...", "nodsa_reason": "postponed" | "ignored" | ...,
//	          "repositories": { "<suite>": "<version>" } } } } } }
//
// Status mapping (mirrors how Ubuntu wording is normalized):
//
//	resolved + fixed_version "0"   -> not_affected (never vulnerable in Debian)
//	resolved + fixed_version       -> released (fixed in that version)
//	open, urgency unimportant      -> ignored (Debian will not fix; potentially vulnerable)
//	open, urgency end-of-life      -> ignored (package out of security support)
//	open, nodsa_reason postponed   -> deferred
//	open                           -> needed (affected, no fix yet)
//	undetermined                   -> unknown
//
// Raw wording (status, urgency, nodsa) is preserved on every rule.
package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "debian-tracker/1.0.0"

// Vendor is the rule store vendor directory and the rule distribution.
const Vendor = "debian"

type releaseEntry struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	NoDSA        string `json:"nodsa"`
	NoDSAReason  string `json:"nodsa_reason"`
}

type cveEntry struct {
	Scope    string                  `json:"scope"`
	Releases map[string]releaseEntry `json:"releases"`
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
	// Releases lists the codenames rules were produced for, sorted.
	Releases []string
}

// ParseFile parses a tracker JSON file.
func ParseFile(path string, meta rules.FeedSourceMetadata, releases map[string]bool) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, meta, releases)
}

// Parse streams the tracker JSON one source package at a time. Only
// codenames in releases are kept; a nil set keeps every codename.
func Parse(r io.Reader, meta rules.FeedSourceMetadata, releases map[string]bool) (*ParseResult, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("tracker json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("tracker json: expected an object at top level")
	}
	res := &ParseResult{}
	packagesSeen := map[string]bool{}
	cvesSeen := map[string]bool{}
	releasesSeen := map[string]bool{}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("tracker json: %w", err)
		}
		src, _ := keyTok.(string)
		var cves map[string]cveEntry
		if err := dec.Decode(&cves); err != nil {
			return nil, fmt.Errorf("tracker json: package %q: %w", src, err)
		}
		src = strings.TrimSpace(src)
		res.Metrics.RecordsDownloaded += len(cves)
		if src == "" {
			res.Metrics.Reject("package_without_name")
			continue
		}
		ids := make([]string, 0, len(cves))
		for id := range cves {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			entry := cves[id]
			res.Metrics.RecordsParsed++
			cveID := strings.TrimSpace(id)
			if !strings.HasPrefix(cveID, "CVE-") {
				// TEMP-xxxx ids are tracker placeholders, not CVEs.
				res.Metrics.Reject("non_cve_identifier")
				continue
			}
			produced := false
			for codename, rel := range entry.Releases {
				if releases != nil && !releases[codename] {
					continue
				}
				rule, reason := buildRule(src, cveID, codename, rel, meta)
				if reason != "" {
					res.Metrics.Reject(reason)
					continue
				}
				res.Rules = append(res.Rules, rule)
				res.Metrics.RulesGenerated++
				releasesSeen[codename] = true
				produced = true
			}
			if produced {
				packagesSeen[src] = true
				cvesSeen[cveID] = true
				res.Metrics.RecordsNormalized++
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("tracker json: %w", err)
	}
	for r := range releasesSeen {
		res.Releases = append(res.Releases, r)
	}
	sort.Strings(res.Releases)
	sort.Slice(res.Rules, func(i, j int) bool { return res.Rules[i].RuleID < res.Rules[j].RuleID })
	res.Metrics.PackagesSeen = len(packagesSeen)
	res.Metrics.CVEsSeen = len(cvesSeen)
	res.Metrics.ReleasesSeen = len(releasesSeen)
	return res, nil
}

// buildRule normalizes one (source, CVE, release) entry. A non-empty
// reason means the entry was rejected.
func buildRule(src, cveID, codename string, rel releaseEntry, meta rules.FeedSourceMetadata) (rules.PackageVulnerabilityRule, string) {
	status, fixed := normalize(rel)
	if status == rules.StatusReleased && fixed == "" {
		return rules.PackageVulnerabilityRule{}, "resolved_without_fixed_version"
	}
	raw := rel.Status
	if rel.Urgency != "" {
		raw += " (urgency: " + rel.Urgency + ")"
	}
	var notes []string
	if rel.NoDSA != "" || rel.NoDSAReason != "" {
		notes = append(notes, strings.TrimSpace("no-dsa: "+rel.NoDSAReason+" "+rel.NoDSA))
	}
	return rules.PackageVulnerabilityRule{
		RuleID:           fmt.Sprintf("debian:%s:%s:%s", codename, cveID, src),
		Ecosystem:        "dpkg",
		Vendor:           Vendor,
		Distribution:     "debian",
		Release:          codename,
		PackageName:      "", // tracker rules are source-package rules
		SourcePackage:    src,
		Status:           status,
		RawStatus:        raw,
		FixedVersion:     fixed,
		Comparator:       "dpkg",
		CVEID:            cveID,
		Urgency:          rel.Urgency,
		VendorNotes:      strings.Join(notes, "; "),
		SourcePriority:   1,
		SourceSnapshotID: meta.RawObjectID,
		RawObjectID:      src + "/" + cveID,
		SourceURL:        "https://security-tracker.debian.org/tracker/" + cveID,
	}, ""
}

func normalize(rel releaseEntry) (status, fixed string) {
	urgency := strings.ToLower(strings.TrimSpace(rel.Urgency))
	switch strings.ToLower(strings.TrimSpace(rel.Status)) {
	case "resolved":
		fv := strings.TrimSpace(rel.FixedVersion)
		if fv == "0" {
			return rules.StatusNotAffected, ""
		}
		return rules.StatusReleased, fv
	case "open":
		switch {
		case urgency == "unimportant", urgency == "end-of-life":
			return rules.StatusIgnored, ""
		case strings.EqualFold(strings.TrimSpace(rel.NoDSAReason), "postponed"):
			return rules.StatusDeferred, ""
		default:
			return rules.StatusNeeded, ""
		}
	default:
		return rules.StatusUnknown, ""
	}
}

// RulesByRelease splits parsed rules per codename for the rule store.
func RulesByRelease(list []rules.PackageVulnerabilityRule) map[string][]rules.PackageVulnerabilityRule {
	out := map[string][]rules.PackageVulnerabilityRule{}
	for _, r := range list {
		out[r.Release] = append(out[r.Release], r)
	}
	return out
}

// Sync downloads the tracker JSON, parses it and publishes one rule file
// per wanted codename. Each publish replaces the previous rules for that
// codename, because the tracker document is complete.
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, releases map[string]bool, validateOnly bool) (*ParseResult, rules.FeedSourceMetadata, error) {
	snap, err := dl.Fetch(src)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	meta := snap.Meta
	meta.ParserVersion = ParserVersion
	res, err := ParseFile(snap.Path, meta, releases)
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

// Publish writes the parsed rules per codename.
func Publish(store *rules.Store, res *ParseResult, meta rules.FeedSourceMetadata) error {
	byRelease := RulesByRelease(res.Rules)
	for _, codename := range res.Releases {
		if err := store.SaveRules(Vendor, codename, byRelease[codename], meta); err != nil {
			return fmt.Errorf("publish rules %s: %w", codename, err)
		}
	}
	return nil
}
