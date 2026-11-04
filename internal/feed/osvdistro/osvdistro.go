// Package osvdistro parses the OSV bulk exports that RPM distribution
// vendors publish about their own errata
// (https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip)
// into normalized rpm package rules per release.
//
// One archive holds one JSON advisory per file. Each affected[] entry names
// a package and an OSV ecosystem string that carries the release:
//
//	Rocky Linux   "Rocky Linux:9"                        source (SRPM) names
//	AlmaLinux     "AlmaLinux:9"                          binary names
//	Red Hat       "Red Hat:enterprise_linux:9::baseos"   binary names
//	openSUSE      "openSUSE:Leap 15.6"                   source names, binaries
//	                                                     in ecosystem_specific
//
// Ranges are type ECOSYSTEM with introduced/fixed events in rpm EVR form.
// Only ecosystem strings that map to exactly one host release are used;
// everything else (EUS/AUS streams, SLES modules, other vendors in the same
// archive) is counted and skipped, never guessed.
package osvdistro

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "osv-distro/1.0.0"

// Distro describes how one vendor's OSV ecosystem maps onto host releases.
type Distro struct {
	// Vendor is the rule store directory, rule Vendor and rule Distribution
	// (the normalized platform distribution id).
	Vendor string
	// ecosystemRe captures the release key from affected[].package.ecosystem.
	ecosystemRe *regexp.Regexp
	// SourceNames means package.name is the source (SRPM) package name.
	SourceNames bool
}

// Release returns the release key an OSV ecosystem string maps to.
func (d Distro) Release(ecosystem string) (string, bool) {
	m := d.ecosystemRe.FindStringSubmatch(strings.TrimSpace(ecosystem))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Distros lists the supported OSV distribution feeds by vendor id.
var Distros = map[string]Distro{
	"rocky": {
		Vendor:      "rocky",
		ecosystemRe: regexp.MustCompile(`^Rocky Linux:([0-9]+)$`),
		SourceNames: true,
	},
	"almalinux": {
		Vendor:      "almalinux",
		ecosystemRe: regexp.MustCompile(`^AlmaLinux:([0-9]+)$`),
	},
	"rhel": {
		// Mainline RHEL repositories only (baseos, appstream, crb, ...).
		// EUS/AUS/E4S/TUS streams use other product names and are skipped.
		Vendor:      "rhel",
		ecosystemRe: regexp.MustCompile(`^Red Hat:enterprise_linux:([0-9]+)::[A-Za-z0-9_.-]+$`),
	},
	"opensuse": {
		Vendor:      "opensuse",
		ecosystemRe: regexp.MustCompile(`^openSUSE:Leap ([0-9]+\.[0-9]+)$`),
		SourceNames: true,
	},
}

// --- OSV document subset ---

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string     `json:"type"`
		Events []osvEvent `json:"events"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Binaries []map[string]string `json:"binaries"`
	} `json:"ecosystem_specific"`
}

type osvDoc struct {
	ID         string        `json:"id"`
	Summary    string        `json:"summary"`
	Published  string        `json:"published"`
	Modified   string        `json:"modified"`
	Withdrawn  string        `json:"withdrawn"`
	Aliases    []string      `json:"aliases"`
	Upstream   []string      `json:"upstream"`
	Related    []string      `json:"related"`
	Affected   []osvAffected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
	// Releases lists the release keys rules were produced for, sorted.
	Releases []string
}

// parser accumulates rules over many documents.
type parser struct {
	distro   Distro
	releases map[string]bool
	meta     rules.FeedSourceMetadata
	res      *ParseResult
	byID     map[string]int
	packages map[string]bool
	cves     map[string]bool
	rels     map[string]bool
}

func newParser(d Distro, releases map[string]bool, meta rules.FeedSourceMetadata) *parser {
	return &parser{
		distro: d, releases: releases, meta: meta,
		res:      &ParseResult{},
		byID:     map[string]int{},
		packages: map[string]bool{},
		cves:     map[string]bool{},
		rels:     map[string]bool{},
	}
}

func (p *parser) finish() *ParseResult {
	for r := range p.rels {
		p.res.Releases = append(p.res.Releases, r)
	}
	sort.Strings(p.res.Releases)
	sort.Slice(p.res.Rules, func(i, j int) bool { return p.res.Rules[i].RuleID < p.res.Rules[j].RuleID })
	p.res.Metrics.PackagesSeen = len(p.packages)
	p.res.Metrics.CVEsSeen = len(p.cves)
	p.res.Metrics.ReleasesSeen = len(p.rels)
	return p.res
}

// ParseFile parses an OSV all.zip archive, or a single advisory JSON file.
// Only releases in the set are kept; a nil set keeps every release.
func ParseFile(path string, d Distro, releases map[string]bool, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p := newParser(d, releases, meta)
		p.add(data)
		return p.finish(), nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("osv zip: %w", err)
	}
	defer zr.Close()
	p := newParser(d, releases, meta)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			p.res.Metrics.Reject("zip_entry_unreadable")
			continue
		}
		// Single advisories are small; cap reads so a corrupt entry cannot
		// exhaust memory.
		data, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			p.res.Metrics.Reject("zip_entry_unreadable")
			continue
		}
		p.add(data)
	}
	return p.finish(), nil
}

// ParseDocuments parses raw advisory JSON documents (tests, imports).
func ParseDocuments(docs [][]byte, d Distro, releases map[string]bool, meta rules.FeedSourceMetadata) *ParseResult {
	p := newParser(d, releases, meta)
	for _, data := range docs {
		p.add(data)
	}
	return p.finish()
}

func (p *parser) add(data []byte) {
	p.res.Metrics.RecordsDownloaded++
	var doc osvDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		p.res.Metrics.Reject("document_decode_error")
		return
	}
	p.res.Metrics.RecordsParsed++
	if doc.ID == "" {
		p.res.Metrics.Reject("document_without_id")
		return
	}
	if doc.Withdrawn != "" {
		p.res.Metrics.Reject("withdrawn")
		return
	}
	// Affected entries for other vendors or unsupported product streams are
	// expected in shared archives; they are not counted as rejections.
	var relevant []osvAffected
	for _, a := range doc.Affected {
		release, ok := p.distro.Release(a.Package.Ecosystem)
		if !ok {
			continue
		}
		if p.releases != nil && !p.releases[release] {
			continue
		}
		relevant = append(relevant, a)
	}
	if len(relevant) == 0 {
		return
	}
	cves := cveIDs(doc)
	if len(cves) == 0 {
		// Bug-fix and enhancement errata without a CVE are not
		// vulnerability findings.
		p.res.Metrics.Reject("advisory_without_cve")
		return
	}
	urgency := urgencyFromSummary(doc.Summary)
	sourceURL := advisoryURL(doc)
	var published *time.Time
	if t, err := time.Parse(time.RFC3339, doc.Published); err == nil {
		published = &t
	}
	produced := false
	for _, a := range relevant {
		release, _ := p.distro.Release(a.Package.Ecosystem)
		name := strings.TrimSpace(a.Package.Name)
		if name == "" {
			p.res.Metrics.Reject("package_without_name")
			continue
		}
		for _, rg := range a.Ranges {
			if !strings.EqualFold(rg.Type, "ECOSYSTEM") {
				p.res.Metrics.Reject("range_type_" + strings.ToLower(rg.Type))
				continue
			}
			for _, iv := range intervals(rg.Events) {
				if iv.lastAffected {
					p.res.Metrics.Reject("last_affected_unsupported")
					continue
				}
				for _, t := range p.targets(name, iv.fixed, a) {
					if isDebugPackage(t.binary) || (t.binary == "" && isDebugPackage(t.source)) {
						continue
					}
					for _, cve := range cves {
						p.emit(doc, release, cve, t, iv.introduced, urgency, sourceURL, published, a.Package.Ecosystem)
						produced = true
					}
				}
			}
		}
	}
	if produced {
		p.res.Metrics.RecordsNormalized++
	}
}

type target struct {
	binary string // "" for a source-level rule
	source string // "" when the feed names binaries only
	fixed  string
}

// targets expands one affected package into rule targets.
func (p *parser) targets(name, fixed string, a osvAffected) []target {
	if !p.distro.SourceNames {
		return []target{{binary: name, fixed: fixed}}
	}
	// When every binary carries the package's fixed version, one
	// source-level rule (matched through the installed SOURCERPM) says the
	// same thing as one rule per binary at a fraction of the size. Binaries
	// with their own versions keep per-binary rules, so a source-level fixed
	// version is never compared against a differently versioned binary.
	uniform := fixed != ""
	for _, m := range a.EcosystemSpecific.Binaries {
		for _, ver := range m {
			if v := strings.TrimSpace(ver); v != "" && v != fixed {
				uniform = false
			}
		}
	}
	if uniform {
		return []target{{source: name, fixed: fixed}}
	}
	var out []target
	for _, m := range a.EcosystemSpecific.Binaries {
		for bin, ver := range m {
			bin = strings.TrimSpace(bin)
			if bin == "" {
				continue
			}
			fv := strings.TrimSpace(ver)
			if fv == "" || fixed == "" {
				fv = fixed
			}
			out = append(out, target{binary: bin, source: name, fixed: fv})
		}
	}
	if len(out) == 0 {
		out = append(out, target{source: name, fixed: fixed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].binary < out[j].binary })
	return out
}

func (p *parser) emit(doc osvDoc, release, cve string, t target, introduced, urgency, sourceURL string, published *time.Time, ecosystem string) {
	ident := t.binary
	if ident == "" {
		ident = "src:" + t.source
	}
	id := fmt.Sprintf("%s:%s:%s:%s:%s", p.distro.Vendor, release, doc.ID, cve, ident)
	if introduced != "" {
		id += ":from:" + introduced
	}
	if _, dup := p.byID[id]; dup {
		// The same package is listed under several repositories of one
		// release (baseos and appstream); one rule is enough.
		return
	}
	status := rules.StatusReleased
	raw := "fixed"
	if t.fixed == "" {
		status = rules.StatusNeeded
		raw = "affected, no fixed event"
	}
	r := rules.PackageVulnerabilityRule{
		RuleID:            id,
		Ecosystem:         "rpm",
		Vendor:            p.distro.Vendor,
		Distribution:      p.distro.Vendor,
		Release:           release,
		PackageName:       t.binary,
		SourcePackage:     t.source,
		Status:            status,
		RawStatus:         raw + " (" + ecosystem + ")",
		FixedVersion:      t.fixed,
		IntroducedVersion: introduced,
		Comparator:        "rpm",
		CVEID:             cve,
		AdvisoryIDs:       []string{doc.ID},
		Urgency:           urgency,
		VendorNotes:       doc.Summary,
		SourcePriority:    1,
		PublishedAt:       published,
		SourceSnapshotID:  p.meta.RawObjectID,
		RawObjectID:       doc.ID,
		SourceURL:         sourceURL,
	}
	p.byID[id] = len(p.res.Rules)
	p.res.Rules = append(p.res.Rules, r)
	p.res.Metrics.RulesGenerated++
	p.rels[release] = true
	p.cves[cve] = true
	if t.binary != "" {
		p.packages[t.binary] = true
	} else {
		p.packages[t.source] = true
	}
}

type interval struct {
	introduced   string // "" when the range starts at "0"
	fixed        string // "" when no fix is published
	lastAffected bool
}

// intervals pairs OSV events into [introduced, fixed) intervals.
func intervals(events []osvEvent) []interval {
	var out []interval
	var cur *interval
	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			if cur != nil {
				out = append(out, *cur)
			}
			intro := strings.TrimSpace(ev.Introduced)
			if intro == "0" {
				intro = ""
			}
			cur = &interval{introduced: intro}
		case ev.Fixed != "":
			if cur == nil {
				cur = &interval{}
			}
			cur.fixed = strings.TrimSpace(ev.Fixed)
			out = append(out, *cur)
			cur = nil
		case ev.LastAffected != "":
			if cur == nil {
				cur = &interval{}
			}
			cur.lastAffected = true
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func cveIDs(doc osvDoc) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(s, "CVE-") && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(doc.ID)
	for _, list := range [][]string{doc.Aliases, doc.Upstream, doc.Related} {
		for _, s := range list {
			add(s)
		}
	}
	sort.Strings(out)
	return out
}

// urgencyFromSummary reads the Red Hat style severity prefix
// ("Important: openssl security update").
func urgencyFromSummary(summary string) string {
	i := strings.IndexByte(summary, ':')
	if i <= 0 {
		return ""
	}
	switch w := strings.ToLower(strings.TrimSpace(summary[:i])); w {
	case "low", "moderate", "important", "critical":
		return w
	}
	return ""
}

func advisoryURL(doc osvDoc) string {
	for _, r := range doc.References {
		if strings.EqualFold(r.Type, "ADVISORY") && r.URL != "" {
			return r.URL
		}
	}
	return ""
}

// isDebugPackage reports debuginfo/debugsource packages, which are never
// a runtime attack surface and multiply the rule count.
func isDebugPackage(name string) bool {
	return strings.HasSuffix(name, "-debuginfo") || strings.HasSuffix(name, "-debugsource") ||
		strings.Contains(name, "-debuginfo-")
}

// RulesByRelease splits parsed rules per release for the rule store.
func RulesByRelease(list []rules.PackageVulnerabilityRule) map[string][]rules.PackageVulnerabilityRule {
	out := map[string][]rules.PackageVulnerabilityRule{}
	for _, r := range list {
		out[r.Release] = append(out[r.Release], r)
	}
	return out
}

// Publish writes the parsed rules per release. The archive is complete, so
// each publish replaces the previous rules for that release.
func Publish(store *rules.Store, d Distro, res *ParseResult, meta rules.FeedSourceMetadata) error {
	byRelease := RulesByRelease(res.Rules)
	for _, rel := range res.Releases {
		if err := store.SaveRules(d.Vendor, rel, byRelease[rel], meta); err != nil {
			return fmt.Errorf("publish rules %s/%s: %w", d.Vendor, rel, err)
		}
	}
	return nil
}

// Sync downloads one vendor archive, parses it and publishes the wanted
// releases.
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, releases map[string]bool, validateOnly bool) (*ParseResult, rules.FeedSourceMetadata, error) {
	d, ok := Distros[src.Vendor]
	if !ok {
		return nil, rules.FeedSourceMetadata{}, fmt.Errorf("source %s: vendor %q has no OSV distro mapping", src.ID, src.Vendor)
	}
	snap, err := dl.Fetch(src)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	meta := snap.Meta
	meta.ParserVersion = ParserVersion
	res, err := ParseFile(snap.Path, d, releases, meta)
	if err != nil {
		return nil, meta, fmt.Errorf("parse %s: %w", snap.Path, err)
	}
	if validateOnly {
		return res, meta, nil
	}
	if err := Publish(store, d, res, meta); err != nil {
		return nil, meta, err
	}
	return res, meta, nil
}
