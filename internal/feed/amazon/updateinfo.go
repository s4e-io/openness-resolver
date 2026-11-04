// Package amazon parses the Amazon Linux security advisories (ALAS) that
// Amazon publishes as repository metadata: the core repository of every
// release carries repodata/updateinfo.xml.gz, the same document
// `dnf updateinfo` / `yum updateinfo` read on the host.
//
// Fetch chain (all on cdn.amazonlinux.com, https only):
//
//	<release>/core/.../mirror.list   one line: the current repository base URL
//	<base>/repodata/repomd.xml       names the updateinfo location
//	<base>/repodata/updateinfo.xml.gz
//
// Document shape:
//
//	<updates><update type="security">
//	  <id>ALAS2023-2024-512</id> <severity>Important</severity>
//	  <issued date="2024-02-15 21:23:00"/>
//	  <references><reference id="CVE-2024-0727" type="cve"/></references>
//	  <pkglist><collection short="amazon-linux-2023">
//	    <package name="openssl-libs" epoch="1" version="3.0.8"
//	             release="1.amzn2023.0.11" arch="aarch64"/>
//	  </collection></pkglist>
//	</update></updates>
//
// Every listed package is a binary package at its fixed version. Rules are
// binary-level (no source package names are published) and arch-free when
// all architectures share one fixed version.
package amazon

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "amazon-updateinfo/1.0.0"

// Vendor is the rule store directory and rule distribution id.
const Vendor = "amazon"

// repoHost is the only host the fetch chain may follow.
const repoHost = "cdn.amazonlinux.com"

// collections maps a release to the updateinfo collection it publishes.
var collections = map[string]string{
	"2":    "amazon-linux-2",
	"2023": "amazon-linux-2023",
}

// advisoryPaths maps a release to its path on alas.aws.amazon.com.
var advisoryPaths = map[string]string{
	"2":    "AL2",
	"2023": "AL2023",
}

type xmlPackage struct {
	Name    string `xml:"name,attr"`
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
	Arch    string `xml:"arch,attr"`
}

type xmlUpdate struct {
	Type     string `xml:"type,attr"`
	ID       string `xml:"id"`
	Title    string `xml:"title"`
	Severity string `xml:"severity"`
	Issued   struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	References []struct {
		ID   string `xml:"id,attr"`
		Type string `xml:"type,attr"`
	} `xml:"references>reference"`
	Collections []struct {
		Short    string       `xml:"short,attr"`
		Packages []xmlPackage `xml:"package"`
	} `xml:"pkglist>collection"`
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Release string
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
}

// Parse reads an updateinfo document (plain or gzip) for one release.
func Parse(r io.Reader, release string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	collection, ok := collections[release]
	if !ok {
		return nil, fmt.Errorf("amazon: unsupported release %q", release)
	}
	br, err := maybeGunzip(r)
	if err != nil {
		return nil, err
	}
	res := &ParseResult{Release: release}
	packagesSeen := map[string]bool{}
	cvesSeen := map[string]bool{}
	ruleIDs := map[string]bool{}

	dec := xml.NewDecoder(br)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("amazon updateinfo: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "update" {
			continue
		}
		res.Metrics.RecordsDownloaded++
		var u xmlUpdate
		if err := dec.DecodeElement(&u, &se); err != nil {
			return nil, fmt.Errorf("amazon updateinfo: %w", err)
		}
		res.Metrics.RecordsParsed++
		id := strings.TrimSpace(u.ID)
		switch {
		case id == "":
			res.Metrics.Reject("update_without_id")
			continue
		case u.Type != "security":
			// Bug-fix and enhancement updates are not vulnerability findings.
			res.Metrics.Reject("non_security_update")
			continue
		}
		cves := cveIDs(u)
		if len(cves) == 0 {
			res.Metrics.Reject("advisory_without_cve")
			continue
		}
		fixed := map[string]map[string]string{} // name -> arch -> EVR
		for _, c := range u.Collections {
			if c.Short != collection {
				res.Metrics.Reject("foreign_collection")
				continue
			}
			for _, p := range c.Packages {
				name := strings.TrimSpace(p.Name)
				if name == "" || p.Version == "" || p.Release == "" {
					res.Metrics.Reject("package_without_nevra")
					continue
				}
				if p.Arch == "src" || isDebugPackage(name) {
					continue
				}
				if fixed[name] == nil {
					fixed[name] = map[string]string{}
				}
				fixed[name][p.Arch] = evr(p)
			}
		}
		if len(fixed) == 0 {
			res.Metrics.Reject("advisory_without_packages")
			continue
		}
		var published *time.Time
		if t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(u.Issued.Date)); err == nil {
			published = &t
		}
		names := make([]string, 0, len(fixed))
		for n := range fixed {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			packagesSeen[name] = true
			for _, t := range targets(fixed[name]) {
				for _, cve := range cves {
					ruleID := fmt.Sprintf("amazon:%s:%s:%s:%s", release, id, cve, name)
					if t.arch != "" {
						ruleID += ":" + t.arch
					}
					if ruleIDs[ruleID] {
						continue
					}
					ruleIDs[ruleID] = true
					cvesSeen[cve] = true
					res.Rules = append(res.Rules, rules.PackageVulnerabilityRule{
						RuleID:           ruleID,
						Ecosystem:        "rpm",
						Vendor:           Vendor,
						Distribution:     Vendor,
						Release:          release,
						Architecture:     t.arch,
						PackageName:      name,
						Status:           rules.StatusReleased,
						RawStatus:        "fixed (" + collection + ")",
						FixedVersion:     t.fixed,
						Comparator:       "rpm",
						CVEID:            cve,
						AdvisoryIDs:      []string{id},
						Urgency:          strings.ToLower(strings.TrimSpace(u.Severity)),
						VendorNotes:      strings.TrimSpace(u.Title),
						SourcePriority:   1,
						PublishedAt:      published,
						SourceSnapshotID: meta.RawObjectID,
						RawObjectID:      id,
						SourceURL:        "https://alas.aws.amazon.com/" + advisoryPaths[release] + "/" + id + ".html",
					})
					res.Metrics.RulesGenerated++
				}
			}
		}
		res.Metrics.RecordsNormalized++
	}
	sort.Slice(res.Rules, func(i, j int) bool { return res.Rules[i].RuleID < res.Rules[j].RuleID })
	res.Metrics.PackagesSeen = len(packagesSeen)
	res.Metrics.CVEsSeen = len(cvesSeen)
	res.Metrics.ReleasesSeen = 1
	return res, nil
}

type target struct {
	arch  string // "" when every architecture has the same fixed version
	fixed string
}

// targets collapses per-architecture fixed versions into one arch-free rule
// when they agree, and keeps per-arch rules when they differ.
func targets(byArch map[string]string) []target {
	versions := map[string]bool{}
	for _, v := range byArch {
		versions[v] = true
	}
	if len(versions) == 1 {
		for v := range versions {
			return []target{{fixed: v}}
		}
	}
	out := make([]target, 0, len(byArch))
	for arch, v := range byArch {
		out = append(out, target{arch: arch, fixed: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].arch < out[j].arch })
	return out
}

// evr writes [epoch:]version-release; epoch 0 is left out like rpm -q does.
func evr(p xmlPackage) string {
	v := strings.TrimSpace(p.Version) + "-" + strings.TrimSpace(p.Release)
	if e := strings.TrimSpace(p.Epoch); e != "" && e != "0" {
		return e + ":" + v
	}
	return v
}

func cveIDs(u xmlUpdate) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range u.References {
		id := strings.ToUpper(strings.TrimSpace(r.ID))
		if r.Type != "cve" || !strings.HasPrefix(id, "CVE-") || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// isDebugPackage reports debuginfo/debugsource packages, which are never
// a runtime attack surface and multiply the rule count.
func isDebugPackage(name string) bool {
	return strings.HasSuffix(name, "-debuginfo") || strings.HasSuffix(name, "-debugsource") ||
		strings.Contains(name, "-debuginfo-")
}

func maybeGunzip(r io.Reader) (io.Reader, error) {
	buf := make([]byte, 2)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("amazon updateinfo: %w", err)
	}
	rest := io.MultiReader(bytes.NewReader(buf[:n]), r)
	if n == 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		zr, err := gzip.NewReader(rest)
		if err != nil {
			return nil, fmt.Errorf("amazon updateinfo gzip: %w", err)
		}
		return zr, nil
	}
	return rest, nil
}

// MirrorBase returns the repository base URL from a mirror.list document.
// Only an https URL on the Amazon Linux CDN is accepted.
func MirrorBase(mirrorList string) (string, error) {
	for _, line := range strings.Split(mirrorList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Scheme != "https" || u.Host != repoHost {
			return "", fmt.Errorf("amazon mirror list: unexpected repository URL %q", line)
		}
		if !strings.HasSuffix(line, "/") {
			line += "/"
		}
		return line, nil
	}
	return "", fmt.Errorf("amazon mirror list: no repository URL")
}

type repomd struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
	} `xml:"data"`
}

// UpdateinfoHref returns the updateinfo location named by repomd.xml. The
// location must stay inside the repository.
func UpdateinfoHref(repomdXML []byte) (string, error) {
	var md repomd
	if err := xml.Unmarshal(repomdXML, &md); err != nil {
		return "", fmt.Errorf("amazon repomd: %w", err)
	}
	for _, d := range md.Data {
		if d.Type != "updateinfo" {
			continue
		}
		href := strings.TrimSpace(d.Location.Href)
		clean := path.Clean(href)
		if href == "" || strings.Contains(href, "://") || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") {
			return "", fmt.Errorf("amazon repomd: unsafe updateinfo location %q", href)
		}
		return clean, nil
	}
	return "", fmt.Errorf("amazon repomd: no updateinfo entry")
}

// ParseFile parses a local updateinfo.xml or updateinfo.xml.gz file.
func ParseFile(file, release string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, release, meta)
}

// ReleaseFromSourceID returns the release of an amazon-updateinfo-<release> source.
func ReleaseFromSourceID(id string) string {
	return strings.TrimPrefix(id, "amazon-updateinfo-")
}

// Sync follows the mirror list to the release's updateinfo, parses it and
// publishes the rules for that release. Every hop is kept as a raw snapshot.
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, validateOnly bool) (*ParseResult, rules.FeedSourceMetadata, error) {
	release := ReleaseFromSourceID(src.ID)
	if _, ok := collections[release]; !ok {
		return nil, rules.FeedSourceMetadata{}, fmt.Errorf("source %s: unsupported amazon release %q", src.ID, release)
	}
	mirror, err := dl.Fetch(src)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	data, err := os.ReadFile(mirror.Path)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	base, err := MirrorBase(string(data))
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	hop := func(suffix, u string) (*feed.SnapshotResult, error) {
		s := src
		s.ID = src.ID + "-" + suffix
		s.URL = u
		return dl.Fetch(s)
	}
	md, err := hop("repomd", base+"repodata/repomd.xml")
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	mdData, err := os.ReadFile(md.Path)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	href, err := UpdateinfoHref(mdData)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	ui, err := hop("updateinfo", base+href)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	meta := ui.Meta
	meta.ParserVersion = ParserVersion
	res, err := ParseFile(ui.Path, release, meta)
	if err != nil {
		return nil, meta, fmt.Errorf("parse %s: %w", ui.Path, err)
	}
	if validateOnly {
		return res, meta, nil
	}
	if err := store.SaveRules(Vendor, release, res.Rules, meta); err != nil {
		return nil, meta, fmt.Errorf("publish rules %s/%s: %w", Vendor, release, err)
	}
	return res, meta, nil
}
