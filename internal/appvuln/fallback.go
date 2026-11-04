package appvuln

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The fallback matcher guesses the NVD product of an installed application the catalog
// does not know, from its name and publisher alone. A guess can be wrong, so its findings
// are "potentially_vulnerable": listed, not counted, and without an update card. It is
// strict on purpose, because a name alone says little:
//
//   - every word (and number) of the NVD product is in the application name;
//   - the vendor is the publisher, or is in the name when it is not just the product again
//     (file_project:file, git:git say nothing about who made a "File Converter");
//   - a role in the name (client, server, CLI, agent) is in the product too: "Zimbra
//     Desktop" is not the Zimbra server;
//   - the name has no part word (documentation, plugin) and at most one word more than the
//     product, none for a one-word product: "Docker Compose" is not docker:docker;
//   - a tie between two vendors is no match.

// fbProduct is one NVD product the fallback matcher can pick.
type fbProduct struct {
	key string // "vendor:product"
	// all is every word of the product; req the ones the name must have (its noise words
	// and "client" are optional: steam_client is the program called "Steam");
	// nums the numbers in the product ("openvpn_3").
	all, req, nums []string
	vendor         []string
	vendorJoined   string
	// vendorIsProduct: the vendor names only the product, so it is no evidence by itself
	vendorIsProduct bool
	cves            int
}

// fallback indexes the fallback database by product word.
type fallback struct {
	db      DB
	byToken map[string][]*fbProduct
}

var (
	parens   = regexp.MustCompile(`\([^)]*\)|\[[^]]*\]`)
	nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)
	// appxName is a Store package id ("Microsoft.Windows.Search"), not a program name.
	appxName = regexp.MustCompile(`^[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$`)
	// a version starts with a number: not "N-127021-g6ae491a26c", not "latest"
	versionLike = regexp.MustCompile(`^[vV]?[0-9]`)
)

// companyWords are legal forms and filler in vendor and publisher names.
var companyWords = set("inc", "ltd", "llc", "corp", "corporation", "co", "gmbh", "ag", "sa", "bv", "ab",
	"limited", "company", "the", "project", "software", "foundation", "team", "community", "technologies",
	"technology", "development", "org", "com", "net", "developers", "developer", "contributors")

// noiseWords in an application name say nothing about which product it is: architecture,
// language, packaging.
var noiseWords = set("x64", "x86", "amd64", "arm64", "win32", "win64", "bit", "64bit", "32bit", "en", "us",
	"edition", "version", "release", "build", "setup", "installer", "install", "for", "windows", "win",
	"app", "application", "and", "of", "by", "on", "with", "the", "update", "project", "free", "pro",
	"professional", "home", "portable", "legacy", "stable", "lts")

// roleWords say which side of a product it is; one in the name must be in the product.
var roleWords = set("client", "desktop", "server", "cli", "agent", "console", "runner", "sidecar", "daemon",
	"gui", "service", "gateway", "proxy", "mobile", "web")

// clientWords in a product name may be missing from the program's name: the installed
// program is the client. A server, console or CLI product is something else.
var clientWords = set("client", "desktop")

// componentWords mark a part of a product (its documentation, a plugin, a helper) whose
// own version says nothing about the product's CVEs.
var componentWords = set("documentation", "docs", "doc", "manual", "help", "library", "libraries", "utility",
	"utilities", "utils", "scripts", "launcher", "helper", "plugin", "plugins", "addin", "addon", "extension",
	"extensions", "driver", "drivers", "redistributable", "maintenance", "bootstrap", "support", "headers",
	"symbols", "debug", "language", "pack", "component", "components", "shared", "core", "interpreter",
	"executables", "sdk", "tools", "module", "connector", "integration", "theme", "samples", "examples",
	"updater", "uninstaller", "assistant", "wrapper", "viewer", "editor", "manager", "converter")

func set(w ...string) map[string]bool {
	m := make(map[string]bool, len(w))
	for _, s := range w {
		m[s] = true
	}
	return m
}

// split cuts a name into lowercase words and numbers, without what is in parentheses.
func split(s string) (words, nums []string) {
	s = strings.ReplaceAll(strings.ToLower(parens.ReplaceAllString(s, " ")), `\`, "")
	for _, w := range strings.Fields(nonAlnum.ReplaceAllString(s, " ")) {
		if strings.ContainsAny(w, "abcdefghijklmnopqrstuvwxyz") {
			words = append(words, w)
		} else {
			nums = append(nums, strings.TrimLeft(w, "0"))
		}
	}
	return words, nums
}

func without(words []string, drop ...map[string]bool) []string {
	var out []string
next:
	for _, w := range words {
		for _, d := range drop {
			if d[w] {
				continue next
			}
		}
		out = append(out, w)
	}
	return out
}

func newFallback(db DB) *fallback {
	f := &fallback{db: db, byToken: map[string][]*fbProduct{}}
	for key, vulns := range db.Products {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 || parts[0] == "microsoft" {
			// Microsoft programs are patched through Windows Update, and their versions
			// often do not move with the fix; the OS feeds cover them.
			continue
		}
		vw, _ := split(parts[0])
		pw, nums := split(parts[1])
		p := &fbProduct{key: key, all: pw, nums: nums, vendor: without(vw, companyWords), cves: len(vulns)}
		p.req = without(pw, noiseWords, clientWords)
		p.vendorJoined = strings.Join(p.vendor, "")
		if len(p.req) == 0 || len(strings.Join(p.req, "")) < 3 || p.vendorJoined == "" {
			continue
		}
		p.vendorIsProduct = true
		for _, w := range p.vendor {
			p.vendorIsProduct = p.vendorIsProduct && contains(p.all, w)
		}
		for _, w := range p.req {
			f.byToken[w] = append(f.byToken[w], p)
		}
	}
	return f
}

// match returns the NVD product an application most likely is, or nil.
func (f *fallback) match(a app) *fbProduct {
	if appxName.MatchString(strings.TrimSpace(a.ProductName)) {
		return nil
	}
	name, nums := split(a.ProductName)
	if len(name) == 0 {
		return nil
	}
	pubWords, _ := split(a.Publisher)
	pub := without(pubWords, companyWords)
	seen := map[*fbProduct]bool{}
	var best []*fbProduct
	bestLen := 0
	for _, w := range name {
		for _, p := range f.byToken[w] {
			if seen[p] {
				continue
			}
			seen[p] = true
			if !fits(p, name, nums, pub) {
				continue
			}
			switch n := len(p.req); {
			case n > bestLen:
				best, bestLen = []*fbProduct{p}, n
			case n == bestLen:
				best = append(best, p)
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	sort.Slice(best, func(i, j int) bool {
		if best[i].cves != best[j].cves {
			return best[i].cves > best[j].cves
		}
		return best[i].key < best[j].key
	})
	for _, p := range best[1:] {
		if p.vendorJoined != best[0].vendorJoined {
			return nil // two vendors fit equally well: no guess
		}
	}
	return best[0]
}

func fits(p *fbProduct, name, nums, pub []string) bool {
	for _, w := range p.req {
		if !contains(name, w) {
			return false
		}
	}
	for _, n := range p.nums {
		if !contains(nums, n) {
			return false
		}
	}
	if !publisherIs(p, pub) {
		if p.vendorIsProduct {
			return false
		}
		for _, w := range p.vendor {
			if !contains(name, w) {
				return false
			}
		}
	}
	extra := 0
	for _, w := range name {
		if contains(p.all, w) || contains(p.vendor, w) {
			continue
		}
		if roleWords[w] || componentWords[w] {
			return false
		}
		if !noiseWords[w] && !companyWords[w] {
			extra++
		}
	}
	if len(p.req) == 1 {
		return extra == 0
	}
	return extra <= 1
}

// publisherIs says whether the publisher is the product's vendor: the same name, a short
// form of it ("Valve" for valvesoftware), or, when the vendor is more than the product's
// name, the vendor's words within the publisher ("Trimble Navigation" for trimble).
func publisherIs(p *fbProduct, pub []string) bool {
	pj := strings.Join(pub, "")
	switch {
	case pj == "":
		return false
	case pj == p.vendorJoined, len(pj) >= 4 && strings.HasPrefix(p.vendorJoined, pj):
		return true
	case p.vendorIsProduct:
		return false
	}
	for _, w := range p.vendor {
		if !contains(pub, w) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// findings returns the possible CVEs of an application the fallback matched.
func (f *fallback) findings(p *fbProduct, a app, ver string) []Finding {
	var out []Finding
	title := f.db.Titles[p.key]
	for _, v := range f.db.Products[p.key] {
		fix, hit := affected(ver, v.Ranges, false)
		if !hit {
			continue
		}
		sev := strings.ToLower(v.Severity)
		if sev == "" {
			sev = "unknown"
		}
		fd := Finding{
			FindingID: "app-guess:" + p.key + ":" + ver + ":" + v.CVE, Scope: "host", State: "potentially_vulnerable",
			CPE: p.key, Guess: true,
			Severity: sev, CVEID: v.CVE, AdvisoryIDs: []string{}, BinaryPackage: strings.TrimSpace(a.ProductName),
			SourcePackage: p.key, InstalledVersion: ver, FixedVersion: fix,
			Reasons: []string{
				fmt.Sprintf("%q (publisher %q) is not in the reviewed application catalog; by its name it looks like NVD product %s (%s)",
					strings.TrimSpace(a.ProductName), a.Publisher, p.key, title),
				fmt.Sprintf("version %s is in an affected range of that product; confirm the product before acting", ver),
			},
		}
		if v.CVSS > 0 {
			score := v.CVSS
			fd.CVSSScore = &score
		}
		out = append(out, fd)
	}
	return out
}

// fallbackVersion is the application's version as the fallback compares it: the display
// version when it looks like one, else none.
func fallbackVersion(a app) string {
	v := strings.TrimSpace(a.DisplayVersion)
	if !versionLike.MatchString(v) {
		return ""
	}
	return v
}
