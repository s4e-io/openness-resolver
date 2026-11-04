package main

// The resolver must work with no OpenNess or S4E service, key or account: it
// syncs from the vulnerability data publishers themselves. These tests fail
// when a default URL points anywhere else, or when an OPENNESS_* variable
// becomes required.

import (
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/feed/osv"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// publisherHosts are the only hosts the code may name: the publishers of the
// advisory data, and the advisory pages rules link to.
var publisherHosts = map[string]string{
	"security-metadata.canonical.com":            "Canonical Ubuntu OVAL",
	"ubuntu.com":                                 "Ubuntu security notices (links in rules)",
	"security-tracker.debian.org":                "Debian security tracker",
	"secdb.alpinelinux.org":                      "Alpine secdb",
	"cdn.amazonlinux.com":                        "Amazon Linux repositories (updateinfo)",
	"alas.aws.amazon.com":                        "Amazon Linux security center (links in rules)",
	"api.msrc.microsoft.com":                     "Microsoft MSRC CVRF API",
	"osv-vulnerabilities.storage.googleapis.com": "OSV data dumps (Rocky, AlmaLinux, Red Hat, openSUSE)",
	"api.osv.dev":                                "OSV query API (PyPI)",
}

// forbidden are substrings no URL host may contain.
var forbidden = []string{"s4e", "openness", "anchorsecurity"}

var urlPattern = regexp.MustCompile("https?://[^\\s\"'`<>)]+")

// sourceFiles are the non-test Go files of the module.
func sourceFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(fixture(dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 20 {
		t.Fatalf("found only %d source files", len(out))
	}
	return out
}

func checkHost(t *testing.T, where, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		t.Errorf("%s: unparsable URL %q", where, raw)
		return
	}
	host := strings.ToLower(u.Hostname())
	for _, f := range forbidden {
		if strings.Contains(host, f) {
			t.Errorf("%s: URL %s points to an OpenNess/S4E host", where, raw)
		}
	}
	if _, ok := publisherHosts[host]; !ok {
		t.Errorf("%s: URL %s is not a known publisher host; add it to publisherHosts only if it is the data publisher", where, raw)
	}
}

// Every URL literal in the code names a publisher.
func TestNoURLOutsidePublishers(t *testing.T) {
	seen := 0
	for _, f := range sourceFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(fixture(""), f)
		for _, u := range urlPattern.FindAllString(string(raw), -1) {
			u = strings.TrimRight(u, ".,;")
			if strings.Contains(u, "<") || strings.HasSuffix(u, "://") {
				continue
			}
			checkHost(t, rel, u)
			seen++
		}
		for _, f := range forbidden[:1] {
			// The module path github.com/s4e-io/... is the only allowed mention.
			text := strings.ReplaceAll(string(raw), "github.com/s4e-io/openness-resolver", "")
			if strings.Contains(strings.ToLower(text), f+".io") || strings.Contains(strings.ToLower(text), f+".dev") {
				t.Errorf("%s names an S4E domain", rel)
			}
		}
	}
	if seen < 10 {
		t.Errorf("only %d URLs found; the URL scan is broken", seen)
	}
}

// Every source the registry or the release feeds can produce downloads from a publisher.
func TestEverySourceURLIsAPublisher(t *testing.T) {
	var srcs []rules.AdvisorySource
	srcs = append(srcs, rules.Registry()...)
	for vendor, releases := range map[string][]string{
		"ubuntu":    {"focal", "jammy", "noble", "plucky"},
		"alpine":    {"v3.14", "v3.20", "v3.22"},
		"amazon":    {"2", "2023"},
		"microsoft": {"2023-Jan", "2026-Oct"},
	} {
		for _, r := range releases {
			s, err := rules.ReleaseSources(vendor, r)
			if err != nil {
				t.Fatal(err)
			}
			srcs = append(srcs, s...)
		}
	}
	srcs = append(srcs, rules.MSRCSources(24, time.Now())...)
	for _, s := range srcs {
		checkHost(t, "source "+s.ID, s.URL)
	}
	checkHost(t, "osv.DefaultEndpoint", osv.DefaultEndpoint)
}

// OPENNESS_OSV_URL and OPENNESS_OSV_HEADERS are optional: without them PyPI
// queries go to api.osv.dev with no extra header.
func TestOSVEnvironmentIsOptional(t *testing.T) {
	t.Setenv("OPENNESS_OSV_URL", "")
	t.Setenv("OPENNESS_OSV_HEADERS", "")
	defer func() { osv.Endpoint, osv.Headers = osv.DefaultEndpoint, map[string]string{} }()
	setOSVEndpoint("")
	if osv.Endpoint != "https://api.osv.dev/v1/query" {
		t.Errorf("endpoint %s, want the public OSV API", osv.Endpoint)
	}
	if len(osv.Headers) != 0 {
		t.Errorf("headers %v, want none", osv.Headers)
	}
	t.Setenv("OPENNESS_OSV_URL", "https://osv-mirror.example.org/v1/query")
	t.Setenv("OPENNESS_OSV_HEADERS", "Authorization: Bearer x\nmalformed line")
	setOSVEndpoint("")
	if osv.Endpoint != "https://osv-mirror.example.org/v1/query" || len(osv.Headers) != 1 {
		t.Errorf("endpoint %s headers %v", osv.Endpoint, osv.Headers)
	}
	setOSVEndpoint("https://flag.example.org/v1/query")
	if osv.Endpoint != "https://flag.example.org/v1/query" {
		t.Errorf("--osv-url must win over OPENNESS_OSV_URL, got %s", osv.Endpoint)
	}
}

// The full offline flow (import, PyPI sync from a mirror, resolve) runs with no
// OPENNESS_* variable set: offlineEnv strips them, and the golden tests use it.
// This test pins that the binary reads no other OPENNESS_* variable.
func TestOnlyDocumentedEnvironmentVariables(t *testing.T) {
	re := regexp.MustCompile(`Getenv\("([A-Z0-9_]+)"\)|LookupEnv\("([A-Z0-9_]+)"\)`)
	found := map[string]bool{}
	for _, f := range sourceFiles(t) {
		raw, _ := os.ReadFile(f)
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			found[m[1]+m[2]] = true
		}
	}
	for name := range found {
		if name != "OPENNESS_OSV_URL" && name != "OPENNESS_OSV_HEADERS" {
			t.Errorf("code reads environment variable %s; document it in README and add it here", name)
		}
	}
}
