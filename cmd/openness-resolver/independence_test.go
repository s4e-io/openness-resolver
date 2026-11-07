package main

// The resolver must work with no OpenNess or S4E service, key or account: it
// syncs from the vulnerability data publishers themselves. These tests fail
// when a default URL points anywhere else, or when an OPENNESS_* variable
// becomes required.

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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

// githubRelease is the one github.com URL shape the code may name: a release asset of the
// public S4E catalog repository, where the S4E backend publishes the app-mapper bundle.
// Downloading it needs no account, key or S4E service.
var githubRelease = regexp.MustCompile(`^https://github\.com/s4e-io/openness-app-mapper/releases/(latest/download|download/[A-Za-z0-9._-]+)/[A-Za-z0-9._-]+$`)

// hostProblem says why a URL may not appear in the code, or "" when it may.
func hostProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Sprintf("unparsable URL %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	for _, f := range forbidden {
		if strings.Contains(host, f) {
			return fmt.Sprintf("URL %s points to an OpenNess/S4E host", raw)
		}
	}
	if host == "github.com" {
		if githubRelease.MatchString(raw) {
			return ""
		}
		return fmt.Sprintf("URL %s: only release downloads of github.com/s4e-io/openness-app-mapper are allowed on github.com", raw)
	}
	if _, ok := publisherHosts[host]; !ok {
		return fmt.Sprintf("URL %s is not a known publisher host; add it to publisherHosts only if it is the data publisher", raw)
	}
	return ""
}

func checkHost(t *testing.T, where, raw string) {
	t.Helper()
	if p := hostProblem(raw); p != "" {
		t.Errorf("%s: %s", where, p)
	}
}

// The github.com exception is exactly the catalog's release downloads; S4E and OpenNess
// hosts stay banned.
func TestHostRules(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://github.com/s4e-io/openness-app-mapper/releases/latest/download/app-mapper.json.gz": true,
		"https://github.com/s4e-io/openness-app-mapper/releases/latest/download/SHA256SUMS":         true,
		"https://github.com/s4e-io/openness-app-mapper/releases/download/v2026.11.05/SHA256SUMS":    true,
		"https://github.com/s4e-io/openness-app-mapper/archive/main.zip":                            false,
		"https://github.com/s4e-io/openness-backend/releases/latest/download/app-mapper.json.gz": false,
		"https://github.com/other/openness-app-mapper/releases/latest/download/app-mapper.json.gz":  false,
		"https://api.github.com/repos/s4e-io/openness-app-mapper/releases/latest":                   false,
		"https://s4e.io/app-mapper.json.gz":                                                      false,
		"https://getopenness.com/app-mapper.json.gz":                                             false,
		"https://openness.s4e.io/api/mapper":                                                     false,
		"https://api.osv.dev/v1/query":                                                           true,
	} {
		if got := hostProblem(raw) == ""; got != ok {
			t.Errorf("%s allowed=%v, want %v (%s)", raw, got, ok, hostProblem(raw))
		}
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
}

// The full offline flow (import, resolve) runs with no OPENNESS_* variable set:
// offlineEnv strips them, and the golden tests use it. This test pins that the binary
// reads no environment variable of its own.
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
		t.Errorf("code reads environment variable %s; document it in README and add it here", name)
	}
}
