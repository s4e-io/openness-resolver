package main

// PyPI data is a downloaded feed (osv-pypi): resolve matches Python packages against the
// local rules and makes no network call; without the feed the result is partial.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// failOnCall is an HTTP(S) proxy that fails the test on any request: every outgoing call
// of the binary goes to it.
func failOnCall(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("network call during resolve: %s %s", r.Method, r.URL)
		http.Error(w, "no network", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func noNetworkEnv(proxy string) []string {
	env := offlineEnv()
	return append(env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy)
}

func TestResolvePyPIFromLocalFeedWithoutNetwork(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data")
	ev := evidencePath("ubuntu-22.04-jammy")
	proxy, calls := failOnCall(t)
	env := noNetworkEnv(proxy.URL)
	zip := packZip(t, fixture("testdata/feeds/osv/pypi"), filepath.Join(tmp, "pypi-all.zip"))
	for _, args := range [][]string{
		{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", fixture("testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml"), "--fetched-at", fetchedAt, "--data-dir", data},
		{"rules", "import", "--source", "osv-pypi", "--file", zip, "--fetched-at", fetchedAt, "--data-dir", data},
	} {
		if r := runCLI(t, "", env, args...); r.Code != 0 {
			t.Fatalf("%v: %d %s", args, r.Code, r.Stderr)
		}
	}
	out := filepath.Join(tmp, "findings.json")
	r := runCLI(t, "", env, "resolve", "--input", ev, "--data-dir", data, "--output", out, "--stale-after", "0")
	if r.Code != 0 {
		t.Fatalf("resolve: %d %s", r.Code, r.Stderr)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d network calls", n)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Ecosystem string `json:"ecosystem"`
			CVEID     string `json:"cve_id"`
		} `json:"findings"`
		RuleCoverage struct {
			State   string `json:"state"`
			Sources []struct {
				Source       string `json:"source"`
				DownloadedAt string `json:"downloaded_at"`
			} `json:"sources"`
		} `json:"rule_coverage"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RuleCoverage.State != "covered" {
		t.Errorf("coverage %s", doc.RuleCoverage.State)
	}
	if !strings.Contains(string(raw), `"osv:pypi:psutil:CVE-2019-18874:GHSA-qfc5-mcwq-26q8"`) {
		t.Error("no psutil finding from the local osv-pypi feed")
	}
	found := false
	for _, s := range doc.RuleCoverage.Sources {
		if s.Source == "osv-pypi" && s.DownloadedAt == "2026-10-30T00:00:00Z" {
			found = true
		}
	}
	if !found {
		t.Errorf("rule_coverage.sources lacks osv-pypi with downloaded_at: %+v", doc.RuleCoverage.Sources)
	}
}

func TestResolveWithoutPyPIFeedIsPartial(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data")
	proxy, calls := failOnCall(t)
	env := noNetworkEnv(proxy.URL)
	if r := runCLI(t, "", env, "rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", fixture("testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml"), "--fetched-at", fetchedAt, "--data-dir", data); r.Code != 0 {
		t.Fatal(r.Stderr)
	}
	out := filepath.Join(tmp, "findings.json")
	r := runCLI(t, "", env, "resolve", "--input", evidencePath("ubuntu-22.04-jammy"), "--data-dir", data, "--output", out, "--stale-after", "0")
	if r.Code != 0 {
		t.Fatalf("a missing osv-pypi must not fail resolve: %d %s", r.Code, r.Stderr)
	}
	if calls.Load() != 0 {
		t.Fatal("network call")
	}
	raw, _ := os.ReadFile(out)
	for _, want := range []string{`"state": "partial"`, `"kind": "not_synced"`, "PyPI data (osv-pypi) is not synced", `"comparator": "dpkg"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("findings.json lacks %s", want)
		}
	}
}
