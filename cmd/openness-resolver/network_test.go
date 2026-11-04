package main

// Nightly network tests: the real thing against the publishers, with no
// OpenNess or S4E account, key, secret or service. They run only when
// OPENNESS_NIGHTLY=1 (.github/workflows/nightly.yml, or by hand):
//
//	OPENNESS_NIGHTLY=1 go test ./cmd/openness-resolver -run TestNightlySync -v -timeout 30m
//	OPENNESS_NIGHTLY=1 go test ./cmd/openness-resolver -run 'TestNightlySync/^alpine-3.20$' -v
//	OPENNESS_NIGHTLY=1 go test ./cmd/openness-resolver -run TestNightlyFeedValidate -v -timeout 30m
//
// TestNightlySync runs `feed sync --for` on a committed synthetic evidence file,
// then `resolve`, and asserts exit code 0, rule coverage "covered" and rules
// loaded for the fixture's release. TestNightlyFeedValidate downloads and parses
// every enabled source, so a publisher format change fails the next morning.
// With GITHUB_STEP_SUMMARY set, both append a per-source table (rules, download
// size, time) to the job summary.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var nightlyCases = []struct {
	evidence  string
	release   string // rule_coverage.asset_release the fixture must get
	syncExtra []string
}{
	{evidence: "ubuntu-22.04-jammy", release: "ubuntu/jammy"}, // also queries OSV for one PyPI package
	{evidence: "ubuntu-24.04-noble", release: "ubuntu/noble"},
	{evidence: "debian-12-bookworm", release: "debian/bookworm"},
	{evidence: "rocky-9", release: "rocky/9"},
	{evidence: "amazon-linux-2023", release: "amazon/2023"},
	{evidence: "alpine-3.20", release: "alpine/v3.20"},
	{evidence: "opensuse-leap-15.6", release: "opensuse/15.6"},
	// Two MSRC months: the current month may not be published yet (404 is skipped).
	{evidence: "windows-server-2022", release: "windows/windows_server_2022", syncExtra: []string{"--months", "2"}},
}

func nightlyEnv(t *testing.T) []string {
	t.Helper()
	if os.Getenv("OPENNESS_NIGHTLY") != "1" {
		t.Skip("set OPENNESS_NIGHTLY=1 to sync from the publishers")
	}
	// No OPENNESS_* variable reaches the binary: PyPI goes to the public api.osv.dev.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "OPENNESS_") {
			env = append(env, kv)
		}
	}
	return env
}

// sourceStat is one "==> <id>" block of feed sync or feed validate output.
type sourceStat struct {
	id, size, rules, took, status string
}

var (
	syncHeader = regexp.MustCompile(`^==> (\S+) `)
	sizeField  = regexp.MustCompile(`size=(\d+)B`)
	rulesField = regexp.MustCompile(`\brules=(\d+)`)
	tookField  = regexp.MustCompile(`^\s+took (\S+)`)
)

func parseSyncOutput(out string) []sourceStat {
	var stats []sourceStat
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if m := syncHeader.FindStringSubmatch(l); m != nil {
			stats = append(stats, sourceStat{id: m[1], status: "ok"})
			continue
		}
		if len(stats) == 0 {
			continue
		}
		s := &stats[len(stats)-1]
		if m := sizeField.FindStringSubmatch(l); m != nil {
			s.size = humanBytes(m[1])
		}
		if m := rulesField.FindStringSubmatch(l); m != nil {
			s.rules = m[1]
		}
		if m := tookField.FindStringSubmatch(l); m != nil {
			s.took = m[1]
		}
		switch {
		case strings.Contains(l, "FAILED:"):
			s.status = "FAILED: " + strings.TrimSpace(strings.SplitN(l, "FAILED:", 2)[1])
		case strings.Contains(l, "(404), skipped"):
			s.status = "not published yet (404)"
		}
	}
	return stats
}

func humanBytes(n string) string {
	var b float64
	fmt.Sscan(n, &b)
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", b/(1<<10))
	}
	return n + " B"
}

// writeSummary appends a Markdown table to $GITHUB_STEP_SUMMARY when it is set.
func writeSummary(t *testing.T, title string, stats []sourceStat, extra string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "### %s\n\n| Source | Rules | Download size | Time | Status |\n|---|---|---|---|---|\n", title)
	for _, s := range stats {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", s.id, s.rules, s.size, s.took, s.status)
	}
	if extra != "" {
		b.WriteString("\n" + extra + "\n")
	}
	b.WriteString("\n")
	t.Log("\n" + b.String())
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("step summary: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(b.String())
}

func TestNightlySync(t *testing.T) {
	env := nightlyEnv(t)
	for _, tc := range nightlyCases {
		t.Run(tc.evidence, func(t *testing.T) {
			tmp := t.TempDir()
			data := filepath.Join(tmp, "data")
			ev := evidencePath(tc.evidence)
			args := append([]string{"feed", "sync", "--for", ev, "--data-dir", data}, tc.syncExtra...)
			sync := runCLI(t, "", env, args...)
			t.Logf("feed sync (exit %d):\n%s%s", sync.Code, sync.Stdout, sync.Stderr)
			stats := parseSyncOutput(sync.Stdout)

			out := filepath.Join(tmp, "findings.json")
			res := runCLI(t, "", env, "resolve", "--input", ev, "--data-dir", data, "--output", out)
			t.Logf("resolve (exit %d):\n%s%s", res.Code, res.Stdout, res.Stderr)

			var doc struct {
				RuleCoverage struct {
					AssetRelease  string `json:"asset_release"`
					RulesForAsset int    `json:"rules_for_asset"`
					State         string `json:"state"`
					Reason        string `json:"reason"`
					Sources       []struct {
						Source string `json:"source"`
						URL    string `json:"url"`
					} `json:"sources"`
				} `json:"rule_coverage"`
				Findings []struct {
					State string `json:"state"`
				} `json:"findings"`
			}
			if raw, err := os.ReadFile(out); err == nil {
				json.Unmarshal(raw, &doc)
			}
			cov := doc.RuleCoverage
			writeSummary(t, fmt.Sprintf("%s (%s): sync exit %d, resolve exit %d, coverage %s, %d rules, %d findings",
				tc.evidence, cov.AssetRelease, sync.Code, res.Code, cov.State, cov.RulesForAsset, len(doc.Findings)), stats, "")

			if sync.Code != 0 {
				t.Errorf("feed sync exit %d", sync.Code)
			}
			if res.Code != 0 {
				t.Errorf("resolve exit %d", res.Code)
			}
			if cov.State != "covered" {
				t.Errorf("rule_coverage.state %q, want covered (%s)", cov.State, cov.Reason)
			}
			if cov.AssetRelease != tc.release || cov.RulesForAsset == 0 {
				t.Errorf("asset release %q with %d rules, want rules loaded for %s", cov.AssetRelease, cov.RulesForAsset, tc.release)
			}
			for _, s := range cov.Sources {
				checkHost(t, "coverage source "+s.Source, strings.Fields(s.URL)[0])
			}
		})
	}
}

func TestNightlyFeedValidate(t *testing.T) {
	env := nightlyEnv(t)
	tmp := t.TempDir()
	r := runCLI(t, "", env, "feed", "validate", "--data-dir", filepath.Join(tmp, "data"), "--months", "2")
	t.Logf("feed validate (exit %d):\n%s%s", r.Code, r.Stdout, r.Stderr)
	stats := parseSyncOutput(r.Stdout)
	failed := 0
	for _, s := range stats {
		if strings.HasPrefix(s.status, "FAILED") {
			failed++
		}
	}
	writeSummary(t, fmt.Sprintf("feed validate: %d sources, %d failed, exit %d", len(stats), failed, r.Code), stats,
		"Rules are what the parser produced; validate publishes nothing.")
	if r.Code != 0 || failed > 0 {
		t.Errorf("feed validate: exit %d, %d sources failed", r.Code, failed)
	}
	if len(stats) < 20 {
		t.Errorf("feed validate covered only %d sources", len(stats))
	}
}
