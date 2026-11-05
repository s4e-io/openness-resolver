package main

// Old data (G1) and mapper downgrades (B7), through the binary.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// importAlpine imports the Alpine v3.20 fixtures as fetched age ago.
func importAlpine(t *testing.T, dataDir string, age time.Duration) {
	t.Helper()
	at := time.Now().UTC().Add(-age).Format(time.RFC3339)
	for _, f := range []string{"main.json", "community.json"} {
		r := run(t, "rules", "import", "--source", "alpine-secdb-v3.20", "--file", fixture("testdata/feeds/alpine/v3.20/"+f), "--fetched-at", at, "--data-dir", dataDir)
		if r.Code != 0 {
			t.Fatal(r.Stderr)
		}
	}
}

type staleDoc struct {
	Notes        []string `json:"notes"`
	RuleCoverage struct {
		State   string `json:"state"`
		Sources []struct {
			Source  string `json:"source"`
			AgeDays *int   `json:"age_days"`
			Stale   *bool  `json:"stale"`
		} `json:"sources"`
	} `json:"rule_coverage"`
}

func readStale(t *testing.T, path string) staleDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d staleDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestStaleData(t *testing.T) {
	tmp := t.TempDir()
	oldData, freshData := filepath.Join(tmp, "old"), filepath.Join(tmp, "fresh")
	importAlpine(t, oldData, 10*24*time.Hour)
	importAlpine(t, freshData, 25*time.Hour)
	alpine := evidencePath("alpine-3.20")
	out := filepath.Join("{tmp}", "out.json")
	source := func(t *testing.T, tmp string) (int, bool, []string) {
		d := readStale(t, filepath.Join(tmp, "out.json"))
		if len(d.RuleCoverage.Sources) == 0 || d.RuleCoverage.Sources[0].AgeDays == nil || d.RuleCoverage.Sources[0].Stale == nil {
			t.Fatalf("sources %+v", d.RuleCoverage.Sources)
		}
		s := d.RuleCoverage.Sources[0]
		return *s.AgeDays, *s.Stale, d.Notes
	}
	runFlagCases(t, []flagCase{
		{name: "old feed warns and notes, exit unchanged", args: []string{"resolve", "--input", alpine, "--data-dir", oldData, "--output", out},
			stderr: []string{"warning: old data: alpine-secdb-v3.20-community (10 days)", "run `openness-resolver feed sync`"},
			check: func(t *testing.T, tmp string, r cliResult) {
				age, stale, notes := source(t, tmp)
				if age != 10 || !stale || !strings.Contains(strings.Join(notes, "\n"), "old data: alpine-secdb-v3.20-community (10 days)") {
					t.Errorf("age %d stale %v notes %v", age, stale, notes)
				}
				if strings.Count(r.Stderr, "warning: old data") != 1 {
					t.Errorf("want one warning line:\n%s", r.Stderr)
				}
			}},
		{name: "fresh feed is quiet", args: []string{"resolve", "--input", alpine, "--data-dir", freshData, "--output", out},
			check: func(t *testing.T, tmp string, r cliResult) {
				if age, stale, _ := source(t, tmp); age != 1 || stale || strings.Contains(r.Stderr, "old data") {
					t.Errorf("age %d stale %v stderr %s", age, stale, r.Stderr)
				}
			}},
		{name: "stale-after override", args: []string{"resolve", "--input", alpine, "--data-dir", oldData, "--output", out, "--stale-after", "30d"},
			check: func(t *testing.T, tmp string, r cliResult) {
				if _, stale, _ := source(t, tmp); stale || strings.Contains(r.Stderr, "old data") {
					t.Errorf("stale %v stderr %s", stale, r.Stderr)
				}
			}},
		{name: "stale-after go duration", args: []string{"resolve", "--input", alpine, "--data-dir", freshData, "--output", out, "--stale-after", "12h"},
			stderr: []string{"warning: old data: alpine-secdb-v3.20-community (1 day)"}},
		{name: "stale-after 0 turns the check off", args: []string{"resolve", "--input", alpine, "--data-dir", oldData, "--output", out, "--stale-after", "0"},
			check: func(t *testing.T, tmp string, r cliResult) {
				if age, stale, _ := source(t, tmp); age != 10 || stale || strings.Contains(r.Stderr, "old data") {
					t.Errorf("age %d stale %v stderr %s", age, stale, r.Stderr)
				}
			}},
		{name: "stale-after not a duration", args: []string{"resolve", "--input", alpine, "--stale-after", "soon"}, code: 2,
			stderr: []string{`invalid value "soon" for flag -stale-after`}},
		{name: "feed list shows age", args: []string{"feed", "list", "--data-dir", oldData},
			stdout: []string{"data alpine/v3.20 alpine-secdb-v3.20-community downloaded_at=", "age_days=10 stale=true"}},
		{name: "feed list stale-after", args: []string{"feed", "list", "--data-dir", oldData, "--stale-after", "30d"},
			stdout: []string{"age_days=10 stale=false"}},
	})
}

// The application mapper is old after 7 days, MSRC after 35.
func TestStaleMapperAndMSRC(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data")
	at := func(d int) string {
		return time.Now().UTC().Add(-time.Duration(d) * 24 * time.Hour).Format(time.RFC3339)
	}
	for _, imp := range [][]string{
		{"msrc-cvrf-2023-Jan", fixture("internal/resolver/testdata/msrc/2023-Jan.json"), at(20)},
		{"msrc-cvrf-2026-Oct", fixture("internal/resolver/testdata/msrc/2026-Oct.json"), at(20)},
		{"app-mapper", deviceMapper(t, tmp), at(8)},
	} {
		if r := run(t, "rules", "import", "--source", imp[0], "--file", imp[1], "--fetched-at", imp[2], "--data-dir", data); r.Code != 0 {
			t.Fatal(r.Stdout + r.Stderr)
		}
	}
	out := filepath.Join(tmp, "out.json")
	r := run(t, "resolve", "--input", evidencePath("windows-server-2022"), "--data-dir", data, "--output", out)
	if r.Code != 0 {
		t.Fatalf("exit %d\n%s", r.Code, r.Stderr)
	}
	if !strings.Contains(r.Stderr, "warning: old data: app-mapper (8 days); run `openness-resolver feed sync`") {
		t.Errorf("stderr:\n%s", r.Stderr)
	}
	for _, s := range readStale(t, out).RuleCoverage.Sources {
		if s.Stale == nil || *s.Stale != (s.Source == "app-mapper") {
			t.Errorf("%s stale %v", s.Source, s.Stale)
		}
	}
}

// writeMapperVersion writes the device mapper with another version.
func writeMapperVersion(t *testing.T, dir, version string) string {
	t.Helper()
	raw, err := os.ReadFile(deviceMapper(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	m["version"], _ = json.Marshal(version)
	raw, _ = json.Marshal(m)
	p := filepath.Join(dir, version+".json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMapperNoSilentDowngrade(t *testing.T) {
	tmp := t.TempDir()
	newer := fakeCatalogRelease(t, writeMapperVersion(t, tmp, "2099.01.02"), false)
	older := fakeCatalogRelease(t, writeMapperVersion(t, tmp, "2099.01.01"), false)
	ancient := fakeCatalogRelease(t, writeMapperVersion(t, tmp, "2000.01.01"), false)
	data := filepath.Join(tmp, "data")
	version := func(dir string) string {
		raw, _ := os.ReadFile(filepath.Join(dir, "mapper", "app-mapper.json.gz.meta.json"))
		var m struct {
			Version string `json:"version"`
		}
		json.Unmarshal(raw, &m)
		return m.Version
	}
	sync := func(url string, extra ...string) cliResult {
		return run(t, append([]string{"feed", "sync", "--source", "app-mapper", "--mapper-url", url, "--data-dir", data}, extra...)...)
	}
	if r := sync(newer); r.Code != 0 || version(data) != "2099.01.02" {
		t.Fatalf("exit %d version %s\n%s", r.Code, version(data), r.Stdout)
	}
	r := sync(older)
	if r.Code != 0 || !strings.Contains(r.Stdout, "older than the synced one (2099.01.02); kept the current mapper") || version(data) != "2099.01.02" {
		t.Errorf("downgrade: exit %d version %s\n%s", r.Code, version(data), r.Stdout)
	}
	if r := sync(older, "--allow-downgrade"); r.Code != 0 || version(data) != "2099.01.01" {
		t.Errorf("--allow-downgrade: exit %d version %s\n%s", r.Code, version(data), r.Stdout)
	}
	empty := filepath.Join(tmp, "empty")
	r = run(t, "feed", "sync", "--source", "app-mapper", "--mapper-url", ancient, "--data-dir", empty)
	if r.Code != 0 || !strings.Contains(r.Stdout, "older than the built-in one") {
		t.Errorf("older than built-in: exit %d\n%s", r.Code, r.Stdout)
	}
	if _, err := os.Stat(filepath.Join(empty, "mapper", "app-mapper.json.gz")); err == nil {
		t.Error("a mapper older than the built-in one was installed")
	}
	if r := run(t, "feed", "sync", "--allow-downgrade=maybe"); r.Code != 2 {
		t.Errorf("--allow-downgrade=maybe: exit %d", r.Code)
	}
}
