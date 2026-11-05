package main

// Golden end-to-end tests of the CLI, offline and deterministic.
//
// Each case builds a fresh data directory with `openness-resolver rules import` from
// small committed feed fixtures (testdata/feeds, internal/resolver/testdata/msrc),
// runs `openness-resolver resolve` on a committed synthetic evidence file
// (testdata/evidence/synthetic) and compares the exit code, stderr, findings,
// remediation groups and rule_coverage with testdata/golden/<case>.json.
// The same golden files must pass on Linux and on Windows.
//
//	go test ./cmd/openness -run TestGolden            # compare
//	go test ./cmd/openness -run TestGolden -update    # rewrite the golden files

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// feedImport is one `rules import` before resolve. zipDir, when set, names a
// directory of OSV JSON documents that is packed into an all.zip archive first,
// the shape the publisher serves.
type feedImport struct {
	source string
	file   string
	zipDir string
}

type goldenCase struct {
	name     string
	evidence string
	imports  []feedImport
	// pypi syncs the evidence's PyPI packages from a local OSV mirror.
	pypi bool
}

const fetchedAt = "2026-10-30T00:00:00Z"

var goldenCases = []goldenCase{
	{name: "ubuntu-22.04-jammy", evidence: "ubuntu-22.04-jammy", pypi: true, imports: []feedImport{
		{source: "ubuntu-oval-usn-jammy", file: "testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml"},
	}},
	// The same host without its PyPI rules: coverage is missing, resolve exits 1.
	{name: "ubuntu-22.04-jammy-missing-pypi", evidence: "ubuntu-22.04-jammy", imports: []feedImport{
		{source: "ubuntu-oval-usn-jammy", file: "testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml"},
	}},
	{name: "debian-11-bullseye", evidence: "debian-11-bullseye", imports: []feedImport{
		{source: "debian-security-tracker", file: "testdata/feeds/debian/tracker-sample.json"},
	}},
	{name: "debian-12-bookworm", evidence: "debian-12-bookworm", imports: []feedImport{
		{source: "debian-security-tracker", file: "testdata/feeds/debian/tracker-sample.json"},
	}},
	{name: "debian-13-trixie", evidence: "debian-13-trixie", imports: []feedImport{
		{source: "debian-security-tracker", file: "testdata/feeds/debian/tracker-sample.json"},
	}},
	{name: "rhel-9", evidence: "rhel-9", imports: []feedImport{
		{source: "osv-rhel", zipDir: "testdata/feeds/osv/rhel"},
	}},
	{name: "rocky-9", evidence: "rocky-9", imports: []feedImport{
		{source: "osv-rocky", zipDir: "testdata/feeds/osv/rocky"},
	}},
	{name: "almalinux-8", evidence: "almalinux-8", imports: []feedImport{
		{source: "osv-almalinux", zipDir: "testdata/feeds/osv/almalinux"},
	}},
	{name: "opensuse-leap-15.6", evidence: "opensuse-leap-15.6", imports: []feedImport{
		{source: "osv-opensuse", zipDir: "testdata/feeds/osv/opensuse"},
	}},
	// Alpine main and community documents share one rule file per branch.
	{name: "alpine-3.20", evidence: "alpine-3.20", imports: []feedImport{
		{source: "alpine-secdb-v3.20", file: "testdata/feeds/alpine/v3.20/main.json"},
		{source: "alpine-secdb-v3.20", file: "testdata/feeds/alpine/v3.20/community.json"},
	}},
	{name: "windows-server-2022", evidence: "windows-server-2022", imports: []feedImport{
		{source: "msrc-cvrf-2023-Jan", file: "internal/resolver/testdata/msrc/2023-Jan.json"},
		{source: "msrc-cvrf-2026-Oct", file: "internal/resolver/testdata/msrc/2026-Oct.json"},
	}},
	// No rules at all: never an all-clear, resolve exits 1.
	{name: "windows-server-2022-no-rules", evidence: "windows-server-2022"},
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			got := runGoldenCase(t, tc)
			compareGolden(t, filepath.Join("testdata", "golden", tc.name+".json"), got)
		})
	}
}

func runGoldenCase(t *testing.T, tc goldenCase) []byte {
	t.Helper()
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	for _, imp := range tc.imports {
		file := fixture(imp.file)
		if imp.zipDir != "" {
			file = packZip(t, fixture(imp.zipDir), filepath.Join(tmp, filepath.Base(imp.zipDir)+"-all.zip"))
		}
		r := run(t, "rules", "import", "--source", imp.source, "--file", file,
			"--fetched-at", fetchedAt, "--data-dir", dataDir)
		if r.Code != 0 {
			t.Fatalf("rules import %s: exit %d\n%s%s", imp.source, r.Code, r.Stdout, r.Stderr)
		}
	}
	ev := evidencePath(tc.evidence)
	var mirror *osvMirror
	if tc.pypi {
		mirror = newOSVMirror(t)
		r := run(t, "feed", "sync", "--for", ev, "--pypi-only", "--osv-url", mirror.queryURL(), "--data-dir", dataDir)
		if r.Code != 0 {
			t.Fatalf("feed sync --pypi-only: exit %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		}
	}
	out := filepath.Join(tmp, "findings.json")
	// --stale-after 0: the fixtures were fetched on a fixed date, so their age grows;
	// old-data warnings have their own tests (stale_test.go).
	r := run(t, "resolve", "--input", ev, "--data-dir", dataDir, "--output", out, "--stale-after", "0")
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("resolve wrote no findings (exit %d): %v\n%s", r.Code, err, r.Stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	stderr := strings.ReplaceAll(r.Stderr, "\r\n", "\n")
	stderr = strings.ReplaceAll(stderr, ev, "<evidence>")
	golden := map[string]any{
		"exit_code":          r.Code,
		"stderr":             stderr,
		"platform_support":   doc["platform_support"],
		"platform_tested":    doc["platform_tested"],
		"support_reason":     doc["support_reason"],
		"rule_coverage":      doc["rule_coverage"],
		"findings":           doc["findings"],
		"remediation_groups": doc["remediation_groups"],
		"notes":              doc["notes"],
	}
	if mirror != nil {
		maskPyPISnapshot(golden)
	}
	maskBuiltinMapper(golden)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(golden); err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(buf.String(), "\n")
	if mirror != nil {
		s = strings.ReplaceAll(s, mirror.URL, "<osv-mirror>")
		s = pypiSnapshot.ReplaceAllString(s, "pypi-<unix-time>")
	}
	return append([]byte(s), '\n')
}

// pypiSnapshot is the raw object id of an OSV PyPI sync, named by the sync time.
var pypiSnapshot = regexp.MustCompile(`pypi-[0-9]{9,}`)

// maskPyPISnapshot replaces the time of the PyPI sync (it ran now) in the
// coverage sources.
func maskPyPISnapshot(golden map[string]any) {
	cov, _ := golden["rule_coverage"].(map[string]any)
	srcs, _ := cov["sources"].([]any)
	for _, s := range srcs {
		if m, ok := s.(map[string]any); ok && m["source"] == "osv-pypi" {
			m["downloaded_at"] = "<sync-time>"
		}
	}
}

// maskBuiltinMapper replaces the version of the built-in application mapper (it changes
// whenever the bundled data is refreshed) and the age of every source in the coverage
// sources.
func maskBuiltinMapper(golden map[string]any) {
	cov, _ := golden["rule_coverage"].(map[string]any)
	srcs, _ := cov["sources"].([]any)
	for _, s := range srcs {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if m["source"] == "app-mapper-builtin" {
			m["version"] = "<builtin>"
		}
		if _, ok := m["age_days"]; ok {
			m["age_days"] = "<age>"
		}
	}
}

// packZip writes the *.json files of dir into a stored (uncompressed) zip with
// fixed timestamps, so the archive bytes and its sha256 are the same on every OS.
func packZip(t *testing.T, dir, dst string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no OSV documents in %s: %v", dir, err)
	}
	sort.Strings(files)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name: filepath.Base(f), Method: zip.Store,
			Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if bytes.Equal(got, want) {
		return
	}
	if bytes.Contains(want, []byte("\r\n")) {
		t.Errorf("%s has CRLF line endings; .gitattributes must keep testdata LF", path)
	}
	gl, wl := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("%s differs at line %d (run with -update after checking the change)\n got: %s\nwant: %s", path, i+1, g, w)
		}
	}
}
