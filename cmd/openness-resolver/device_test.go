package main

// Network devices (resolve --device) and the app-mapper feed source, end to end through the
// binary. The device goldens run the built-in catalog's seed device entries on the
// synthetic device files of testdata/devices against a small vulnerability fixture
// (testdata/devices/vulns.json), so the seed regular expressions are what is tested.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// deviceMapper writes a mapper bundle of the built-in catalog and the device vulns fixture.
func deviceMapper(t *testing.T, dir string) string {
	t.Helper()
	cat, err := os.ReadFile(fixture("internal/appvuln/data/catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := os.ReadFile(fixture("testdata/devices/vulns.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"format": "openness-app-mapper/1", "version": "2099.01.01",
		"catalog": json.RawMessage(cat), "vulns": json.RawMessage(vulns)})
	p := filepath.Join(dir, "devices-mapper.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func devicePath(name string) string { return fixture("testdata/devices/" + name + ".json") }

var deviceCases = []struct {
	name, device string
	unverified   bool
}{
	{name: "device-cisco-ios-xe", device: "cisco-ios-xe", unverified: true},
	{name: "device-fortinet-fortios", device: "fortinet-fortios", unverified: true},
	{name: "device-juniper-junos", device: "juniper-junos", unverified: true},
	// No device entry: not_supported, exit 0, a note.
	{name: "device-no-match", device: "net-snmp-linux", unverified: true},
	// Matched, but no version in software_rev: state unknown, no findings, a note.
	{name: "device-version-unknown", device: "fortinet-no-version", unverified: true},
	// The seed entries are unreviewed: without --app-unverified nothing is claimed.
	{name: "device-unreviewed-entry", device: "cisco-ios-xe"},
	// A host name and addresses in sysDescr, a serial hint: none reaches the findings.
	{name: "device-host-guard", device: "cisco-ios-xe-host-in-descr", unverified: true},
}

func TestGoldenDevices(t *testing.T) {
	for _, tc := range deviceCases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			out := filepath.Join(tmp, "findings.json")
			args := []string{"resolve", "--device", devicePath(tc.device), "--mapper", deviceMapper(t, tmp),
				"--data-dir", filepath.Join(tmp, "data"), "--output", out}
			if tc.unverified {
				args = append(args, "--app-unverified")
			}
			r := run(t, args...)
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("no findings (exit %d): %v\n%s", r.Code, err, r.Stderr)
			}
			if tc.name == "device-no-match" && bytes.Contains(raw, []byte(" gw ")) {
				t.Error("the sysDescr of an unmatched device (it names the host) reached the findings")
			}
			if tc.name == "device-host-guard" {
				for _, secret := range []string{"core-sw1", "example.com", "10.20.30.40", "fe80::1", "FOC1234X0YZ", "C9300-48P", "cisco.com"} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Errorf("findings carry %q from the device file", secret)
					}
				}
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			golden := map[string]any{"exit_code": r.Code, "stderr": strings.ReplaceAll(r.Stderr, "\r\n", "\n")}
			for _, k := range []string{"asset", "platform", "platform_support", "support_reason", "rule_coverage",
				"findings", "remediation_groups", "unknowns", "notes", "application_mapper"} {
				golden[k] = doc[k]
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(golden); err != nil {
				t.Fatal(err)
			}
			compareGolden(t, filepath.Join("testdata", "golden", tc.name+".json"), buf.Bytes())
		})
	}
}

// fakeCatalogRelease serves a GitHub-like release of the S4E catalog: app-mapper.json.gz and
// SHA256SUMS, or 404 when gone is set.
func fakeCatalogRelease(t *testing.T, mapperJSON string, gone bool) string {
	t.Helper()
	raw, err := os.ReadFile(mapperJSON)
	if err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(raw)
	zw.Close()
	sum := sha256.Sum256(z.Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case gone:
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  app-mapper.json.gz\n"))
		case strings.HasSuffix(r.URL.Path, "/app-mapper.json.gz"):
			w.Write(z.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/s4e-io/openness-app-mapper/releases/latest/download/app-mapper.json.gz"
}

type coverageDoc struct {
	RuleCoverage struct {
		State   string `json:"state"`
		Sources []struct {
			Source       string `json:"source"`
			URL          string `json:"url"`
			SHA256       string `json:"sha256"`
			Version      string `json:"version"`
			DownloadedAt string `json:"downloaded_at"`
		} `json:"sources"`
	} `json:"rule_coverage"`
	Findings []struct {
		CVEID string `json:"cve_id"`
	} `json:"findings"`
}

func readCoverage(t *testing.T, path string) coverageDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d coverageDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAppMapperSource(t *testing.T) {
	tmp := t.TempDir()
	mapper := deviceMapper(t, tmp)
	url := fakeCatalogRelease(t, mapper, false)
	gone := fakeCatalogRelease(t, mapper, true)
	data := filepath.Join(tmp, "data")
	out := filepath.Join("{tmp}", "out.json")
	windows := evidencePath("windows-server-2022")
	// a data directory with the mapper synced, for the resolve cases
	if r := run(t, "feed", "sync", "--source", "app-mapper", "--mapper-url", url, "--data-dir", data); r.Code != 0 {
		t.Fatal(r.Stdout + r.Stderr)
	}
	runFlagCases(t, []flagCase{
		{name: "registry lists app-mapper", args: []string{"feed", "list", "--data-dir", "{tmp}"}, stdout: []string{"app-mapper", "openness"}},
		{name: "source dry run", args: []string{"feed", "sync", "--source", "app-mapper", "--dry-run"},
			stdout: []string{"source app-mapper " + rules.AppMapperURL}},
		{name: "mapper-url dry run", args: []string{"feed", "sync", "--source", "app-mapper", "--mapper-url", url, "--dry-run"},
			stdout: []string{"source app-mapper " + url}},
		{name: "vendor openness", args: []string{"feed", "sync", "--vendor", "openness", "--dry-run"}, stdout: []string{"source app-mapper "}},
		{name: "for windows includes app-mapper", args: []string{"feed", "sync", "--for", windows, "--months", "1", "--dry-run"},
			stdout: []string{"host: windows applications -> app-mapper", "source app-mapper "}},
		{name: "for linux has no app-mapper", args: []string{"feed", "sync", "--for", evidencePath("alpine-3.20"), "--dry-run"},
			notStdout: []string{"app-mapper"}},
		{name: "for device", args: []string{"feed", "sync", "--for", devicePath("juniper-junos"), "--dry-run"},
			stdout: []string{"network device -> app-mapper", "source app-mapper "}, notStdout: []string{"osv-pypi", "msrc"}},
		{name: "for device with a host field", args: []string{"feed", "sync", "--for", filepath.Join("{tmp}", "dev.json"), "--dry-run"},
			setup: func(t *testing.T, tmp string) {
				os.WriteFile(filepath.Join(tmp, "dev.json"), []byte(`{"format":"openness-device/1","sys_descr":"x","sys_name":"core-sw1"}`), 0o644)
			},
			code: 1, stderr: []string{`unknown field "sys_name"`, "no host names or addresses"}},
		{name: "sync source", args: []string{"feed", "sync", "--source", "app-mapper", "--mapper-url", url, "--data-dir", "{tmp}"},
			stdout: []string{"==> app-mapper ", "mapper version=2099.01.01"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				var m map[string]any
				raw, err := os.ReadFile(filepath.Join(tmp, "mapper", "app-mapper.json.gz.meta.json"))
				if err != nil || json.Unmarshal(raw, &m) != nil {
					t.Fatalf("metadata: %v", err)
				}
				if m["version"] != "2099.01.01" || m["source_url"] != url || m["downloaded_at"] == "" || len(m["sha256"].(string)) != 64 {
					t.Errorf("metadata %v", m)
				}
				r := run(t, "feed", "list", "--data-dir", tmp)
				if !strings.Contains(r.Stdout, "version=2099.01.01 downloaded_at=") {
					t.Errorf("feed list:\n%s", r.Stdout)
				}
			}},
		{name: "not published fails when asked by name", args: []string{"feed", "sync", "--source", "app-mapper", "--mapper-url", gone, "--data-dir", "{tmp}"},
			code: 1, stdout: []string{"FAILED: app-mapper: not published yet"}},
		{name: "not published is skipped otherwise", args: []string{"feed", "sync", "--vendor", "openness", "--mapper-url", gone, "--data-dir", "{tmp}"},
			stdout: []string{"not published yet", "skipped"}},
		{name: "validate source", args: []string{"feed", "validate", "--source", "app-mapper", "--mapper-url", url, "--data-dir", "{tmp}"},
			stdout: []string{"mapper version=2099.01.01"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if _, err := os.Stat(filepath.Join(tmp, "mapper", "app-mapper.json.gz")); err == nil {
					t.Error("validate installed the mapper")
				}
			}},
		{name: "rules import", args: []string{"rules", "import", "--source", "app-mapper", "--file", mapper, "--fetched-at", "2026-11-05T06:00:00Z", "--data-dir", "{tmp}"},
			stdout: []string{"mapper version=2099.01.01"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				r := run(t, "resolve", "--device", devicePath("juniper-junos"), "--data-dir", tmp, "--output", filepath.Join(tmp, "o.json"), "--app-unverified")
				d := readCoverage(t, filepath.Join(tmp, "o.json"))
				if r.Code != 0 || len(d.RuleCoverage.Sources) != 1 || d.RuleCoverage.Sources[0].DownloadedAt != "2026-11-05T06:00:00Z" {
					t.Errorf("exit %d coverage %+v", r.Code, d.RuleCoverage)
				}
			}},

		// resolve picks --mapper, else <data-dir>/mapper/app-mapper.json.gz, else the built-in one.
		{name: "resolve uses the synced mapper", args: []string{"resolve", "--device", devicePath("juniper-junos"), "--data-dir", data, "--output", out, "--app-unverified"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				d := readCoverage(t, filepath.Join(tmp, "out.json"))
				s := d.RuleCoverage.Sources
				if len(s) != 1 || s[0].Source != "app-mapper" || s[0].Version != "2099.01.01" || s[0].URL != url || s[0].DownloadedAt == "" || len(s[0].SHA256) != 64 {
					t.Errorf("sources %+v", s)
				}
				if len(d.Findings) != 1 || d.Findings[0].CVEID != "CVE-2099-3001" {
					t.Errorf("findings %+v", d.Findings)
				}
			}},
		{name: "resolve --mapper wins over the synced mapper", args: []string{"resolve", "--device", devicePath("juniper-junos"), "--data-dir", data, "--mapper", mapper, "--output", out, "--app-unverified"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if s := readCoverage(t, filepath.Join(tmp, "out.json")).RuleCoverage.Sources; len(s) != 1 || s[0].Source != "app-mapper-file" {
					t.Errorf("sources %+v", s)
				}
			}},
		{name: "resolve falls back to the built-in mapper", args: []string{"resolve", "--device", devicePath("juniper-junos"), "--data-dir", "{tmp}", "--output", out},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if s := readCoverage(t, filepath.Join(tmp, "out.json")).RuleCoverage.Sources; len(s) != 1 || s[0].Source != "app-mapper-builtin" || s[0].Version == "" {
					t.Errorf("sources %+v", s)
				}
			}},
		{name: "resolve windows lists the mapper", args: []string{"resolve", "--input", windows, "--data-dir", data, "--output", out},
			code: 1, // no MSRC rules
			check: func(t *testing.T, tmp string, _ cliResult) {
				if s := readCoverage(t, filepath.Join(tmp, "out.json")).RuleCoverage.Sources; len(s) != 1 || s[0].Source != "app-mapper" || s[0].Version != "2099.01.01" {
					t.Errorf("sources %+v", s)
				}
			}},
		{name: "resolve input and device", args: []string{"resolve", "--input", windows, "--device", devicePath("juniper-junos")}, code: 1,
			stderr: []string{"resolve takes --input or --device, not both"}},
		{name: "resolve device not found", args: []string{"resolve", "--device", filepath.Join("{tmp}", "none.json")}, code: 1,
			stderr: []string{"device: "}},
		{name: "resolve device with an address field", args: []string{"resolve", "--device", filepath.Join("{tmp}", "dev.json"), "--output", out}, code: 1,
			setup: func(t *testing.T, tmp string) {
				os.WriteFile(filepath.Join(tmp, "dev.json"), []byte(`{"format":"openness-device/1","sys_descr":"x","ip_address":"10.0.0.1"}`), 0o644)
			},
			stderr: []string{`unknown field "ip_address"`}},
		{name: "resolve device states", args: []string{"resolve", "--device", devicePath("cisco-ios-xe"), "--mapper", mapper, "--app-unverified", "--output", out, "--states", "vulnerable"},
			stdout: []string{"rule coverage: 3 rules loaded for device/cisco.ios-xe", "CVE-2099-1001", "CVE-2099-1003"}, notStdout: []string{"CVE-2099-1002"}},
	})
}
