package appvuln

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCatalog = `[{"id":"acme.tool","name":"Acme Tool","match":{"name":"^Acme Tool"},"cpe":["acme:tool"],"verified":true,"update":"winget upgrade --id Acme.Tool"},
 {"id":"acme.beta","name":"Acme Beta","match":{"name":"^Acme Beta"},"cpe":["acme:beta"]}]`

const testVulns = `{"version":"t1","products":{"acme:tool":[{"cve":"CVE-2026-0001","sev":"HIGH","cvss":8.1,"r":[{"ee":"2.0"}]}]}}`

func writeBundle(t *testing.T, gz bool, fallback []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteBundle(&buf, "2026.11.3", []byte(testCatalog), []byte(testVulns), fallback); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	name := "mapper.json"
	if gz {
		var z bytes.Buffer
		w := gzip.NewWriter(&z)
		w.Write(data)
		w.Close()
		data, name = z.Bytes(), "mapper.json.gz"
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func apps(vs ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(vs))
	for i, v := range vs {
		out[i] = json.RawMessage(v)
	}
	return out
}

// A mapper file replaces the built-in catalog and database; every application is listed
// with its status, so the ones nothing matched can be reported.
func TestLoadFileAndApplicationStatuses(t *testing.T) {
	for _, gz := range []bool{false, true} {
		d, err := LoadFile(writeBundle(t, gz, nil))
		if err != nil {
			t.Fatal(err)
		}
		if d.Version != "2026.11.3" || len(d.Catalog) != 2 || d.fb == nil {
			t.Fatalf("gz=%v: version %q, %d entries, fallback kept %v", gz, d.Version, len(d.Catalog), d.fb != nil)
		}
		r := d.EvaluateApps(apps(
			`{"product_name":"Acme Tool","display_version":"1.5","publisher":"Acme","product_code":"{1-2}","architecture":"x64"}`,
			`{"product_name":"Acme Tool","display_version":"","publisher":"Acme"}`,
			`{"product_name":"Acme Beta","display_version":"0.9"}`,
			`{"product_name":"Contoso Payroll","display_version":"3.1","publisher":"Contoso"}`,
			`{"display_version":"1.0"}`,
		), Options{})
		if len(r.Findings) != 1 || r.Findings[0].FindingID != "app:acme.tool:1.5:CVE-2026-0001" || r.Findings[0].FixedVersion != "2.0" {
			t.Fatalf("findings %+v", r.Findings)
		}
		if len(r.Remediations) != 1 || r.Remediations[0].FixedVersion != "2.0" || len(r.Remediations[0].FindingIDs) != 1 {
			t.Fatalf("remediations %+v", r.Remediations)
		}
		want := []struct{ name, status string }{
			{"Acme Tool", AppMatched}, {"Acme Tool", AppNoVersion}, {"Acme Beta", AppSkipped}, {"Contoso Payroll", AppUnmatched},
		}
		if len(r.Applications) != len(want) {
			t.Fatalf("applications %+v", r.Applications)
		}
		for i, w := range want {
			if a := r.Applications[i]; a.Name != w.name || a.Status != w.status {
				t.Errorf("application %d = %+v, want %s %s", i, a, w.name, w.status)
			}
		}
		if a := r.Applications[0]; a.ProductID != "acme.tool" || a.CVEs != 1 || a.ProductCode != "{1-2}" || a.Architecture != "x64" {
			t.Errorf("matched row %+v", a)
		}
	}
}

func TestLoadFileRejects(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"format":  `{"format":"other/1","catalog":[],"vulns":{}}`,
		"missing": `{"format":"openness-app-mapper/1","catalog":[{"id":"x","name":"x","match":{"name":"x"},"cpe":[]}]}`,
		"regex":   `{"format":"openness-app-mapper/1","catalog":[{"id":"x","name":"x","match":{"name":"("},"cpe":[]}],"vulns":{"products":{}}}`,
		"json":    `{`,
	} {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadFile(p); err == nil || !strings.Contains(err.Error(), "mapper") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := LoadFile(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("absent file loaded")
	}
}

// The built-in data reports its database version.
func TestBuiltinVersion(t *testing.T) {
	d, err := Builtin()
	if err != nil || d.Version == "" {
		t.Fatalf("builtin version %q, %v", d.Version, err)
	}
}
