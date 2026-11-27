package appvuln

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func advData(t *testing.T) *Data {
	t.Helper()
	cat := `[{"id":"7zip.7zip","name":"7-Zip","match":{"name":"^7-Zip\\b"},"version":{"parts":2},"cpe":["7-zip:7-zip"],"update":"winget upgrade --id 7zip.7zip","verified":true},
	 {"id":"TeamViewer.TeamViewer","name":"TeamViewer","match":{"name":"^TeamViewer\\b"},"version":{},"cpe":["teamviewer:teamviewer"],"verified":true}]`
	db := `{"version":"t","products":{"7-zip:7-zip":[{"cve":"CVE-NVD-1","sev":"high","r":[{"ee":"24.09"}]}]}}`
	d, err := Load([]byte(cat), []byte(db))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const advFile = `{"format":"openness-advisories/1","version":"2026-11-28T10:00:00Z","advisories":[
 {"id":"7-zip-before-26-06","url":"https://getopenness.com/advisories/7-zip-before-26-06","product_id":"7zip.7zip","status":"active",
  "vulns":[{"cve":"CVE-NEW-1","sev":"high","r":[{"ee":"26.06"}]},{"cve":"CVE-NVD-1","sev":"high","r":[{"ee":"26.06"}]}]},
 {"id":"teamviewer-15-82","product_id":"TeamViewer.TeamViewer","status":"active",
  "vulns":[{"cve":"CVE-TV-1","sev":"medium","r":[{"si":"15.0","ee":"15.82"},{"si":"14.0","ee":"14.7.48809"},{"si":"13.0","ee":"13.2.36222"}]}]},
 {"id":"gone","product_id":"7zip.7zip","status":"withdrawn","vulns":[{"cve":"CVE-GONE","sev":"critical","r":[{"ee":"99"}]}]}]}`

func loadAdv(t *testing.T, s string) *Advisories {
	t.Helper()
	a, err := LoadAdvisories(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func byCVE(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.CVEID] = f
	}
	return m
}

func TestAdvisoryFindings(t *testing.T) {
	d := advData(t)
	d.SetAdvisories(loadAdv(t, advFile))
	res := d.Evaluate(ev(map[string]any{"product_name": "7-Zip 24.08 (x64)", "display_version": "24.08"}), Options{})
	got := byCVE(res.Findings)
	if len(got) != 2 {
		t.Fatalf("findings %v", res.Findings)
	}
	// The NVD reports CVE-NVD-1: the advisory does not repeat it.
	if f := got["CVE-NVD-1"]; f.Advisory != "" || f.CPE != "7-zip:7-zip" {
		t.Fatalf("the NVD finding was replaced by the advisory: %+v", f)
	}
	f := got["CVE-NEW-1"]
	if f.Advisory != "7-zip-before-26-06" || f.AdvisoryURL == "" || f.FixedVersion != "26.06" || f.State != "vulnerable" ||
		len(f.AdvisoryIDs) != 1 || !strings.Contains(f.Reasons[0], "Openness advisory") {
		t.Fatalf("advisory finding %+v", f)
	}
	if _, ok := got["CVE-GONE"]; ok {
		t.Fatal("a withdrawn advisory produced a finding")
	}
	// One update card for the application, with the higher fixed version.
	if len(res.Remediations) != 1 || res.Remediations[0].FixedVersion != "26.06" || res.Remediations[0].ClosesCount != 2 {
		t.Fatalf("card %+v", res.Remediations)
	}
}

// When the NVD has not listed the CVE for this version yet but has for others, the
// advisory still reports it; once the NVD range covers the version, the NVD does.
func TestAdvisoryYieldsToNVDPerVersion(t *testing.T) {
	d := advData(t)
	d.SetAdvisories(loadAdv(t, advFile))
	res := d.Evaluate(ev(map[string]any{"product_name": "7-Zip 25.01 (x64)", "display_version": "25.01"}), Options{})
	got := byCVE(res.Findings)
	if f, ok := got["CVE-NVD-1"]; !ok || f.Advisory != "7-zip-before-26-06" {
		t.Fatalf("25.01 is outside the NVD range but inside the advisory: %+v", res.Findings)
	}
	res = d.Evaluate(ev(map[string]any{"product_name": "7-Zip 26.06 (x64)", "display_version": "26.06"}), Options{})
	if len(res.Findings) != 0 {
		t.Fatalf("26.06 is fixed: %+v", res.Findings)
	}
}

// Several ranges in one CVE: each release line has its own fixed version.
func TestAdvisoryBranches(t *testing.T) {
	d := advData(t)
	d.SetAdvisories(loadAdv(t, advFile))
	for v, want := range map[string]string{"15.70.1": "15.82", "14.7.1": "14.7.48809", "13.2.36222": "", "12.0": ""} {
		res := d.Evaluate(ev(map[string]any{"product_name": "TeamViewer", "display_version": v}), Options{})
		f, ok := byCVE(res.Findings)["CVE-TV-1"]
		if want == "" {
			if ok {
				t.Errorf("%s: not affected, got %+v", v, f)
			}
			continue
		}
		if !ok || f.FixedVersion != want {
			t.Errorf("%s: want fixed %s, got %+v", v, want, res.Findings)
		}
	}
}

func TestAdvisoriesFileChecks(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(advFile))
	w.Close()
	if a, err := LoadAdvisories(&gz); err != nil || len(a.Advisories) != 3 {
		t.Fatalf("gzip file: %v", err)
	}
	for _, bad := range []string{
		`{"format":"openness-advisories/2","advisories":[]}`,
		`{"format":"openness-advisories/1","advisories":[{"id":"x","vulns":[]}]}`,
		`not json`,
	} {
		if _, err := LoadAdvisories(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// Without advisories nothing changes; nil removes them again.
	d := advData(t)
	d.SetAdvisories(loadAdv(t, advFile))
	d.SetAdvisories(nil)
	res := d.Evaluate(ev(map[string]any{"product_name": "7-Zip 24.08 (x64)", "display_version": "24.08"}), Options{})
	if len(res.Findings) != 1 || d.AdvisoriesVersion != "" {
		t.Fatalf("advisories still attached: %+v", res.Findings)
	}
}
