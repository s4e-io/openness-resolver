package appvuln

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"24.08", "24.08.00.0", 0}, {"24.08", "24.09", -1}, {"115.10", "115.9.1", 1}, {"1.0", "1.0beta", 1},
		{"3.0.18.0", "3.0.20", -1}, {"0.78.0.0", "0.81", -1}, {"", "1", -1}, {"2.39.2", "2.39.2", 0},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAffected(t *testing.T) {
	rs := []Range{{StartIncl: "115.0", EndExcl: "115.10"}, {StartIncl: "128.0", EndExcl: "128.3"}, {Exact: "8.5.4"}}
	if fix, ok := affected("115.3.1", rs, false); !ok || fix != "115.10" {
		t.Fatalf("115.3.1: %q %v", fix, ok)
	}
	if _, ok := affected("115.10", rs, false); ok {
		t.Fatal("115.10 is fixed")
	}
	if _, ok := affected("8.5.4", rs, false); !ok {
		t.Fatal("exact version")
	}
	if _, ok := affected("1.0", []Range{{}}, false); ok {
		t.Fatal("an open range is too broad to report")
	}
}

func testData(t *testing.T) *Data {
	t.Helper()
	cat := `[{"id":"Mozilla.Firefox.ESR","name":"Mozilla Firefox ESR","match":{"name":"^Mozilla Firefox.*\\bESR\\b","publisher":"Mozilla"},"version":{},"cpe":["mozilla:firefox_esr"],"update":"winget upgrade --id Mozilla.Firefox.ESR","verified":true},
	 {"id":"Mozilla.Firefox","name":"Mozilla Firefox","match":{"name":"^Mozilla Firefox\\b","not_name":"\\bESR\\b"},"version":{},"cpe":["mozilla:firefox"],"verified":true},
	 {"id":"Python.Python.3","name":"Python","match":{"name":"^Python [0-9.]+ \\((64|32)-bit\\)$"},"version":{"from":"product_name","regex":"Python ([0-9]+\\.[0-9]+\\.[0-9]+)"},"cpe":["python:python"],"verified":true},
	 {"id":"Auto.Tool","name":"Auto Tool","match":{"name":"^Auto Tool"},"version":{},"cpe":["auto:tool"],"verified":false}]`
	db := `{"version":"t","products":{
	 "mozilla:firefox_esr":[{"cve":"CVE-1","cvss":9.8,"sev":"critical","r":[{"si":"115.0","ee":"115.10"}]},{"cve":"CVE-2","sev":"high","r":[{"ee":"115.2"}]}],
	 "mozilla:firefox":[{"cve":"CVE-3","sev":"high","r":[{"ee":"200"}]}],
	 "python:python":[{"cve":"CVE-4","sev":"medium","r":[{"si":"3.11.0","ee":"3.11.5"}]}],
	 "auto:tool":[{"cve":"CVE-5","sev":"low","r":[{"ee":"9"}]}]}}`
	d, err := Load([]byte(cat), []byte(db))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ev(apps ...map[string]any) []byte {
	var list []any
	for _, a := range apps {
		list = append(list, map[string]any{"value": a})
	}
	b, _ := json.Marshal(map[string]any{"operating_system": map[string]any{"distribution_id": "windows"}, "applications": list})
	return b
}

func TestEvaluate(t *testing.T) {
	d := testData(t)
	doc := ev(
		map[string]any{"product_name": "Mozilla Firefox ESR (x64 en-US)", "display_version": "115.3.1", "publisher": "Mozilla"},
		map[string]any{"product_name": "Mozilla Firefox ESR (x64 en-US)", "display_version": "115.3.1", "publisher": "Mozilla"}, // a duplicate entry
		map[string]any{"product_name": "Python 3.11.4 (64-bit)", "display_version": "3.11.4150.0"},
		map[string]any{"product_name": "Python 3.11.4 Core Interpreter (64-bit)", "display_version": "3.11.4150.0"},
		map[string]any{"product_name": "Auto Tool", "display_version": "1.0"},
		map[string]any{"product_name": "Unknown App", "display_version": "1.0"},
	)
	r := d.Evaluate(doc, Options{})
	ids := []string{}
	for _, f := range r.Findings {
		ids = append(ids, f.CVEID+"/"+f.InstalledVersion)
	}
	// ESR is not Firefox (CVE-3), the Python component entries are not Python, the auto entry is off,
	// and Python's version comes from its name (3.11.4150.0 would be past 3.11.5).
	if strings.Join(ids, " ") != "CVE-1/115.3.1 CVE-4/3.11.4" || r.Matched != 2 {
		t.Fatalf("findings %v matched %d", ids, r.Matched)
	}
	if len(r.Remediations) != 2 || r.Remediations[0].Action != "Update Mozilla Firefox ESR to 115.10 or later" ||
		r.Remediations[0].CommandHint != "winget upgrade --id Mozilla.Firefox.ESR" || r.Remediations[0].MaxSeverity != "critical" {
		t.Fatalf("remediations %+v", r.Remediations)
	}
	if f := r.Findings[0]; f.CVSSScore == nil || *f.CVSSScore != 9.8 || f.State != "vulnerable" || f.FixedVersion != "115.10" {
		t.Fatalf("finding %+v", f)
	}
	if r := d.Evaluate(doc, Options{Unverified: true}); len(r.Findings) != 3 || !strings.Contains(strings.Join(r.Findings[0].Reasons, " "), "not reviewed") {
		t.Fatalf("with unverified %+v", r.Findings)
	}
	if r := d.Evaluate([]byte(`{"operating_system":{"distribution_id":"ubuntu"}}`), Options{Unverified: true}); len(r.Findings) != 0 {
		t.Fatal("linux evidence")
	}
}

func TestBuiltinLoads(t *testing.T) {
	d, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	for _, p := range d.Catalog {
		if p.Verified {
			verified++
		}
	}
	if verified < 40 || len(d.DB.Products) < 40 {
		t.Fatalf("catalog %d verified, db %d products", verified, len(d.DB.Products))
	}
}

func TestVersionFirstSubmatch(t *testing.T) {
	d, err := Load([]byte(`[{"id":"openjdk","name":"OpenJDK","match":{"name":"^OpenJDK"},
		"version":{"from":"product_name","regex":"\\b((1[1-9]|2[0-9])\\.[0-9]+\\.[0-9]+)"},"cpe":["oracle:openjdk"],"verified":true}]`),
		[]byte(`{"version":"t","products":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	// the outer group is the version; an inner group must not replace it
	if v := d.Catalog[0].versionOf(app{ProductName: "OpenJDK Platform 17.0.8"}); v != "17.0.8" {
		t.Fatalf("version %q, want 17.0.8", v)
	}
}

func TestVersionFormat(t *testing.T) {
	d, err := Load([]byte(`[{"id":"java","name":"Java","match":{"name":"^Java"},
		"version":{"from":"product_name","regex":"(?P<major>[1-8]) Update (?P<upd>[0-9]+)","format":"1.${major}.0.${upd}"},
		"cpe":["oracle:jre"],"verified":true}]`), []byte(`{"version":"t","products":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"Java 8 Update 401 (64-bit)":                    "1.8.0.401",
		"Java SE Development Kit 8 Update 202 (64-bit)": "1.8.0.202",
		"Java(TM) 6 Update 45":                          "1.6.0.45",
		"Java 8":                                        "",
	} {
		if v := d.Catalog[0].versionOf(app{ProductName: name}); v != want {
			t.Errorf("%q: version %q, want %q", name, v, want)
		}
	}
	if _, err := Load([]byte(`[{"id":"x","name":"X","match":{"name":"^X"},"version":{"format":"$1"},"cpe":["a:b"]}]`),
		[]byte(`{"version":"t","products":{}}`)); err == nil {
		t.Error("a format without a regex loaded")
	}
}

func TestExactUpTo(t *testing.T) {
	rs := []Range{{Exact: "1.8.0.391"}, {Exact: "1.8.0.401"}, {Exact: "11.0.22"}}
	for v, want := range map[string]bool{
		"1.8.0.202": true,  // an older update of the listed line
		"1.8.0.401": true,  // listed
		"1.8.0.411": false, // newer than every listed 8 update
		"11.0.20":   true,
		"17.0.8":    false, // no 17 release is listed
		"1.7.0.80":  false, // another line
	} {
		if _, ok := affected(v, rs, true); ok != want {
			t.Errorf("%s: affected %v, want %v", v, ok, want)
		}
	}
	if _, ok := affected("1.8.0.202", rs, false); ok {
		t.Error("without exact_up_to an unlisted version is affected")
	}
}

func TestCVEUnderTwoCPEs(t *testing.T) {
	d, err := Load([]byte(`[{"id":"java","name":"Java","match":{"name":"^Java"},"cpe":["oracle:jre","oracle:jdk"],"verified":true}]`),
		[]byte(`{"version":"t","products":{
		 "oracle:jre":[{"cve":"CVE-1","sev":"high","r":[{"ee":"2.0"}]}],
		 "oracle:jdk":[{"cve":"CVE-1","sev":"high","r":[{"ee":"2.0"}]},{"cve":"CVE-2","sev":"low","r":[{"ee":"2.0"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := d.Evaluate(ev(map[string]any{"product_name": "Java", "display_version": "1.0"}), Options{})
	if len(r.Findings) != 2 || len(r.Remediations) != 1 || r.Remediations[0].ClosesCount != 2 {
		t.Fatalf("findings %d, remediations %+v", len(r.Findings), r.Remediations)
	}
}

// Firefox ESR 115 is not reached by a range of the 128 line, and a range under plain
// "firefox" that is the 115 line's fix counts.
func TestSameBranch(t *testing.T) {
	d, err := Load([]byte(`[{"id":"esr","name":"Firefox ESR","match":{"name":"ESR"},"cpe":["mozilla:firefox_esr","mozilla:firefox"],"verified":true,"same_branch":true}]`),
		[]byte(`{"products":{
		 "mozilla:firefox_esr":[{"cve":"CVE-128-ONLY","sev":"HIGH","r":[{"ee":"128.4.0"}]},{"cve":"CVE-115","sev":"HIGH","r":[{"ee":"115.10"}]}],
		 "mozilla:firefox":[{"cve":"CVE-RAPID","sev":"HIGH","r":[{"ee":"148.0"}]},{"cve":"CVE-115-PLAIN","sev":"HIGH","r":[{"ee":"115.39.0"},{"ee":"140.14.0"}]},
		   {"cve":"CVE-EXACT","sev":"LOW","r":[{"v":"115.3.1"}]},{"cve":"CVE-OPEN","sev":"LOW","r":[{"si":"100.0"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := d.EvaluateApps(apps(`{"product_name":"Firefox ESR","display_version":"115.3.1"}`), Options{})
	got := map[string]string{}
	for _, f := range r.Findings {
		got[f.CVEID] = f.FixedVersion
	}
	want := map[string]string{"CVE-115": "115.10", "CVE-115-PLAIN": "115.39.0", "CVE-EXACT": "", "CVE-OPEN": ""}
	if len(got) != len(want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	for k, v := range want {
		if fix, ok := got[k]; !ok || fix != v {
			t.Errorf("%s: fix %q (found %v), want %q", k, fix, ok, v)
		}
	}
	// On the 128 line the 128 range counts and the 115 ones do not.
	r = d.EvaluateApps(apps(`{"product_name":"Firefox ESR","display_version":"128.3.0"}`), Options{})
	if len(r.Findings) != 2 || r.Findings[0].CVEID != "CVE-128-ONLY" && r.Findings[1].CVEID != "CVE-128-ONLY" {
		t.Fatalf("128 line: %+v", r.Findings)
	}
}
