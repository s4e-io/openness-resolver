package appvuln

import (
	"strings"
	"testing"
)

func testFallback(t *testing.T) *Data {
	t.Helper()
	d, err := Load([]byte(`[{"id":"Docker.DockerDesktop","name":"Docker Desktop","match":{"name":"^Docker Desktop$"},"cpe":["docker:desktop"],"verified":true}]`),
		[]byte(`{"version":"t","products":{"docker:desktop":[{"cve":"CVE-2000-0001","sev":"high","r":[{"ee":"9.0"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	vuln := `[{"cve":"CVE-2001-0001","cvss":7.5,"sev":"HIGH","r":[{"ee":"5.0"}]}]`
	fb := `{"version":"t","products":{` +
		`"jetbrains:youtrack":` + vuln + `,"valvesoftware:steam_client":` + vuln + `,"file_project:file":` + vuln +
		`,"git:git":` + vuln + `,"docker:docker":` + vuln + `,"zimbra:zimbra":` + vuln + `,"c-ares_project:c-ares":` + vuln +
		`,"openvpn:openvpn_3":` + vuln + `,"roonlabs:roon_server":` + vuln + `,"media-server_project:media-server":` + vuln +
		`,"microsoft:teams":` + vuln + `,"python:python":` + vuln + `,"acme:widget":` + vuln + `,"other:widget":` + vuln +
		`},"titles":{"jetbrains:youtrack":"JetBrains YouTrack"}}`
	if err := d.LoadFallback([]byte(fb)); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestFallbackMatch(t *testing.T) {
	d := testFallback(t)
	for _, c := range []struct{ name, publisher, want string }{
		{"JetBrains YouTrack", "JetBrains s.r.o.", "jetbrains:youtrack"},
		{"Steam", "Valve Corporation", "valvesoftware:steam_client"}, // "client" may be left out
		{"File Converter", "Adrien Allard", ""},                      // file_project:file is the Unix file command
		{"File", "file_project", "file_project:file"},                // the publisher is that vendor
		{"git-crypt", "AGWA", ""},                                    // git:git needs Git as the publisher
		{"Docker Compose", "Docker Inc.", ""},                        // one word more than a one-word product
		{"Zimbra Desktop", "Zimbra", ""},                             // a desktop program is not the server
		{"Ares", "Ares Galaxy", ""},                                  // c-ares needs the "c"
		{"OpenVPN", "OpenVPN Inc.", ""},                              // openvpn_3 needs the 3
		{"Roon", "Roon Labs", ""},                                    // the server needs "server"
		{"Universal Media Server", "Universal Media Server", ""},     // the publisher is not media-server_project
		{"Microsoft Teams", "Microsoft Corporation", ""},             // Microsoft is left to Windows Update
		{"Microsoft.Windows.Search", "Microsoft", ""},                // a Store package id
		{"Python 3.11.4 Documentation (64-bit)", "Python Software Foundation", ""},
		{"Widget", "", ""}, // two vendors fit equally: no guess
	} {
		got := ""
		if p := d.fb.match(app{ProductName: c.name, Publisher: c.publisher}); p != nil {
			got = p.key
		}
		if got != c.want {
			t.Errorf("%q by %q: got %q, want %q", c.name, c.publisher, got, c.want)
		}
	}
}

func TestFallbackFindings(t *testing.T) {
	d := testFallback(t)
	doc := []byte(`{"operating_system":{"distribution_id":"windows"},"applications":[
	 {"value":{"product_name":"JetBrains YouTrack","display_version":"4.2","publisher":"JetBrains"}},
	 {"value":{"product_name":"JetBrains YouTrack","display_version":"4.2","publisher":"JetBrains"}},
	 {"value":{"product_name":"Steam","display_version":"N-1234-gabc","publisher":"Valve"}},
	 {"value":{"product_name":"Docker Desktop","display_version":"4.1","publisher":"Docker Inc."}}]}`)
	r := d.Evaluate(doc, Options{Fallback: true})
	// YouTrack once (the duplicate entry is one application), Steam has no version, Docker
	// Desktop is the catalog's
	if r.Guessed != 1 || r.Matched != 1 || len(r.Findings) != 2 {
		t.Fatalf("guessed %d, matched %d, findings %+v", r.Guessed, r.Matched, r.Findings)
	}
	var g, c int
	for _, f := range r.Findings {
		switch f.State {
		case "potentially_vulnerable":
			g++
			if f.SourcePackage != "jetbrains:youtrack" || f.Severity != "high" ||
				!strings.Contains(strings.Join(f.Reasons, " "), "not in the reviewed application catalog") {
				t.Errorf("guess %+v", f)
			}
		case "vulnerable":
			c++
		}
	}
	if g != 1 || c != 1 || len(r.Remediations) != 1 {
		t.Fatalf("guessed findings %d, catalog findings %d, remediations %d", g, c, len(r.Remediations))
	}
	if r := d.Evaluate(doc, Options{}); r.Guessed != 0 || len(r.Findings) != 1 {
		t.Fatalf("fallback off: %+v", r)
	}
}
