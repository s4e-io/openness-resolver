package appvuln

import (
	"encoding/json"
	"strings"
	"testing"
)

const verifyCatalog = `[
 {"id":"microsoft.silverlight","name":"Microsoft Silverlight","match":{"name":"^Microsoft Silverlight","publisher":"Microsoft"},
  "version":{"parts":3},"cpe":["microsoft:silverlight"],"verified":true,
  "verify":{"product_codes":["{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}"],
            "file":{"path":"Microsoft Silverlight\\sllauncher.exe","base":"program_files","signer":"Microsoft Corporation","version_from_file":true}}},
 {"id":"acme.tool","name":"Acme Tool","match":{"name":"^Acme Tool"},"cpe":["acme:tool"],"verified":true}]`

const verifyVulns = `{"version":"t","products":{
 "microsoft:silverlight":[{"cve":"CVE-2026-1000","sev":"HIGH","r":[{"ee":"5.1.50918"}]}],
 "acme:tool":[{"cve":"CVE-2026-2000","sev":"LOW","r":[{"ee":"2.0"}]}]}}`

func verifyData(t *testing.T) *Data {
	t.Helper()
	d, err := Load([]byte(verifyCatalog), []byte(verifyVulns))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func silverlightApp(extra string) string {
	return `{"product_name":"Microsoft Silverlight","publisher":"Microsoft Corporation","display_version":"5.1.50000.0"` + extra + `}`
}

func signed(signer, status, version string) string {
	b, _ := json.Marshal([]map[string]any{{"probe_id": "microsoft.silverlight", "path": `C:\Program Files\Microsoft Silverlight\sllauncher.exe`,
		"exists": true, "file_version": version, "signature_status": status, "signer_cn": signer}})
	return `,"file_checks":` + string(b)
}

func TestVerifyMatches(t *testing.T) {
	d := verifyData(t)
	for _, c := range []struct {
		name, app, status, strength, version string
		cves                                 int
	}{
		{"signed file, version from the file", silverlightApp(signed("Microsoft Corporation", "valid", "5.1.40000.0")), AppMatched, StrengthSignature, "5.1.40000", 1},
		{"signed file is newer: no CVE", silverlightApp(signed("Microsoft Corporation", "valid", "5.1.50918.0")), AppMatched, StrengthSignature, "5.1.50918", 0},
		{"product code (subkey)", silverlightApp(`,"key":"{89f4137d-6c26-4a84-bdb8-2e5a4bb71e00}"`), AppMatched, StrengthProductCode, "5.1.50000", 1},
		{"product code (field)", silverlightApp(`,"product_code":"{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}"`), AppMatched, StrengthProductCode, "5.1.50000", 1},
		{"renamed program: its file is not there", silverlightApp(`,"key":"Notepad++","file_checks":[{"probe_id":"microsoft.silverlight","path":"C:\\Program Files\\Microsoft Silverlight\\sllauncher.exe","exists":false}]`), AppVerifyFailed, "", "", 0},
		{"not checked (old collector): name only", silverlightApp(`,"key":"Notepad++"`), AppMatched, StrengthName, "5.1.50000", 1},
		{"check failed to run: name only", silverlightApp(`,"file_checks":[{"probe_id":"microsoft.silverlight","path":"x","exists":false,"error":"not checked: powershell failed"}]`), AppMatched, StrengthName, "5.1.50000", 1},
		{"wrong signer", silverlightApp(signed("Evil Corp", "valid", "5.1.40000.0")), AppVerifyFailed, "", "", 0},
		{"bad signature", silverlightApp(signed("Microsoft Corporation", "invalid", "5.1.40000.0")), AppVerifyFailed, "", "", 0},
		{"no verify: the name decides", `{"product_name":"Acme Tool","display_version":"1.0"}`, AppMatched, StrengthName, "1.0", 1},
	} {
		r := d.EvaluateApps(apps(c.app), Options{})
		a := r.Applications[0]
		if a.Status != c.status || a.MatchStrength != c.strength || a.MatchedVersion != c.version || len(r.Findings) != c.cves {
			t.Errorf("%s: status %s strength %q version %q, %d findings (%s)", c.name, a.Status, a.MatchStrength, a.MatchedVersion, len(r.Findings), a.VerifyReason)
			continue
		}
		if c.status == AppVerifyFailed && a.VerifyReason == "" {
			t.Errorf("%s: no reason", c.name)
		}
		for _, f := range r.Findings {
			if f.MatchStrength != c.strength {
				t.Errorf("%s: finding strength %q", c.name, f.MatchStrength)
			}
			if c.strength == StrengthSignature && !strings.Contains(strings.Join(f.Reasons, " "), "signed by Microsoft Corporation") {
				t.Errorf("%s: reasons %v", c.name, f.Reasons)
			}
		}
	}
	// a refused match is not guessed by the fallback either
	if r := d.EvaluateApps(apps(silverlightApp(signed("Evil Corp", "valid", "5.1.40000.0"))), Options{Fallback: true}); len(r.Findings) != 0 {
		t.Fatalf("fallback reported a refused match: %+v", r.Findings)
	}
}

func TestProbes(t *testing.T) {
	ps := verifyData(t).Probes()
	if len(ps) != 1 || ps[0].ID != "microsoft.silverlight" || ps[0].Base != "program_files" || ps[0].Name != "^Microsoft Silverlight" || ps[0].Publisher != "Microsoft" {
		t.Fatalf("probes %+v", ps)
	}
	if b, err := Builtin(); err != nil || b.Probes() == nil {
		t.Fatalf("builtin probes: %v", err)
	}
}
