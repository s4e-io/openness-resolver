package resolver_test

import (
	"encoding/json"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/resolver"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

func testMapper(t *testing.T) *appvuln.Data {
	t.Helper()
	d, err := appvuln.Load(
		[]byte(`[{"id":"acme.tool","name":"Acme Tool","match":{"name":"^Acme Tool"},"cpe":["acme:tool"],"verified":true,"update":"winget upgrade --id Acme.Tool"}]`),
		[]byte(`{"version":"t1","products":{"acme:tool":[
		  {"cve":"CVE-2026-0001","sev":"HIGH","cvss":8.1,"r":[{"ee":"2.0"}]},
		  {"cve":"CVE-2026-0002","sev":"MEDIUM","r":[{"si":"1.0","ee":"1.6"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	d.Version = "t1"
	return d
}

func appRecord(t *testing.T, v map[string]any) evidence.Record {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return evidence.Record{EvidenceID: "app", Value: b}
}

// A Windows host's applications get CVE findings with the NVD rating, one update card per
// application version next to the OS card, and a status list; the cards still balance.
func TestWindowsApplications(t *testing.T) {
	lr, err := tf.NewWindowsServer2022("5386").Load()
	if err != nil {
		t.Fatal(err)
	}
	lr.Doc.Applications = []evidence.Record{
		appRecord(t, map[string]any{"product_name": "Acme Tool", "display_version": "1.5", "publisher": "Acme"}),
		appRecord(t, map[string]any{"product_name": "Contoso Payroll", "display_version": "3.1", "publisher": "Contoso"}),
	}
	e := resolver.NewEngine(windowsRules())
	e.Apps = testMapper(t)
	res, err := e.Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	var app []findings.Finding
	for _, f := range res.Findings {
		if f.DetectionMethod == resolver.MethodNVDCPERange {
			app = append(app, f)
		}
	}
	if len(app) != 2 {
		t.Fatalf("application findings %+v", app)
	}
	for _, f := range app {
		if f.State != findings.StateVulnerable || f.Distribution != "windows" || f.BinaryPackage != "Acme Tool" || f.Confidence != "high" {
			t.Errorf("finding %+v", f)
		}
		if f.CVEID == "CVE-2026-0001" && (f.Severity != "high" || f.CVSSScore == nil || *f.CVSSScore != 8.1 || f.FixedVersion != "2.0") {
			t.Errorf("rating %+v", f)
		}
	}
	var card *findings.RemediationGroup
	for i, g := range res.RemediationGroups {
		if g.Action == findings.ActionUpdateApplication {
			card = &res.RemediationGroups[i]
		}
	}
	if card == nil || *card.Closes.Count != 2 || card.Targets[0].Kind != findings.TargetKindApplication ||
		card.Targets[0].TargetVersion != "2.0" || card.CommandHint != "winget upgrade --id Acme.Tool" || card.SourcePackage != "acme.tool" {
		t.Fatalf("application card %+v", card)
	}
	if !res.Reconciliation.RemediationBalanced {
		t.Fatalf("reconciliation must balance: %+v", res.Reconciliation)
	}
	if res.ApplicationMapper != "t1" || len(res.Applications) != 2 || res.Applications[1].Status != appvuln.AppUnmatched {
		t.Fatalf("applications %q %+v", res.ApplicationMapper, res.Applications)
	}

	// Without a mapper the applications are not looked at.
	lr2, _ := tf.NewWindowsServer2022("5386").Load()
	lr2.Doc.Applications = lr.Doc.Applications
	res2, err := resolver.NewEngine(windowsRules()).Resolve(lr2)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Applications != nil || res2.ApplicationMapper != "" {
		t.Fatalf("no mapper: %+v", res2.Applications)
	}
}

// Applications on a Linux host are not judged by the Windows application mapper.
func TestApplicationsOnlyOnWindows(t *testing.T) {
	lr, err := tf.NewWindowsServer2022("5386").Load()
	if err != nil {
		t.Fatal(err)
	}
	lr.Doc.OperatingSystem.DistributionID = "ubuntu"
	lr.Doc.Applications = []evidence.Record{appRecord(t, map[string]any{"product_name": "Acme Tool", "display_version": "1.5"})}
	e := resolver.NewEngine(windowsRules())
	e.Apps = testMapper(t)
	res, err := e.Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.DetectionMethod == resolver.MethodNVDCPERange {
			t.Fatalf("application finding on a non-Windows host: %+v", f)
		}
	}
}
