package resolver_test

import (
	"encoding/json"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
	_ "github.com/s4e-io/openness-resolver/internal/version/winbuild"
)

func windowsRules() *rules.RuleSet {
	rs := &rules.RuleSet{Rules: []rules.PackageVulnerabilityRule{
		tf.MSRCRule("CVE-2026-100201", "windows_server_2022", "", "KB5126655", "20348.5761", true),
		tf.MSRCRule("CVE-2026-100202", "windows_server_2022", "", "KB5126655", "20348.5761", true),
		tf.MSRCRule("CVE-2026-000001", "windows_server_2022", "", "KB5099540", "20348.5386", false),
		// Same product key but another servicing branch: must be rejected, not compared.
		tf.MSRCRule("CVE-2026-000002", "windows_server_2022", "", "KB0000001", "25398.1000", false),
		// Another product: never selected.
		tf.MSRCRule("CVE-2026-100200", "windows_server_2025", "", "KB5126646", "26100.33650", true),
	}}
	rs.Reindex()
	return rs
}

func TestWindowsVulnerableAndCard(t *testing.T) {
	lr, err := tf.NewWindowsServer2022("5386").Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.NewEngine(windowsRules()).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.PlatformSupport != "supported" || res.Platform.Codename != "windows_server_2022" || res.Platform.WindowsBuild != "20348.5386" {
		t.Fatalf("platform %+v support=%s reason=%s", res.Platform, res.PlatformSupport, res.SupportReason)
	}
	if res.RuleCoverage.State != resolver.CoverageCovered || res.RuleCoverage.AssetRelease != "windows/windows_server_2022" || res.RuleCoverage.RulesForAsset != 4 {
		t.Fatalf("coverage %+v", res.RuleCoverage)
	}
	states := map[string]string{}
	for _, f := range res.Findings {
		states[f.CVEID] = f.State
		if f.BinaryPackage != "windows" || f.DetectionMethod != resolver.MethodMSRCFixedBuild || f.InstalledVersion != "20348.5386" {
			t.Fatalf("finding shape %+v", f)
		}
	}
	if states["CVE-2026-100201"] != findings.StateVulnerable || states["CVE-2026-100202"] != findings.StateVulnerable {
		t.Fatalf("expected vulnerable: %v", states)
	}
	if states["CVE-2026-000001"] != findings.StateFixed {
		t.Fatalf("5386 >= 5386 must be fixed: %v", states)
	}
	if _, seen := states["CVE-2026-000002"]; seen {
		t.Fatalf("other build rule must be rejected, not decided: %v", states)
	}
	if _, seen := states["CVE-2026-100200"]; seen {
		t.Fatalf("other product rule must not apply: %v", states)
	}
	if res.Metrics.RulesRejected < 1 {
		t.Fatalf("rejected %d", res.Metrics.RulesRejected)
	}

	var card *findings.RemediationGroup
	for i := range res.RemediationGroups {
		if res.RemediationGroups[i].Action == findings.ActionInstallUpdate {
			card = &res.RemediationGroups[i]
		}
	}
	if card == nil {
		t.Fatalf("install_update card missing: %+v", res.RemediationGroups)
	}
	if *card.Closes.Count != 2 || len(card.Closes.CVEIDs) != 2 || card.AdvisoryIDs[0] != "KB5126655" {
		t.Fatalf("card closes %+v advisories %v", card.Closes, card.AdvisoryIDs)
	}
	if !card.RequiresReboot || card.Targets[0].TargetVersion != "20348.5761" || card.Targets[0].Kind != findings.TargetKindOSBuild || card.CommandHint != "" {
		t.Fatalf("card %+v", card)
	}
	if !res.Reconciliation.RemediationBalanced {
		t.Fatalf("reconciliation must balance: %+v", res.Reconciliation)
	}
}

func TestWindowsPatchedHostHasNoCard(t *testing.T) {
	lr, _ := tf.NewWindowsServer2022("5761").Load()
	res, err := resolver.NewEngine(windowsRules()).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.State == findings.StateVulnerable {
			t.Fatalf("fully patched host must have no vulnerable finding: %+v", f)
		}
	}
	for _, g := range res.RemediationGroups {
		if g.Action == findings.ActionInstallUpdate {
			t.Fatal("no install_update card expected")
		}
	}
}

func TestWindowsNoRulesIsCoverageGapNotClean(t *testing.T) {
	lr, _ := tf.NewWindowsServer2022("5000").Load()
	res, err := resolver.NewEngine(&rules.RuleSet{}).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.RuleCoverage.State != resolver.CoverageMissing {
		t.Fatalf("coverage %+v", res.RuleCoverage)
	}
	found := false
	for _, u := range res.Unknowns {
		if u.Kind == "rule_coverage" && u.Subject == "windows/windows_server_2022" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknowns %+v", res.Unknowns)
	}
}

func TestWindowsUnmappedBuildIsNotSupported(t *testing.T) {
	d := tf.NewWindowsServer2022("1")
	d.SetOS(map[string]any{"build_number": "99999", "os_build": "99999.1"})
	lr, _ := d.Load()
	res, err := resolver.NewEngine(windowsRules()).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.PlatformSupport != "not_supported" || res.SupportReason == "" {
		t.Fatalf("support=%s reason=%q", res.PlatformSupport, res.SupportReason)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("no findings expected for unmapped build: %d", len(res.Findings))
	}
}

func TestWindowsBadUBRIsNotSupportedNotClean(t *testing.T) {
	d := tf.NewWindowsServer2022("1")
	d.SetOS(map[string]any{"ubr": "-5", "os_build": ""})
	lr, _ := d.Load()
	res, err := resolver.NewEngine(windowsRules()).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.PlatformSupport == "supported" {
		t.Fatalf("garbage UBR must not look supported: reason=%q findings=%d", res.SupportReason, len(res.Findings))
	}
}

func TestListsNeverNullInJSON(t *testing.T) {
	lr, _ := tf.NewWindowsServer2022("5761").Load()
	res, err := resolver.NewEngine(windowsRules()).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "remediation_groups", "software_inventory", "unknowns", "notes", "evidence_errors"} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s must be a JSON array, got %T", k, m[k])
		}
	}
}

// A hotpatch host is fixed by the hotpatch build for CVEs that have a hotpatch
// fix, still needs the regular (reboot) update for CVEs that have none, and
// a host on any other UBR is judged by the regular update alone.
func TestWindowsHotpatchStream(t *testing.T) {
	hot := tf.MSRCRule("CVE-2026-200001", "windows_server_2022", "", "KB5200001", "20348.5440", false)
	hot.RuleID += ":hotpatch"
	hot.RawStatus = "Security Hotpatch Update"
	rs := &rules.RuleSet{Rules: []rules.PackageVulnerabilityRule{
		hot,
		tf.MSRCRule("CVE-2026-200001", "windows_server_2022", "", "KB5200002", "20348.5499", true),
		tf.MSRCRule("CVE-2026-200002", "windows_server_2022", "", "KB5200002", "20348.5499", true),
	}}
	rs.Reindex()
	cases := []struct {
		ubr  string
		want map[string]string
	}{
		{"5440", map[string]string{"CVE-2026-200001": findings.StateFixed, "CVE-2026-200002": findings.StateVulnerable}},
		{"5441", map[string]string{"CVE-2026-200001": findings.StateVulnerable, "CVE-2026-200002": findings.StateVulnerable}},
		{"5499", map[string]string{"CVE-2026-200001": findings.StateFixed, "CVE-2026-200002": findings.StateFixed}},
	}
	for _, tc := range cases {
		lr, _ := tf.NewWindowsServer2022(tc.ubr).Load()
		res, err := resolver.NewEngine(rs).Resolve(lr)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, f := range res.Findings {
			got[f.CVEID] = f.State
		}
		for cve, state := range tc.want {
			if got[cve] != state {
				t.Errorf("UBR %s %s: state %q, want %q", tc.ubr, cve, got[cve], state)
			}
		}
	}
}

// Client products come per architecture with the same fixed build; an x64
// host must never lose a CVE because the 32-bit rule was evaluated.
func TestWindowsArchitectureVariantsDoNotHideCVE(t *testing.T) {
	rs := &rules.RuleSet{Rules: []rules.PackageVulnerabilityRule{
		tf.MSRCRule("CVE-2026-300001", "windows_10_22h2", "386", "KB1", "19045.7000", false),
		tf.MSRCRule("CVE-2026-300001", "windows_10_22h2", "amd64", "KB1", "19045.7000", false),
		tf.MSRCRule("CVE-2026-300001", "windows_10_22h2", "arm64", "KB1", "19045.7000", false),
	}}
	for i := range rs.Rules {
		rs.Rules[i].RuleID += ":" + rs.Rules[i].Architecture
	}
	rs.Reindex()
	for i := 0; i < 20; i++ {
		d := tf.NewWindowsServer2022("6000")
		d.SetOS(map[string]any{"product_name": "Microsoft Windows 10 Pro", "build_number": "19045", "os_build": "19045.6000", "product_type": 1, "installation_type": "Client"})
		lr, _ := d.Load()
		res, err := resolver.NewEngine(rs).Resolve(lr)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 || res.Findings[0].State != findings.StateVulnerable {
			t.Fatalf("run %d: want one vulnerable finding, got %+v", i, res.Findings)
		}
	}
}
