package resolver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"

	_ "github.com/s4e-io/openness-resolver/internal/version/dpkg"
)

func withHighestList(version, origin string) tf.PkgOpt {
	return func(v map[string]any) {
		v["highest_list_version"] = version
		v["highest_list_origin"] = map[string]any{
			"origin": origin,
			"esm":    strings.Contains(strings.ToLower(origin), "esm"),
		}
	}
}

func withRuntimeStale() tf.PkgOpt {
	return func(v map[string]any) { v["runtime_stale"] = true }
}

func TestRemediationGroupsOneSourcePackage(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.20", "Ubuntu")).
		AddPackage("openssl", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.15", "Ubuntu"))
	lib := tf.UbuntuRule("CVE-A", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.18")
	lib.AdvisoryIDs = []string{"USN-1000-1"}
	bin := tf.UbuntuRule("CVE-B", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	bin.AdvisoryIDs = []string{"USN-1001-1"}
	// A second, older fix for libssl3 must not lower the target.
	older := tf.UbuntuRule("CVE-C", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	res := resolve(t, doc, lib, bin, older)

	if !res.Reconciliation.RemediationBalanced {
		t.Fatalf("remediation invariant failed: %+v", res.Reconciliation)
	}
	var card *findings.RemediationGroup
	for i := range res.RemediationGroups {
		if res.RemediationGroups[i].Action == findings.ActionUpgradePackages {
			card = &res.RemediationGroups[i]
		}
	}
	if card == nil {
		t.Fatal("missing upgrade card")
	}
	if card.SourcePackage != "openssl" {
		t.Fatalf("source=%s", card.SourcePackage)
	}
	if card.Closes.Count == nil || *card.Closes.Count != 3 || *card.Closes.Count != len(card.Closes.FindingIDs) {
		t.Fatalf("closes=%+v", card.Closes)
	}
	if card.Availability != findings.AvailabilityNotYetInRepo {
		t.Fatalf("availability=%s, openssl candidate is below its fix", card.Availability)
	}
	byName := map[string]string{}
	for _, target := range card.Targets {
		byName[target.Name] = target.TargetVersion
	}
	if byName["libssl3"] != "3.0.2-0ubuntu1.18" || byName["openssl"] != "3.0.2-0ubuntu1.16" {
		t.Fatalf("targets=%v", byName)
	}
	if strings.Join(card.AdvisoryIDs, ",") != "USN-1000-1,USN-1001-1" {
		t.Fatalf("advisories=%v", card.AdvisoryIDs)
	}
	if card.CommandHint != "apt-get install --only-upgrade libssl3 openssl" {
		t.Fatalf("hint=%q", card.CommandHint)
	}
}

func TestRemediationAvailabilityAndEntitlement(t *testing.T) {
	t.Run("no candidate", func(t *testing.T) {
		doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
		res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
		card := mustUpgrade(t, res)
		if card.Availability != findings.AvailabilityUnknown || card.Action != findings.ActionUpgradePackages {
			t.Fatalf("action=%s availability=%s", card.Action, card.Availability)
		}
	})
	t.Run("candidate covers the fix", func(t *testing.T) {
		doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.16", "Ubuntu"))
		res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
		card := mustUpgrade(t, res)
		if card.Availability != findings.AvailabilityAvailable {
			t.Fatalf("availability=%s", card.Availability)
		}
	})
	t.Run("esm candidate without pro", func(t *testing.T) {
		doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.16", "UbuntuESMApps"))
		res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
		card := mustAction(t, res, findings.ActionRequiresEntitlement)
		if card.RequiresEntitlement == nil || *card.RequiresEntitlement != "ubuntu_pro" {
			t.Fatalf("entitlement=%v", card.RequiresEntitlement)
		}
		if !strings.Contains(card.CommandHint, "requires Ubuntu Pro") {
			t.Fatalf("hint=%q", card.CommandHint)
		}
	})
	t.Run("esm pocket rule without pro", func(t *testing.T) {
		doc := tf.NewUbuntuJammyARM64().AddPackage("libjs-jquery-ui", "1.13.1+dfsg-1", tf.WithSource("jqueryui"))
		rule := tf.UbuntuRule("CVE-2", "jammy", "jqueryui", "libjs-jquery-ui", rules.StatusReleased, "1.13.1+dfsg-1ubuntu0.1~esm1")
		rule.SupportTier = "esm-apps"
		res := resolve(t, doc, rule)
		card := mustAction(t, res, findings.ActionRequiresEntitlement)
		if card.Availability != findings.AvailabilityUnknown {
			t.Fatalf("availability=%s", card.Availability)
		}
	})
	t.Run("pro already on the host", func(t *testing.T) {
		doc := tf.NewUbuntuJammyARM64().
			AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.16", "UbuntuESMApps")).
			AddPackage("esm-pkg", "1.0", tf.WithSource("esm-pkg"), tf.WithRepo("UbuntuESMApps", "jammy-apps-security", "main", "https://esm.ubuntu.com/apps/ubuntu", "matched_apt_lists"))
		res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
		card := mustUpgrade(t, res)
		if card.Action != findings.ActionUpgradePackages || card.RequiresEntitlement != nil {
			t.Fatalf("action=%s entitlement=%v", card.Action, card.RequiresEntitlement)
		}
	})
}

func TestRemediationRestartAndRebootDoNotStealFindings(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("cups-daemon", "2.4.1op1-1ubuntu4.11", tf.WithSource("cups")).
		AddProcess(2948, "cupsd", "/usr/sbin/cupsd", true).
		AddService(2948, "cups.service").
		AddChain(2948, "/usr/sbin/cupsd", "cups-daemon", "cups").
		SetKernel(map[string]any{"running_kernel": "6.8.0-106-generic", "reboot_required": true})
	res := resolve(t, doc, tf.UbuntuRule("CVE-4", "jammy", "cups", "cups-daemon", rules.StatusReleased, "2.4.1op1-1ubuntu4.11"))
	if !res.Reconciliation.RemediationBalanced {
		t.Fatalf("invariant: %+v", res.Reconciliation)
	}
	if res.Reconciliation.RemediationCloses != 0 {
		t.Fatalf("vulnerable_runtime must not be counted as a vulnerable close, closes=%d", res.Reconciliation.RemediationCloses)
	}
	restart := mustAction(t, res, findings.ActionRestartService)
	if restart.Closes.Count == nil || *restart.Closes.Count != 0 {
		t.Fatalf("restart closes=%+v", restart.Closes)
	}
	if len(restart.Targets) != 1 || restart.Targets[0].Name != "cups.service" {
		t.Fatalf("restart targets=%+v", restart.Targets)
	}
	if restart.CommandHint != "systemctl restart cups.service" {
		t.Fatalf("hint=%q", restart.CommandHint)
	}
	reboot := mustAction(t, res, findings.ActionReboot)
	if !reboot.RequiresReboot || *reboot.Closes.Count != 0 || reboot.CommandHint != "reboot" {
		t.Fatalf("reboot=%+v", reboot)
	}
}

func TestRemediationRunningServiceStaysOnUpgradeCard(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("cups-daemon", "2.4.1op1-1ubuntu4.10", tf.WithSource("cups"), withRuntimeStale()).
		AddProcess(2948, "cupsd", "/usr/sbin/cupsd", false).
		AddService(2948, "cups.service").
		AddChain(2948, "/usr/sbin/cupsd", "cups-daemon", "cups")
	res := resolve(t, doc, tf.UbuntuRule("CVE-4", "jammy", "cups", "cups-daemon", rules.StatusReleased, "2.4.1op1-1ubuntu4.11"))
	card := mustUpgrade(t, res)
	if len(card.RequiresServiceRestart) != 1 || card.RequiresServiceRestart[0] != "cups.service" {
		t.Fatalf("restart=%v", card.RequiresServiceRestart)
	}
	if *card.Closes.Count != 1 {
		t.Fatalf("closes=%+v", card.Closes)
	}
	for _, g := range res.RemediationGroups {
		if g.Action == findings.ActionRestartService {
			t.Fatal("running vulnerable package produced a second restart card")
		}
	}
}

func TestRemediationDeterministic(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), withHighestList("3.0.2-0ubuntu1.20", "Ubuntu")).
		AddPackage("openssl", "3.0.2-0ubuntu1.15", tf.WithSource("openssl")).
		SetKernel(map[string]any{"reboot_required": true})
	rule := tf.UbuntuRule("CVE-A", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.18")
	rule.AdvisoryIDs = []string{"USN-1"}
	other := tf.UbuntuRule("CVE-B", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	a := resolve(t, doc, rule, other)
	b := resolve(t, doc, rule, other)
	aj, _ := json.Marshal(a.RemediationGroups)
	bj, _ := json.Marshal(b.RemediationGroups)
	if string(aj) != string(bj) {
		t.Fatalf("groups differ\n%s\n%s", aj, bj)
	}
	af, _ := json.Marshal(a.Findings)
	bf, _ := json.Marshal(b.Findings)
	if string(af) != string(bf) {
		t.Fatal("findings differ across runs")
	}
	if a.GeneratedAt == b.GeneratedAt && a.OutputSchemaVersion != findings.OutputSchemaVersion {
		t.Fatal("schema version missing")
	}
	if a.OutputSchemaVersion != findings.OutputSchemaVersion {
		t.Fatalf("schema=%s", a.OutputSchemaVersion)
	}
}

func TestKernelCardDoesNotInstallAnImageAlreadyOnDisk(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		SetKernel(map[string]any{"running_kernel": "6.8.0-100-generic", "reboot_required": false}).
		AddPackage("linux-modules-6.8.0-100-generic", "6.8.0-100.100~22.04.1", tf.WithSource("linux-hwe-6.8")).
		AddPackage("linux-image-6.8.0-100-generic", "6.8.0-100.100~22.04.1", tf.WithSource("linux-signed-hwe-6.8")).
		AddPackage("linux-image-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-signed-hwe-6.8"))
	res := resolve(t, doc, tf.UbuntuKernelRule("CVE-K2", "jammy", "linux-hwe-6.8", "released", "6.8.0-104.104~22.04.1"))
	card := mustUpgrade(t, res)
	if !card.RequiresReboot {
		t.Fatal("running kernel card must require reboot")
	}
	if card.CommandHint != "reboot" {
		t.Fatalf("hint=%q", card.CommandHint)
	}
	if !kernelFinding(t, res).FixedImageInstalled {
		t.Fatal("fixed image on disk must set fixed_image_installed")
	}
	if strings.Contains(card.CommandHint, "apt-get") {
		t.Fatalf("hint tells the operator to install an image that is already on disk: %q", card.CommandHint)
	}
}

func TestKernelCardInstallsWhenTheFixedImageIsAbsent(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("linux-modules-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-hwe-6.8")).
		AddPackage("linux-image-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-signed-hwe-6.8"))
	res := resolve(t, doc, tf.UbuntuKernelRule("CVE-K1", "jammy", "linux-hwe-6.8", "released", "6.8.0-110.110~22.04.1"))
	card := mustUpgrade(t, res)
	if !card.RequiresReboot {
		t.Fatal("running kernel card must require reboot")
	}
	const want = "apt-get install linux-image-6.8.0-110-generic"
	if card.CommandHint != want {
		t.Fatalf("hint=%q", card.CommandHint)
	}
	if strings.Contains(card.CommandHint, "--only-upgrade") {
		t.Fatalf("hint upgrades the running ABI package: %q", card.CommandHint)
	}
	if kernelFinding(t, res).FixedImageInstalled {
		t.Fatal("absent image must not set fixed_image_installed")
	}
	if len(card.Targets) != 1 || card.Targets[0].Architecture == "" {
		t.Fatalf("kernel target=%+v", card.Targets)
	}
}

func TestRemediationTargetsKeepArchitecture(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), tf.WithArch("arm64"), withHighestList("3.0.2-0ubuntu1.20", "Ubuntu")).
		AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"), tf.WithArch("amd64"), func(v map[string]any) { v["entity_id"] = "pkg:dpkg:libssl3:amd64" }, withHighestList("3.0.2-0ubuntu1.20", "Ubuntu"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-A", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.18"))
	card := mustUpgrade(t, res)
	got := map[string]bool{}
	for _, tg := range card.Targets {
		if tg.Name != "libssl3" {
			t.Fatalf("name=%q", tg.Name)
		}
		got[tg.Architecture] = true
	}
	if len(card.Targets) != 2 || !got["arm64"] || !got["amd64"] {
		t.Fatalf("targets=%+v", card.Targets)
	}
}

func kernelFinding(t *testing.T, res *RunResult) findings.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.DetectionMethod == MethodUbuntuRunningKernel && f.State == findings.StateVulnerable {
			return f
		}
	}
	t.Fatal("no running-kernel finding")
	return findings.Finding{}
}

func mustUpgrade(t *testing.T, res *RunResult) *findings.RemediationGroup {
	t.Helper()
	return mustAction(t, res, findings.ActionUpgradePackages)
}

func mustAction(t *testing.T, res *RunResult, action string) *findings.RemediationGroup {
	t.Helper()
	for i := range res.RemediationGroups {
		if res.RemediationGroups[i].Action == action && res.RemediationGroups[i].SourcePackage != "esm-pkg" {
			return &res.RemediationGroups[i]
		}
	}
	t.Fatalf("no %s card in %d groups", action, len(res.RemediationGroups))
	return nil
}

func TestSanitizeHintTokens(t *testing.T) {
	got, notes := sanitizeHintTokens([]string{"openssl", "x;rm", "libssl3", "a && b"})
	if len(got) != 2 || got[0] != "openssl" || got[1] != "libssl3" {
		t.Fatalf("safe=%v", got)
	}
	if len(notes) != 2 {
		t.Fatalf("notes=%v", notes)
	}
	hint, hintNotes := upgradeHint(findings.ActionUpgradePackages, "ubuntu", "jammy", []string{"evil;id"})
	if hint != "" || len(hintNotes) != 1 {
		t.Fatalf("hint=%q notes=%v", hint, hintNotes)
	}
	note := hintCoverage(nil, hintNotes)
	if note == nil || *note != "hint_tokens_omitted" {
		t.Fatalf("coverage=%v", note)
	}
}
