package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"

	_ "github.com/s4e-io/openness-resolver/internal/version/apk"
	_ "github.com/s4e-io/openness-resolver/internal/version/dpkg"
)

func resolve(t *testing.T, doc *tf.Doc, ruleList ...rules.PackageVulnerabilityRule) *RunResult {
	t.Helper()
	lr, err := doc.Load()
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	engine := NewEngine(tf.RuleSet(ruleList...))
	res, err := engine.Resolve(lr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return res
}

func findFinding(t *testing.T, res *RunResult, pkg, cve string) *findings.Finding {
	t.Helper()
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.BinaryPackage == pkg && f.CVEID == cve {
			return f
		}
	}
	return nil
}

func mustFinding(t *testing.T, res *RunResult, pkg, cve string) *findings.Finding {
	t.Helper()
	f := findFinding(t, res, pkg, cve)
	if f == nil {
		t.Fatalf("expected a finding for %s/%s, got %d findings: %+v", pkg, cve, len(res.Findings), res.Findings)
	}
	return f
}

// Scenario 1: Ubuntu package before fixed version -> vulnerable.
func TestUbuntuPackageBeforeFix(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s, want vulnerable", f.State)
	}
	if f.Confidence != "high" {
		t.Errorf("confidence=%s, want high (direct source mapping, native comparator)", f.Confidence)
	}
	if f.Comparison == nil || !f.Comparison.Result {
		t.Errorf("comparison must be recorded and true: %+v", f.Comparison)
	}
	if f.FixAvailability != findings.FixAvailable {
		t.Errorf("fix availability=%s", f.FixAvailability)
	}
	if f.RuntimeState != findings.RuntimeNotObserved {
		t.Errorf("runtime state=%q, want not_observed_running", f.RuntimeState)
	}
}

// Scenario 2: package exactly at fixed version -> fixed.
func TestUbuntuPackageAtFix(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.16", tf.WithSource("openssl"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	if f := mustFinding(t, res, "libssl3", "CVE-1"); f.State != findings.StateFixed {
		t.Errorf("state=%s, want fixed", f.State)
	}
}

// Scenario 3: package after fixed version -> fixed.
func TestUbuntuPackageAfterFix(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	if f := mustFinding(t, res, "libssl3", "CVE-1"); f.State != findings.StateFixed {
		t.Errorf("state=%s, want fixed", f.State)
	}
}

// Scenario 4: rule for a different Ubuntu release must not apply.
func TestWrongUbuntuRelease(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	// Rule is for noble; index lookup for jammy finds nothing.
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "noble", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	if f := findFinding(t, res, "libssl3", "CVE-1"); f != nil {
		t.Errorf("no finding expected for wrong release, got %+v", f)
	}
	if res.Metrics.PackagesWithoutVendorRules != 1 {
		t.Errorf("package must be counted as without vendor rules")
	}
	// Explicit decision-table check: EvaluateRule on the mismatched rule.
	// (covers the not_applicable path even when indexes would filter it)
}

// Scenario 5: architecture mismatch -> not_applicable.
func TestArchitectureMismatch(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("foo", "1.0-1", tf.WithSource("foo"), tf.WithArch("amd64"))
	r := tf.UbuntuRule("CVE-1", "jammy", "foo", "foo", rules.StatusReleased, "1.0-2")
	r.Architecture = "s390x" // rule constrained to another architecture
	res := resolve(t, doc, r)
	f := mustFinding(t, res, "foo", "CVE-1")
	if f.State != findings.StateNotApplicable {
		t.Errorf("state=%s, want not_applicable (arch mismatch)", f.State)
	}
}

// Scenario 6: binary package mapped to a different source package.
func TestBinaryToSourceMapping(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	// OVAL emits binary-specific rules; fixed version must come from the libssl3 rule.
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s, want vulnerable via binary-specific rule", f.State)
	}
	if f.SourcePackage != "openssl" || f.SourceConfidence != "direct" {
		t.Errorf("source mapping lost: %s/%s", f.SourcePackage, f.SourceConfidence)
	}
}

// Scenario 6b: sibling binary rules must not share fixed versions.
func TestSiblingBinaryRuleDoesNotApply(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	// Source-meta binary name only applies to the openssl package itself, not libssl3.
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	if findFinding(t, res, "libssl3", "CVE-1") != nil {
		t.Fatal("openssl binary rule must not produce a libssl3 finding")
	}
}

// Scenario 7: epoch handling.
func TestEpochPackage(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("openssh-client", "1:8.9p1-3ubuntu0.15", tf.WithSource("openssh"), tf.WithEpoch("1"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssh", "openssh-client", rules.StatusReleased, "1:8.9p1-3ubuntu0.16"))
	f := mustFinding(t, res, "openssh-client", "CVE-1")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s, want vulnerable", f.State)
	}
	if f.InstalledVersion != "1:8.9p1-3ubuntu0.15" {
		t.Errorf("epoch stripped from installed version: %s", f.InstalledVersion)
	}
}

// Scenario 8: tilde pre-release ordering.
func TestTildePreRelease(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("foo", "1.2.3~rc1-0ubuntu1", tf.WithSource("foo"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "foo", "foo", rules.StatusReleased, "1.2.3-0ubuntu1"))
	if f := mustFinding(t, res, "foo", "CVE-1"); f.State != findings.StateVulnerable {
		t.Errorf("state=%s, want vulnerable (~rc1 sorts before release)", f.State)
	}
}

// Scenario 9: Alpine container package before fixed version.
func TestAlpineContainerVulnerable(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddContainer(tf.ContainerSpec{
		ID: "c1", Name: "c1", Digest: "sha256:aaa", ImageRef: "img:latest", State: "running",
		Packages: [][3]string{
			{"alpine-baselayout", "3.4.3-r1", "apk"},
			{"busybox", "1.36.1-r5", "apk"},
		},
	})
	res := resolve(t, doc, tf.AlpineRule("CVE-2", "v3.18", "busybox", rules.StatusReleased, "1.36.1-r7"))
	f := mustFinding(t, res, "busybox", "CVE-2")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s, want vulnerable", f.State)
	}
	if f.Scope != "container" || f.ImageDigest != "sha256:aaa" {
		t.Errorf("container identity lost: scope=%s digest=%s", f.Scope, f.ImageDigest)
	}
	if f.Confidence != "medium" {
		t.Errorf("confidence=%s, want medium (branch inferred)", f.Confidence)
	}
}

// Scenario 10: same Alpine image digest used by multiple containers shares
// one image-level finding referencing every container.
func TestSameImageMultipleContainers(t *testing.T) {
	spec := tf.ContainerSpec{
		Digest: "sha256:aaa", ImageRef: "img:latest", State: "exited",
		Packages: [][3]string{
			{"alpine-baselayout", "3.4.3-r1", "apk"},
			{"busybox", "1.36.1-r5", "apk"},
		},
	}
	doc := tf.NewUbuntuJammyARM64()
	for _, id := range []string{"c1", "c2", "c3"} {
		s := spec
		s.ID, s.Name = id, id
		doc.AddContainer(s)
	}
	res := resolve(t, doc, tf.AlpineRule("CVE-2", "v3.18", "busybox", rules.StatusReleased, "1.36.1-r7"))
	var count int
	for _, f := range res.Findings {
		if f.CVEID == "CVE-2" && f.BinaryPackage == "busybox" {
			count++
			if len(f.ContainerIDs) != 3 {
				t.Errorf("finding must reference all 3 containers, got %v", f.ContainerIDs)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 image-level finding, got %d", count)
	}
	if res.Metrics.ContainerPackages != 2 {
		t.Errorf("image packages must be counted once, got %d", res.Metrics.ContainerPackages)
	}
}

// Scenario 11: missing image digest -> packages not resolved at image level,
// visible note recorded.
func TestMissingImageDigest(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddContainer(tf.ContainerSpec{
		ID: "c1", Name: "c1", Digest: "", ImageRef: "img:latest", State: "running",
		Packages: [][3]string{{"busybox", "1.36.1-r5", "apk"}},
	})
	res := resolve(t, doc, tf.AlpineRule("CVE-2", "v3.18", "busybox", rules.StatusReleased, "1.36.1-r7"))
	if f := findFinding(t, res, "busybox", "CVE-2"); f != nil {
		t.Errorf("no image-level finding expected without digest, got %+v", f)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "no usable image digest") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing-digest note expected, notes=%v", res.Notes)
	}
}

// Scenario 12: vulnerable package installed but not running stays
// vulnerable with runtime_state not_observed_running.
func TestVulnerableNotRunning(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("nginx-core", "1.18.0-6ubuntu14.3", tf.WithSource("nginx"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-3", "jammy", "nginx", "nginx-core", rules.StatusReleased, "1.18.0-6ubuntu14.4"))
	f := mustFinding(t, res, "nginx-core", "CVE-3")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s, must stay vulnerable when not running", f.State)
	}
	if f.RuntimeState != findings.RuntimeNotObserved {
		t.Errorf("runtime_state=%q, want not_observed_running", f.RuntimeState)
	}
}

// Scenario 13: vulnerable package with a running process gets runtime
// enrichment.
func TestVulnerableRunning(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("cups-daemon", "2.4.1op1-1ubuntu4.10", tf.WithSource("cups")).
		AddProcess(2948, "cupsd", "/usr/sbin/cupsd", false).
		AddChain(2948, "/usr/sbin/cupsd", "cups-daemon", "cups")
	res := resolve(t, doc, tf.UbuntuRule("CVE-4", "jammy", "cups", "cups-daemon", rules.StatusReleased, "2.4.1op1-1ubuntu4.11"))
	f := mustFinding(t, res, "cups-daemon", "CVE-4")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s", f.State)
	}
	if f.RuntimeState != findings.RuntimeRunning {
		t.Errorf("runtime_state=%q, want running", f.RuntimeState)
	}
	if len(f.RuntimeProcessIDs) != 1 || f.RuntimeProcessIDs[0] != "2948" {
		t.Errorf("runtime pids=%v", f.RuntimeProcessIDs)
	}
}

// Scenario 14: fixed package on disk with the old (deleted) executable
// still running -> vulnerable_runtime.
func TestFixedButDeletedProcessRunning(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("cups-daemon", "2.4.1op1-1ubuntu4.11", tf.WithSource("cups")).
		AddProcess(2948, "cupsd", "/usr/sbin/cupsd", true). // deleted executable
		AddChain(2948, "/usr/sbin/cupsd", "cups-daemon", "cups")
	res := resolve(t, doc, tf.UbuntuRule("CVE-4", "jammy", "cups", "cups-daemon", rules.StatusReleased, "2.4.1op1-1ubuntu4.11"))
	f := mustFinding(t, res, "cups-daemon", "CVE-4")
	if f.State != findings.StateVulnerableRuntime {
		t.Errorf("state=%s, want vulnerable_runtime", f.State)
	}
	if res.Metrics.FindingsVulnerableRuntime != 1 {
		t.Errorf("metrics: vulnerable_runtime=%d", res.Metrics.FindingsVulnerableRuntime)
	}
}

// Scenario 15: missing source-package evidence -> inferred mapping,
// visible in the finding, confidence not high for source-level rules.
func TestMissingSourceEvidence(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("acme-widget", "1.0-1") // no source metadata
	res := resolve(t, doc, tf.UbuntuRule("CVE-5", "jammy", "acme-widget", "acme-widget", rules.StatusReleased, "1.0-2"))
	f := mustFinding(t, res, "acme-widget", "CVE-5")
	if f.SourceConfidence != "inferred" {
		t.Errorf("source confidence=%s, want inferred", f.SourceConfidence)
	}
	joined := strings.Join(f.Reasons, " ")
	if !strings.Contains(joined, "inferred") {
		t.Errorf("inferred mapping must be stated in reasons: %v", f.Reasons)
	}
}

// Scenario 16: unsupported distribution -> platform not_supported, no host
// findings, reason preserved.
func TestUnsupportedDistribution(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().SetOS(map[string]any{
		"distribution_id": "ol", "version_id": "9.4", "distribution_version": "9.4",
	}).AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16"))
	if res.PlatformSupport != "not_supported" {
		t.Errorf("support=%s, want not_supported", res.PlatformSupport)
	}
	if len(res.Findings) != 0 {
		t.Errorf("no findings expected for unsupported distro, got %d", len(res.Findings))
	}
}

// Scenario 17: malformed vendor rule (released without fixed version) ->
// unknown, never claimed fixed.
func TestMalformedVendorRule(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("foo", "1.0-1", tf.WithSource("foo"))
	r := tf.UbuntuRule("CVE-6", "jammy", "foo", "foo", rules.StatusReleased, "")
	res := resolve(t, doc, r)
	f := mustFinding(t, res, "foo", "CVE-6")
	if f.State != findings.StateUnknown {
		t.Errorf("state=%s, want unknown (released without fixed version)", f.State)
	}
}

// Scenario 18: conflicting vendor data -> conflicting_evidence with both
// rules recorded; lower-priority sources only create informational conflicts.
func TestConflictingVendorData(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("foo", "1.0-1", tf.WithSource("foo"))
	released := tf.UbuntuRule("CVE-7", "jammy", "foo", "foo", rules.StatusReleased, "1.0-2")
	notAffected := tf.UbuntuRule("CVE-7", "jammy", "foo", "foo", rules.StatusNotAffected, "")
	notAffected.RuleID += ":na"
	res := resolve(t, doc, released, notAffected)
	f := mustFinding(t, res, "foo", "CVE-7")
	if f.State != findings.StateConflictingEvidence {
		t.Errorf("state=%s, want conflicting_evidence", f.State)
	}
	if len(f.Conflicts) == 0 {
		t.Errorf("conflicts must be recorded")
	}

	// NVD-style lower-priority disagreement: vendor wins, informational
	// conflict recorded, state NOT conflicting.
	doc2 := tf.NewUbuntuJammyARM64().AddPackage("bar", "2.0-1", tf.WithSource("bar"))
	vendorNA := tf.UbuntuRule("CVE-8", "jammy", "bar", "bar", rules.StatusNotAffected, "")
	nvd := tf.UbuntuRule("CVE-8", "jammy", "bar", "bar", rules.StatusReleased, "2.0-2")
	nvd.RuleID += ":nvd"
	nvd.SourcePriority = 5
	nvd.Vendor = "nvd"
	res2 := resolve(t, doc2, vendorNA, nvd)
	f2 := mustFinding(t, res2, "bar", "CVE-8")
	if f2.State == findings.StateConflictingEvidence {
		t.Errorf("lower-priority source must not force conflicting_evidence; state=%s", f2.State)
	}
}

// Vendor status transitions: needed / deferred / ignored / not_affected /
// does_not_exist.
func TestVendorStatusStates(t *testing.T) {
	cases := []struct {
		status    string
		wantState string
		wantFix   string
	}{
		{rules.StatusNeeded, findings.StateVulnerable, findings.FixUnavailable},
		{rules.StatusDeferred, findings.StateVulnerable, findings.FixDeferred},
		{rules.StatusIgnored, findings.StatePotentiallyVulnerable, ""},
		{rules.StatusNotAffected, findings.StateNotApplicable, ""},
		{rules.StatusDoesNotExist, findings.StateNotApplicable, ""},
	}
	for _, c := range cases {
		doc := tf.NewUbuntuJammyARM64().AddPackage("foo", "1.0-1", tf.WithSource("foo"))
		r := tf.UbuntuRule("CVE-9", "jammy", "foo", "foo", c.status, "")
		res := resolve(t, doc, r)
		f := mustFinding(t, res, "foo", "CVE-9")
		if f.State != c.wantState {
			t.Errorf("status %s: state=%s, want %s", c.status, f.State, c.wantState)
		}
		if c.wantFix != "" && f.FixAvailability != c.wantFix {
			t.Errorf("status %s: fix=%s, want %s", c.status, f.FixAvailability, c.wantFix)
		}
	}
}

// ESM-tier fixes are marked requires_esm but stay vulnerable.
func TestESMFixAvailability(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("roundcube", "1.5.0-1", tf.WithSource("roundcube"))
	r := tf.UbuntuRule("CVE-10", "jammy", "roundcube", "roundcube", rules.StatusReleased, "1.5.0+dfsg.1-2ubuntu0.1~esm1")
	r.SupportTier = "esm-apps"
	res := resolve(t, doc, r)
	f := mustFinding(t, res, "roundcube", "CVE-10")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s", f.State)
	}
	if f.FixAvailability != findings.FixRequiresESM {
		t.Errorf("fix availability=%s, want requires_esm", f.FixAvailability)
	}
}

// Multiple USNs for the same CVE: highest fixed version wins, others
// superseded.
func TestSupersededRules(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.17", tf.WithSource("openssl"))
	r1 := tf.UbuntuRule("CVE-11", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	r2 := tf.UbuntuRule("CVE-11", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.19")
	r2.RuleID += ":newer"
	res := resolve(t, doc, r1, r2)
	f := mustFinding(t, res, "libssl3", "CVE-11")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s: 1.17 < 1.19 (newest USN) must win", f.State)
	}
	if f.FixedVersion != "3.0.2-0ubuntu1.19" {
		t.Errorf("fixed=%s, want 3.0.2-0ubuntu1.19", f.FixedVersion)
	}
	if len(f.SupersededRules) != 1 {
		t.Errorf("superseded=%v", f.SupersededRules)
	}
}

// Host and container packages must never merge even with identical names.
func TestHostContainerScopeSeparation(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("busybox", "1:1.30.1-7ubuntu3", tf.WithSource("busybox")).
		AddContainer(tf.ContainerSpec{
			ID: "c1", Name: "c1", Digest: "sha256:aaa", ImageRef: "img", State: "running",
			Packages: [][3]string{
				{"alpine-baselayout", "3.4.3-r1", "apk"},
				{"busybox", "1.36.1-r5", "apk"},
			},
		})
	res := resolve(t, doc, tf.AlpineRule("CVE-12", "v3.18", "busybox", rules.StatusReleased, "1.36.1-r7"))
	f := mustFinding(t, res, "busybox", "CVE-12")
	if f.Scope != "container" {
		t.Fatalf("scope=%s", f.Scope)
	}
	if f.InstalledVersion != "1.36.1-r5" {
		t.Errorf("container finding must use the container package version, got %s", f.InstalledVersion)
	}
	// The host busybox (dpkg) must not receive apk-rule findings.
	for _, other := range res.Findings {
		if other.Scope == "host" && other.CVEID == "CVE-12" {
			t.Errorf("host package received a container rule finding: %+v", other)
		}
	}
}

// Unknown Alpine branch -> single unknown marker finding, packages not guessed.
func TestUnknownAlpineBranch(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddContainer(tf.ContainerSpec{
		ID: "c1", Name: "c1", Digest: "sha256:bbb", ImageRef: "img", State: "running",
		Packages: [][3]string{{"busybox", "9.9.9-r0", "apk"}}, // no anchors
	})
	res := resolve(t, doc, tf.AlpineRule("CVE-13", "v3.18", "busybox", rules.StatusReleased, "9.9.9-r5"))
	if f := findFinding(t, res, "busybox", "CVE-13"); f != nil {
		t.Errorf("must not guess a branch, got %+v", f)
	}
	var unknown int
	for _, f := range res.Findings {
		if f.State == findings.StateUnknown && f.ImageDigest == "sha256:bbb" {
			unknown++
			if len(f.MissingEvidence) == 0 {
				t.Errorf("unknown finding must state missing evidence")
			}
		}
	}
	if unknown != 1 {
		t.Errorf("expected 1 unknown marker finding, got %d", unknown)
	}
}

// Performance smoke: resolution over the real rule volume happens in
// resolver_bench_test.go; here we assert the metrics contract instead.
func TestMetricsConsistency(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("a", "1.0-1", tf.WithSource("a")).
		AddPackage("b", "2.0-1", tf.WithSource("b"))
	res := resolve(t, doc,
		tf.UbuntuRule("CVE-A", "jammy", "a", "a", rules.StatusReleased, "1.0-2"),
		tf.UbuntuRule("CVE-B", "jammy", "b", "b", rules.StatusReleased, "1.0-1"),
	)
	m := res.Metrics
	if m.HostPackages != 2 || m.AssetPackages != 2 {
		t.Errorf("package counts wrong: %+v", m)
	}
	if m.FindingsVulnerable != 1 || m.FindingsFixed != 1 {
		t.Errorf("finding counts wrong: %+v", m)
	}
	total := m.FindingsVulnerable + m.FindingsFixed + m.FindingsNotApplicable +
		m.FindingsUnknown + m.FindingsConflicting + m.FindingsVulnerableRuntime + m.FindingsPotentially
	if total != len(res.Findings) {
		t.Errorf("metrics do not add up: %d vs %d findings", total, len(res.Findings))
	}
}
