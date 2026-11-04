package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

// kernelDoc builds an Ubuntu jammy host running the 6.8 HWE kernel.
func kernelDoc() *tf.Doc {
	return tf.NewUbuntuJammyARM64().
		AddPackage("linux-modules-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-hwe-6.8")).
		AddPackage("linux-image-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-signed-hwe-6.8"))
}

// T06: running kernel older than the vendor fix -> vulnerable, and the
// kernel is running by definition.
func TestRunningKernelBeforeFix(t *testing.T) {
	res := resolve(t, kernelDoc(),
		tf.UbuntuKernelRule("CVE-K1", "jammy", "linux-hwe-6.8", "released", "6.8.0-110.110~22.04.1"))
	f := mustFinding(t, res, "linux-image-6.8.0-106-generic", "CVE-K1")
	if f.State != findings.StateVulnerable {
		t.Errorf("state=%s", f.State)
	}
	if f.DetectionMethod != MethodUbuntuRunningKernel {
		t.Errorf("method=%s", f.DetectionMethod)
	}
	if f.RuntimeState != findings.RuntimeRunning {
		t.Errorf("running kernel must be runtime running: %q", f.RuntimeState)
	}
	if f.Comparison == nil || f.Comparison.Comparator != "dpkg" {
		t.Errorf("comparison missing: %+v", f.Comparison)
	}
}

// T06: running kernel at/after the fix -> fixed.
func TestRunningKernelAtFix(t *testing.T) {
	res := resolve(t, kernelDoc(),
		tf.UbuntuKernelRule("CVE-K1", "jammy", "linux-hwe-6.8", "released", "6.8.0-106.106~22.04.1"))
	f := mustFinding(t, res, "linux-image-6.8.0-106-generic", "CVE-K1")
	if f.State != findings.StateFixed {
		t.Errorf("state=%s", f.State)
	}
}

// T07: a fixed kernel image is installed but the vulnerable kernel is still
// running -> stays vulnerable with an explicit reboot reason.
func TestFixedKernelInstalledButOldRunning(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		SetKernel(map[string]any{"running_kernel": "6.8.0-100-generic", "reboot_required": true}).
		AddPackage("linux-modules-6.8.0-100-generic", "6.8.0-100.100~22.04.1", tf.WithSource("linux-hwe-6.8")).
		AddPackage("linux-image-6.8.0-100-generic", "6.8.0-100.100~22.04.1", tf.WithSource("linux-signed-hwe-6.8")).
		AddPackage("linux-image-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-signed-hwe-6.8"))
	res := resolve(t, doc,
		tf.UbuntuKernelRule("CVE-K2", "jammy", "linux-hwe-6.8", "released", "6.8.0-104.104~22.04.1"))
	f := mustFinding(t, res, "linux-image-6.8.0-100-generic", "CVE-K2")
	if f.State != findings.StateVulnerable {
		t.Fatalf("must stay vulnerable until reboot, got %s", f.State)
	}
	joined := strings.Join(f.Reasons, " | ")
	if !strings.Contains(joined, "installed but not running") {
		t.Errorf("reboot remediation reason missing: %v", f.Reasons)
	}
	if !strings.Contains(joined, "reboot-required marker") {
		t.Errorf("T09 reboot marker reason missing: %v", f.Reasons)
	}
}

// Flavour separation: advisories for a different kernel family never apply.
func TestKernelFlavourMismatch(t *testing.T) {
	res := resolve(t, kernelDoc(),
		tf.UbuntuKernelRule("CVE-K3", "jammy", "linux-aws", "released", "6.8.0-1030.32"))
	if f := findFinding(t, res, "linux-image-6.8.0-106-generic", "CVE-K3"); f != nil {
		t.Errorf("linux-aws rule must not apply to a linux-hwe-6.8 kernel: %+v", f)
	}
}

// Kernel rules must never be applied to installed kernel packages through
// the generic package path (an old kernel on disk is not running).
func TestKernelRuleNotAppliedToInstalledPackages(t *testing.T) {
	doc := kernelDoc().
		AddPackage("linux-modules-6.5.0-41-generic", "6.5.0-41.41~22.04.2", tf.WithSource("linux-hwe-6.5"))
	res := resolve(t, doc,
		tf.UbuntuKernelRule("CVE-K4", "jammy", "linux-hwe-6.5", "released", "6.5.0-44.44~22.04.1"))
	for _, f := range res.Findings {
		if f.CVEID == "CVE-K4" {
			t.Errorf("kernel rule for a non-running kernel family must produce no finding: %+v", f)
		}
	}
}

// Unknown signed kernel source must not map to a family; kernel advisories
// are skipped rather than guessed.
func TestUnknownSignedSourceNotMapped(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		SetKernel(map[string]any{"running_kernel": "6.8.0-106-generic"}).
		AddPackage("linux-image-6.8.0-106-generic", "6.8.0-106.106~22.04.1", tf.WithSource("linux-signed-unknown"))
	res := resolve(t, doc,
		tf.UbuntuKernelRule("CVE-K6", "jammy", "linux-hwe-6.8", "released", "6.8.0-110.110~22.04.1"))
	for _, f := range res.Findings {
		if f.CVEID == "CVE-K6" {
			t.Fatalf("unknown signed source must prevent kernel findings: %+v", f)
		}
	}
}

// HWE 6.5 advisories must not apply when running linux-hwe-6.8.
func TestHWE65RuleNotAppliedToHWE68Running(t *testing.T) {
	res := resolve(t, kernelDoc(),
		tf.UbuntuKernelRule("CVE-K7", "jammy", "linux-hwe-6.5", "released", "6.5.0-44.44~22.04.1"))
	if f := findFinding(t, res, "linux-image-6.8.0-106-generic", "CVE-K7"); f != nil {
		t.Errorf("linux-hwe-6.5 rule must not apply to linux-hwe-6.8 kernel: %+v", f)
	}
}

// A custom/unmapped kernel makes kernel advisories undecidable; noted, not
// guessed.
func TestCustomKernelSkipped(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		SetKernel(map[string]any{"running_kernel": "6.9.0-custom+"})
	res := resolve(t, doc,
		tf.UbuntuKernelRule("CVE-K5", "jammy", "linux-hwe-6.8", "released", "6.8.0-110.110~22.04.1"))
	for _, f := range res.Findings {
		if f.CVEID == "CVE-K5" {
			t.Errorf("unmapped kernel must not produce kernel findings: %+v", f)
		}
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "custom") || strings.Contains(n, "could not be mapped") {
			found = true
		}
	}
	if !found {
		t.Errorf("unmapped kernel must be noted: %v", res.Notes)
	}
}
