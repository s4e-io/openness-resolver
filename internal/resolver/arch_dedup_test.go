package resolver

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

// Same package, CVE and fixed version published per architecture: the rule
// for the host architecture must decide, never the collapsed wrong-arch one.
func TestArchSpecificRulesDoNotCollapseOntoWrongArch(t *testing.T) {
	for _, order := range [][2]string{{"amd64", "arm64"}, {"arm64", "amd64"}} {
		var list []rules.PackageVulnerabilityRule
		for _, arch := range order {
			r := tf.UbuntuRule("CVE-ARCH", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16")
			r.RuleID += ":" + arch
			r.Architecture = arch
			list = append(list, r)
		}
		doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
		res := resolve(t, doc, list...)
		f := mustFinding(t, res, "libssl3", "CVE-ARCH")
		if f.State != findings.StateVulnerable || f.Rule.RuleID != list[0].RuleID[:len(list[0].RuleID)-len(order[0])]+"arm64" {
			t.Errorf("order %v: state=%s rule=%s", order, f.State, f.Rule.RuleID)
		}
	}
}

// Only a wrong-arch rule: the mismatch stays visible as not_applicable.
func TestArchOnlyWrongRuleStaysVisible(t *testing.T) {
	r := tf.UbuntuRule("CVE-ARCH2", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	r.Architecture = "amd64"
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	res := resolve(t, doc, r)
	if f := mustFinding(t, res, "libssl3", "CVE-ARCH2"); f.State != findings.StateNotApplicable {
		t.Errorf("state=%s", f.State)
	}
}

// RPM rules with an architecture (x86_64 vs aarch64) on a Rocky host.
func TestArchSpecificRPMRules(t *testing.T) {
	var list []rules.PackageVulnerabilityRule
	for _, a := range []struct{ arch, fixed string }{{"aarch64", "1:3.0.7-27.el9"}, {"x86_64", "1:3.0.7-27.el9"}} {
		list = append(list, rules.PackageVulnerabilityRule{
			RuleID: "rocky:9:T:CVE-RA:openssl-libs:" + a.arch, Ecosystem: "rpm", Vendor: "rocky", Distribution: "rocky",
			Release: "9", Architecture: a.arch, PackageName: "openssl-libs", Status: rules.StatusReleased,
			FixedVersion: a.fixed, Comparator: "rpm", CVEID: "CVE-RA", SourcePriority: 1,
		})
	}
	doc := tf.NewUbuntuJammyARM64().SetOS(map[string]any{
		"distribution_id": "rocky", "version_id": "9.4", "distribution_version": "9.4", "version_codename": "", "architecture": "x86_64",
	}).AddPackage("openssl-libs", "1:3.0.7-24.el9", tf.WithArch("x86_64"), func(v map[string]any) { v["package_manager"] = "rpm" })
	res := resolve(t, doc, list...)
	f := mustFinding(t, res, "openssl-libs", "CVE-RA")
	if f.State != findings.StateVulnerable || f.Rule.RuleID != "rocky:9:T:CVE-RA:openssl-libs:x86_64" {
		t.Errorf("state=%s rule=%s", f.State, f.Rule.RuleID)
	}
}
