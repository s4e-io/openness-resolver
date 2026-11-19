package resolver_test

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

const java4shell = "CVE-2026-114938"

func javaInstance(name, path, version, status string, owner map[string]any) map[string]any {
	v := map[string]any{
		"entity_id": "sw:java-runtime:host:" + name, "product_key": "java-runtime", "vendor": "oracle", "product": "jdk",
		"scope": "host", "install_path": path, "version": version,
		"version_candidates": []any{}, "patch_ids": []any{}, "confidence": "direct", "gap": nil, "running": false,
		"signals":          map[string]any{"paths": []any{}, "processes": []any{}, "ports": []any{}, "registry": []any{}},
		"catalog_verified": true,
	}
	if status != "" {
		v["owner_package_status"], v["owner_package"] = status, owner
	}
	return v
}

func jammyX86() *tf.Doc {
	return tf.NewUbuntuJammyARM64().SetOS(map[string]any{"architecture": "x86_64"})
}

func resolveWith(t *testing.T, doc *tf.Doc, list ...rules.PackageVulnerabilityRule) *resolver.RunResult {
	t.Helper()
	lr, err := doc.Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.NewEngine(tf.RuleSet(list...)).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func cveFindings(res *resolver.RunResult, cve string) []findings.Finding {
	var out []findings.Finding
	for _, f := range res.Findings {
		if f.CVEID == cve {
			out = append(out, f)
		}
	}
	return out
}

// Ubuntu packages are judged by the advisory's per-release fixed versions before the OVAL
// has the USN: an old build is vulnerable with the USN named, a fixed build is fixed.
func TestAdvisoryUbuntuPackagesBeforeTheFeed(t *testing.T) {
	doc := jammyX86().
		AddPackage("openjdk-17-jre-headless", "17.0.17+10-1~22.04", tf.WithSource("openjdk-17"), tf.WithArch("amd64")).
		AddPackage("openjdk-17-jdk-headless", "17.0.21.1+2-1~22.04.1", tf.WithSource("openjdk-17"), tf.WithArch("amd64")).
		AddPackage("openjdk-21-jre-headless", "21.0.9+10-1~22.04", tf.WithSource("openjdk-21"), tf.WithArch("amd64")).
		AddPackage("openjdk-11-jre-headless", "11.0.25+9-1~22.04", tf.WithSource("openjdk-11"), tf.WithArch("amd64"))
	// Some other rule keeps the release covered, as a synced feed would.
	res := resolveWith(t, doc, tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.18"))
	got := map[string]findings.Finding{}
	for _, f := range cveFindings(res, java4shell) {
		got[f.BinaryPackage] = f
	}
	if len(got) != 3 {
		t.Fatalf("findings %v", got)
	}
	if f := got["openjdk-17-jre-headless"]; f.State != findings.StateVulnerable || f.FixedVersion != "17.0.21.1+2-1~22.04.1" || f.AdvisoryIDs[0] != "USN-9155-1" {
		t.Errorf("old openjdk-17: %+v", f)
	}
	if f := got["openjdk-17-jdk-headless"]; f.State != findings.StateFixed {
		t.Errorf("fixed openjdk-17: %+v", f)
	}
	if f := got["openjdk-21-jre-headless"]; f.State != findings.StateVulnerable || f.AdvisoryIDs[0] != "USN-9156-1" {
		t.Errorf("old openjdk-21: %+v", f)
	}
	if _, ok := got["openjdk-11-jre-headless"]; ok {
		t.Error("Java 11 is not affected")
	}
}

// Advisory rules are not feed data: a host without any feed rule stays "missing", it does
// not read as covered because an advisory has rules for its release.
func TestAdvisoryRulesDoNotMakeCoverage(t *testing.T) {
	doc := jammyX86().AddPackage("openjdk-17-jre-headless", "17.0.17+10-1~22.04", tf.WithSource("openjdk-17"), tf.WithArch("amd64"))
	res := resolveWith(t, doc)
	if res.RuleCoverage.State != resolver.CoverageMissing || res.RuleCoverage.RulesForAsset != 0 {
		t.Fatalf("coverage %+v", res.RuleCoverage)
	}
	// The advisory still names the vulnerable package.
	if len(cveFindings(res, java4shell)) != 1 {
		t.Fatalf("findings %+v", res.Findings)
	}
}

// When the feed has the USN, its rule and the advisory's merge into one finding.
func TestAdvisoryAndFeedMergeIntoOneFinding(t *testing.T) {
	feed := tf.UbuntuRule(java4shell, "jammy", "openjdk-17", "openjdk-17-jre-headless", rules.StatusReleased, "17.0.21.1+2-1~22.04.1")
	feed.RuleID, feed.AdvisoryIDs = "ubuntu:jammy:USN-9155-1:"+java4shell, []string{"USN-9155-1"}
	doc := jammyX86().AddPackage("openjdk-17-jre-headless", "17.0.17+10-1~22.04", tf.WithSource("openjdk-17"), tf.WithArch("amd64"))
	res := resolveWith(t, doc, feed)
	fs := cveFindings(res, java4shell)
	if len(fs) != 1 || fs[0].State != findings.StateVulnerable || fs[0].FixedVersion != "17.0.21.1+2-1~22.04.1" {
		t.Fatalf("findings %+v", fs)
	}
}

// Installs found on disk: judged by version; Java 8 and 11, fixed builds and ARM64 hosts
// get nothing; an install without a fix on its line is listed without a card.
func TestAdvisoryInstances(t *testing.T) {
	doc := jammyX86().
		AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"), tf.WithArch("amd64")).
		AddSoftwareInstance(javaInstance("a", "/opt/jdk-17", "17.0.21", "not_owned", nil)).
		AddSoftwareInstance(javaInstance("b", "/opt/jdk-17-fixed", "17.0.21.1", "not_owned", nil)).
		AddSoftwareInstance(javaInstance("c", "/opt/jdk-11", "11.0.25", "not_owned", nil)).
		AddSoftwareInstance(javaInstance("d", "/opt/jdk-8", "1.8.0_391", "not_checked", nil)).
		AddSoftwareInstance(javaInstance("e", "/opt/jdk-19", "19.0.2", "not_checked", nil)).
		AddSoftwareInstance(javaInstance("f", "/opt/jdk-21", "21.0.13", "", nil))
	res := resolveWith(t, doc, tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.18"))
	got := map[string]findings.Finding{}
	for _, f := range cveFindings(res, java4shell) {
		got[f.InstalledVersion] = f
	}
	if len(got) != 3 {
		t.Fatalf("findings %+v", got)
	}
	a := got["17.0.21"]
	if a.State != findings.StateVulnerable || a.Confidence != "medium" || a.FixedVersion != "17.0.21.1" || a.Severity != "critical" ||
		a.DetectionMethod != resolver.MethodAdvisory || !strings.Contains(a.BinaryPackage, "/opt/jdk-17") || a.FixAvailability != findings.FixAvailable {
		t.Errorf("17.0.21: %+v", a)
	}
	if !strings.Contains(strings.Join(a.Reasons, " "), "UseBASE64Intrinsics") || !strings.Contains(strings.Join(a.Reasons, " "), "AVX-512") {
		t.Errorf("reasons miss the mitigation or the CPU condition: %v", a.Reasons)
	}
	if e := got["19.0.2"]; e.State != findings.StateVulnerable || e.FixedVersion != "" || e.FixAvailability != findings.FixUnavailable {
		t.Errorf("19.0.2: %+v", e)
	}
	// Cards: the two installs with a fix have one; the end-of-life one has none.
	cards := 0
	for _, g := range res.RemediationGroups {
		if g.Action == findings.ActionUpdateApplication && len(g.Targets) == 1 && g.Targets[0].TargetVersion != "" {
			cards++
			if g.Closes.CVEIDs[0] != java4shell || !strings.Contains(g.CommandHint, "UseBASE64Intrinsics") {
				t.Errorf("card %+v", g)
			}
		}
	}
	if cards != 2 {
		t.Errorf("cards %d", cards)
	}
	// Judged installs leave the unknowns; an install of another line's fixed build too.
	judged := map[string]string{}
	for _, s := range res.SoftwareInventory {
		judged[s.InstallPath] = s.Resolution.Status
	}
	for path, want := range map[string]string{"/opt/jdk-17": resolver.SoftwareAdvisory, "/opt/jdk-17-fixed": resolver.SoftwareAdvisory, "/opt/jdk-11": resolver.SoftwareAdvisory} {
		if judged[path] != want {
			t.Errorf("%s status %q, want %q", path, judged[path], want)
		}
	}
	for _, u := range res.Unknowns {
		if u.Kind == "software" && strings.Contains(u.Subject, "java-runtime") {
			t.Errorf("a judged install is still an unknown: %+v", u)
		}
	}
	// The installs show up in the findings and the resolver never fails on them.
	if res.RuleCoverage.State != resolver.CoverageCovered {
		t.Errorf("coverage %+v", res.RuleCoverage)
	}
}

func TestAdvisoryInstancesSkipARM64(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddSoftwareInstance(javaInstance("a", "/opt/jdk-17", "17.0.21", "not_owned", nil))
	res := resolveWith(t, doc, tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.18"))
	if len(cveFindings(res, java4shell)) != 0 {
		t.Fatalf("an ARM64 host got a finding: %+v", res.Findings)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, java4shell) && strings.Contains(n, "not affected") {
			found = true
		}
	}
	if !found {
		t.Errorf("no note about the skipped install: %v", res.Notes)
	}
}

// An install owned by a package of the distribution is the distribution's call: a finding for
// the package (even a fixed one) means nothing is added; without one it is only potentially
// vulnerable; a package of a third party is judged by the install's version.
func TestAdvisoryInstancesDeferToTheDistribution(t *testing.T) {
	owner := func(name string) map[string]any {
		return map[string]any{"manager": "dpkg", "name": name, "entity_id": "pkg:dpkg:" + name}
	}
	doc := jammyX86().
		AddPackage("openjdk-17-jre-headless", "17.0.21.1+2-1~22.04.1", tf.WithSource("openjdk-17"), tf.WithArch("amd64"),
			tf.WithRepo("Ubuntu", "jammy-updates", "main", "http://archive.ubuntu.com/ubuntu", "matched_apt_lists")).
		AddPackage("vendor-jdk", "9.9", tf.WithSource("vendor-jdk"), tf.WithArch("amd64"),
			tf.WithRepo("Azul", "stable", "main", "https://repos.azul.com", "matched_apt_lists")).
		AddPackage("legacy-jdk", "1.0", tf.WithSource("legacy-jdk"), tf.WithArch("amd64"),
			tf.WithRepo("Ubuntu", "jammy", "universe", "http://archive.ubuntu.com/ubuntu", "matched_apt_lists")).
		// Ubuntu's own package, patched: the release file may still say 17.0.21.
		AddSoftwareInstance(javaInstance("pkg", "/usr/lib/jvm/java-17-openjdk-amd64", "17.0.21", "owned", owner("openjdk-17-jre-headless"))).
		AddSoftwareInstance(javaInstance("azul", "/usr/lib/jvm/zulu17", "17.0.21", "owned", owner("vendor-jdk"))).
		AddSoftwareInstance(javaInstance("legacy", "/usr/lib/jvm/legacy", "17.0.21", "owned", owner("legacy-jdk")))
	res := resolveWith(t, doc, tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.18"))
	var pkgFixed, instVuln, instPotential int
	for _, f := range cveFindings(res, java4shell) {
		switch {
		case f.DetectionMethod != resolver.MethodAdvisory && f.State == findings.StateFixed:
			pkgFixed++
		case f.DetectionMethod == resolver.MethodAdvisory && f.State == findings.StateVulnerable:
			instVuln++
			if !strings.Contains(f.BinaryPackage, "zulu17") {
				t.Errorf("wrong install judged by version: %+v", f)
			}
		case f.DetectionMethod == resolver.MethodAdvisory && f.State == findings.StatePotentiallyVulnerable:
			instPotential++
			if !strings.Contains(f.BinaryPackage, "legacy") || !strings.Contains(strings.Join(f.Reasons, " "), "legacy-jdk") {
				t.Errorf("wrong potential install: %+v", f)
			}
		}
	}
	if pkgFixed != 1 || instVuln != 1 || instPotential != 1 {
		t.Fatalf("fixed package %d, vulnerable install %d, potential install %d: %+v", pkgFixed, instVuln, instPotential, cveFindings(res, java4shell))
	}
}
