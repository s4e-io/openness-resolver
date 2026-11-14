package resolver_test

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

func resolveOrigins(t *testing.T, doc *tf.Doc) *resolver.RunResult {
	t.Helper()
	lr, err := doc.Load()
	if err != nil {
		t.Fatal(err)
	}
	rs := &rules.RuleSet{Rules: []rules.PackageVulnerabilityRule{
		tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.10"),
	}}
	res, err := resolver.NewEngine(rs).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ubuntuRepo() tf.PkgOpt {
	return tf.WithRepo("Ubuntu", "jammy-updates", "main", "http://ports.ubuntu.com/ubuntu-ports", "matched_apt_lists")
}

func dockerRepo() tf.PkgOpt {
	return tf.WithRepo("Docker", "jammy", "stable", "https://download.docker.com/linux/ubuntu", "matched_apt_lists")
}

// A host whose packages all come from the distribution stays covered.
func TestDistributionOnlyHostStaysCovered(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"), ubuntuRepo()).
		AddPackage("superseded", "1.0", tf.WithRepo("", "", "", "", "not_in_apt_lists")).
		AddPackage("bare", "1.0")
	res := resolveOrigins(t, doc)
	if res.RuleCoverage.State != resolver.CoverageCovered {
		t.Fatalf("coverage %+v", res.RuleCoverage)
	}
	o := res.PackageOrigins
	if o == nil || o.Vendor != 1 || o.Unknown != 1 || o.NotClassified != 1 || o.ThirdParty != 0 || len(o.ThirdPartyPackages) != 0 {
		t.Fatalf("origins %+v", o)
	}
	for _, u := range res.Unknowns {
		if u.Kind == "package" {
			t.Fatalf("unexpected package unknown %+v", u)
		}
	}
}

// Third-party packages are listed, make coverage partial and show up in
// unknowns. Unknown origin is never counted as third party.
func TestThirdPartyPackagesAreAGap(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"), ubuntuRepo()).
		AddPackage("docker-ce", "5:28.5.0-1~ubuntu.22.04~jammy", dockerRepo(),
			tf.WithOrigin("Docker", "Docker <support@docker.com>", "https://download.docker.com/linux/ubuntu", "")).
		AddPackage("containerd.io", "1.7.28-1", dockerRepo()).
		AddPackage("superseded", "1.0", tf.WithRepo("", "", "", "", "not_in_apt_lists"))
	res := resolveOrigins(t, doc)

	o := res.PackageOrigins
	if o == nil || o.Vendor != 1 || o.ThirdParty != 2 || o.Unknown != 1 {
		t.Fatalf("origins %+v", o)
	}
	if len(o.ThirdPartyPackages) != 2 || o.ThirdPartyPackages[0].Name != "containerd.io" || o.ThirdPartyPackages[1].Name != "docker-ce" {
		t.Fatalf("third party list %+v", o.ThirdPartyPackages)
	}
	d := o.ThirdPartyPackages[1]
	if d.Origin != "Docker" || d.Status != resolver.ThirdPartyNotEvaluated || d.RepositoryURL == "" || d.RawVersion != "5:28.5.0-1~ubuntu.22.04~jammy" {
		t.Fatalf("docker-ce %+v", d)
	}

	cov := res.RuleCoverage
	if cov.State != resolver.CoveragePartial {
		t.Fatalf("coverage state %s (%s)", cov.State, cov.Reason)
	}
	var gap *resolver.CoverageGap
	for i := range cov.Gaps {
		if cov.Gaps[i].Kind == resolver.GapThirdPartyPackages {
			gap = &cov.Gaps[i]
		}
	}
	if gap == nil || gap.Count != 2 || gap.Release != "ubuntu/jammy" || gap.Detail != "containerd.io, docker-ce" {
		t.Fatalf("gap %+v", gap)
	}
	if !strings.Contains(cov.Reason, "2 packages from outside the distribution not covered by ubuntu/jammy advisories") {
		t.Fatalf("reason %q", cov.Reason)
	}
	if err := cov.EvaluationError("x.openness"); err != nil {
		t.Fatalf("a third-party gap must not fail the run: %v", err)
	}

	n := 0
	for _, u := range res.Unknowns {
		if u.Kind == "package" {
			n++
			if !strings.HasPrefix(u.Reason, "third_party_package: origin Docker") {
				t.Fatalf("unknown %+v", u)
			}
		}
	}
	if n != 2 {
		t.Fatalf("package unknowns %d", n)
	}
}

// A long list is cut in the gap detail, the count stays exact.
func TestThirdPartyGapDetailIsCut(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"), ubuntuRepo())
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		doc.AddPackage("vendor-"+n, "1.0", dockerRepo())
	}
	res := resolveOrigins(t, doc)
	for _, g := range res.RuleCoverage.Gaps {
		if g.Kind == resolver.GapThirdPartyPackages {
			if g.Count != 7 || g.Detail != "vendor-a, vendor-b, vendor-c, vendor-d, vendor-e and 2 more" {
				t.Fatalf("gap %+v", g)
			}
			return
		}
	}
	t.Fatal("no third-party gap")
}

func swInstance(key, path, status string, owner map[string]any) map[string]any {
	v := map[string]any{
		"entity_id": "sw:" + key + ":host:" + path, "product_key": key, "vendor": "v", "product": key,
		"scope": "host", "install_path": path, "version": "1.2.3",
		"version_candidates": []any{}, "patch_ids": []any{}, "confidence": "direct", "gap": nil, "running": false,
		"signals":          map[string]any{"paths": []any{}, "processes": []any{}, "ports": []any{}, "registry": []any{}},
		"catalog_verified": true,
	}
	if status != "" {
		v["owner_package_status"] = status
		v["owner_package"] = owner
	}
	return v
}

// An instance whose files belong to a distribution package is covered by
// that package and is not an unknown. Every other owner fact leaves it
// unjudged, with the reason stated.
func TestSoftwareOwnerDecidesCoverage(t *testing.T) {
	owner := func(name string) map[string]any {
		return map[string]any{"manager": "dpkg", "name": name, "entity_id": "pkg:dpkg:" + name}
	}
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl"), ubuntuRepo()).
		AddPackage("nginx", "1.18.0-6ubuntu14.4", ubuntuRepo()).
		AddPackage("vendor-suite", "6.4.0", dockerRepo()).
		AddPackage("superseded", "1.0", tf.WithRepo("", "", "", "", "not_in_apt_lists")).
		AddSoftwareInstance(swInstance("a-distribution", "/usr", "owned", owner("nginx"))).
		AddSoftwareInstance(swInstance("b-third-party", "/opt/vendor-suite/embedded", "owned", owner("vendor-suite"))).
		AddSoftwareInstance(swInstance("c-unknown-origin", "/usr/lib/x", "owned", owner("superseded"))).
		AddSoftwareInstance(swInstance("d-not-owned", "/usr/local/nginx", "not_owned", nil)).
		AddSoftwareInstance(swInstance("e-not-checked", "/srv/x", "not_checked", nil)).
		AddSoftwareInstance(swInstance("f-old-evidence", "/srv/y", "", nil)).
		AddSoftwareInstance(swInstance("g-missing-package", "/srv/z", "owned", owner("gone")))
	res := resolveOrigins(t, doc)
	if len(res.SoftwareInventory) != 7 {
		t.Fatalf("instances %d", len(res.SoftwareInventory))
	}
	want := []struct{ status, reason string }{
		{resolver.SoftwareCoveredByPackage, "installed by distribution package nginx 1.18.0-6ubuntu14.4"},
		{resolver.SoftwareNoRules, "owned by third-party package vendor-suite (origin Docker)"},
		{resolver.SoftwareNoRules, "whose origin could not be established"},
		{resolver.SoftwareNoRules, "no installed package owns this install"},
		{resolver.SoftwareNoRules, "no vendor feed is wired"},
		{resolver.SoftwareNoRules, "no vendor feed is wired"},
		{resolver.SoftwareNoRules, "not in the package inventory"},
	}
	for i, w := range want {
		s := res.SoftwareInventory[i]
		if s.Resolution.Status != w.status || !strings.Contains(strings.Join(s.Resolution.Reasons, "|"), w.reason) {
			t.Errorf("%s: %+v", s.ProductKey, s.Resolution)
		}
	}
	if res.SoftwareInventory[0].OwnerPackage == nil || res.SoftwareInventory[0].OwnerPackageStatus != "owned" {
		t.Errorf("owner not passed through: %+v", res.SoftwareInventory[0])
	}
	if res.SoftwareInventory[5].OwnerPackageStatus != "" {
		t.Errorf("old evidence must not get an owner status")
	}
	sw := 0
	for _, u := range res.Unknowns {
		if u.Kind == "software" {
			sw++
			if strings.HasPrefix(u.Subject, "a-distribution") {
				t.Errorf("covered instance listed as unknown: %+v", u)
			}
		}
	}
	if sw != 6 {
		t.Errorf("software unknowns %d", sw)
	}
}

// Without evaluated host packages an owning package covers nothing.
func TestSoftwareOwnerNeedsEvaluatedHost(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("nginx", "1.18.0-6ubuntu14.4", ubuntuRepo()).
		AddSoftwareInstance(swInstance("nginx", "/usr", "owned", map[string]any{"manager": "dpkg", "name": "nginx", "entity_id": "pkg:dpkg:nginx"}))
	lr, err := doc.Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.NewEngine(&rules.RuleSet{}).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.PackageOrigins != nil {
		t.Fatalf("origins reported for an unevaluated host: %+v", res.PackageOrigins)
	}
	s := res.SoftwareInventory[0]
	if s.Resolution.Status != resolver.SoftwareNoRules || !strings.Contains(strings.Join(s.Resolution.Reasons, "|"), "host packages were not evaluated") {
		t.Fatalf("resolution %+v", s.Resolution)
	}
}
