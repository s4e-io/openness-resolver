package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/python"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

// A jammy asset resolved against jammy rules reports coverage.
func TestRuleCoveragePresent(t *testing.T) {
	res := resolve(t, tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.10"),
		tf.UbuntuRule("CVE-C1", "jammy", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15"))
	if res.RuleCoverage.State != CoverageCovered {
		t.Fatalf("state=%s", res.RuleCoverage.State)
	}
	if res.RuleCoverage.AssetRelease != "ubuntu/jammy" {
		t.Errorf("release=%q", res.RuleCoverage.AssetRelease)
	}
	if res.RuleCoverage.RulesForAsset == 0 {
		t.Error("rules_for_asset must be counted when covered")
	}
}

// The regression this guards: a rule store loaded with a different release
// produces zero findings, which must never read as an all-clear.
func TestRuleCoverageMissingOnWrongRelease(t *testing.T) {
	res := resolve(t, tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.10"),
		tf.UbuntuRule("CVE-C1", "noble", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15"))
	if res.RuleCoverage.State != CoverageMissing {
		t.Fatalf("state=%s, want %s", res.RuleCoverage.State, CoverageMissing)
	}
	if res.RuleCoverage.RulesForAsset != 0 {
		t.Errorf("rules_for_asset=%d", res.RuleCoverage.RulesForAsset)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(res.Findings))
	}
	if strings.Join(res.RuleCoverage.LoadedReleases, ",") != "ubuntu/noble" {
		t.Errorf("loaded=%v", res.RuleCoverage.LoadedReleases)
	}
}

func TestRuleCoverageMissingOnEmptyStore(t *testing.T) {
	res := resolve(t, tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.10"))
	if res.RuleCoverage.State != CoverageMissing {
		t.Fatalf("state=%s", res.RuleCoverage.State)
	}
	if len(res.RuleCoverage.LoadedReleases) != 0 {
		t.Errorf("loaded=%v", res.RuleCoverage.LoadedReleases)
	}
	if !strings.Contains(res.RuleCoverage.Reason, "not an all-clear") {
		t.Errorf("reason=%q", res.RuleCoverage.Reason)
	}
}

func TestRuleCoverageUbuntuCoveredAlpineImageMissing(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.10").
		AddContainer(tf.ContainerSpec{
			ID: "c1", Name: "c1", Digest: "sha256:alpine", ImageRef: "alpine:3.19", State: "running",
			Packages: [][3]string{
				{"alpine-baselayout", "3.4.3-r2", "apk"},
				{"busybox", "1.36.1-r15", "apk"},
			},
		})
	res := resolve(t, doc, tf.UbuntuRule("CVE-C1", "jammy", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15"))
	cov := res.RuleCoverage
	if cov.State != CoverageMissing {
		t.Fatalf("state=%s, want missing", cov.State)
	}
	if cov.AssetRelease != "ubuntu/jammy" {
		t.Fatalf("asset_release=%q", cov.AssetRelease)
	}
	if cov.RulesForAsset == 0 {
		t.Fatal("ubuntu rules were loaded; rules_for_asset must stay non-zero")
	}
	if len(cov.Gaps) != 1 || cov.Gaps[0].Release != "alpine/v3.19" || cov.Gaps[0].Kind != GapMissingRules {
		t.Fatalf("gaps=%+v", cov.Gaps)
	}
	err := cov.EvaluationError("host.openness")
	if err == nil || !strings.Contains(err.Error(), "feed sync --for host.openness") {
		t.Fatalf("missing image rules should name feed sync: %v", err)
	}
	if strings.Contains(cov.AssetRelease, ",") {
		t.Fatalf("asset_release must stay a single release, got %q", cov.AssetRelease)
	}
}

func TestRuleCoveragePyPIWithoutRulesIsNotClean(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.10").
		AddPythonDistribution(map[string]any{
			"entity_id":          "py-dist:demo",
			"name_normalized":    "demo-pkg",
			"version":            "1.0.0",
			"raw_version_string": "1.0.0",
			"resolver_ecosystem": "pypi",
		})
	res := resolve(t, doc, tf.UbuntuRule("CVE-C1", "jammy", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15"))
	cov := res.RuleCoverage
	// Without osv-pypi the result is partial: the host is evaluated, PyPI is named as not
	// synced in a gap and a note, and resolve does not fail.
	if cov.State != CoveragePartial {
		t.Fatalf("state=%s", cov.State)
	}
	if cov.AssetRelease != "ubuntu/jammy" || cov.RulesForAsset == 0 {
		t.Fatalf("host coverage must stay: %+v", cov)
	}
	if len(cov.Gaps) != 1 || cov.Gaps[0].Release != "pypi" || cov.Gaps[0].Kind != GapNotSynced {
		t.Fatalf("gaps=%+v", cov.Gaps)
	}
	for _, f := range res.Findings {
		if f.Scope == ScopePythonEnvironment {
			t.Fatalf("unevaluated pypi distribution produced a finding: %+v", f)
		}
	}
	if err := cov.EvaluationError("host.openness"); err != nil {
		t.Fatalf("missing PyPI data alone must not fail resolve: %v", err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), PyPINotSyncedNote) {
		t.Fatalf("notes %v", res.Notes)
	}
}

// The osv-pypi archive covers every package: its snapshot names none.
func TestPyPIFullFeedCoversEveryPackage(t *testing.T) {
	inv := &python.Inventory{Distributions: []python.Distribution{{
		ResolverEcosystem: python.EcosystemPyPI,
		NameNormalized:    "never-heard-of",
	}}}
	rs := &rules.RuleSet{Snapshots: []rules.FeedSourceMetadata{{SourceName: "osv-pypi", SHA256: "ab"}}}
	if gaps := pypiCoverageGaps(rs, inv); len(gaps) != 0 {
		t.Fatalf("full feed: %+v", gaps)
	}
}

func TestRuleCoveragePyPINamesOnlyTheUnfetchedPackage(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPythonDistribution(map[string]any{
			"entity_id":          "py-dist:demo",
			"name_normalized":    "demo-pkg",
			"version":            "1.0.0",
			"raw_version_string": "1.0.0",
			"resolver_ecosystem": "pypi",
		})
	res := resolve(t, doc, tf.PyPIRule("CVE-1", "other-pkg", "GHSA-1", "released", "2.0.0"))
	if len(res.RuleCoverage.Gaps) != 1 || res.RuleCoverage.Gaps[0].Release != "pypi/demo-pkg" {
		t.Fatalf("gaps=%+v", res.RuleCoverage.Gaps)
	}
}

func TestPyPINameFetchedWithNoVulnerabilitiesIsCovered(t *testing.T) {
	inv := &python.Inventory{Distributions: []python.Distribution{{
		ResolverEcosystem: python.EcosystemPyPI,
		NameNormalized:    "demo-pkg",
	}}}
	rs := &rules.RuleSet{Snapshots: []rules.FeedSourceMetadata{{
		SourceName:   "osv-pypi",
		PackageNames: []string{"demo-pkg"},
	}}}
	if gaps := pypiCoverageGaps(rs, inv); len(gaps) != 0 {
		t.Fatalf("fetched name with no vulnerabilities is not a gap: %+v", gaps)
	}
}

// The output names the feed snapshot behind every loaded rule directory, so
// rules built from an old download are visible even when coverage is complete.
func TestRuleCoverageSourcesNameTheSnapshot(t *testing.T) {
	st := rules.NewStore(t.TempDir())
	at := time.Date(2026, 11, 3, 23, 29, 38, 0, time.UTC)
	rule := tf.UbuntuRule("CVE-C1", "jammy", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15")
	if err := st.SaveRules("ubuntu", "jammy", []rules.PackageVulnerabilityRule{rule}, rules.FeedSourceMetadata{
		SourceName: "ubuntu-oval-usn-jammy", SourceURL: "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2",
		DownloadedAt: at, SHA256: "6aa0", ParserVersion: "ubuntu-oval/1.1.0"}); err != nil {
		t.Fatal(err)
	}
	rs, err := st.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	got := coverageSources(rs)
	if len(got) != 1 || got[0].Release != "ubuntu/jammy" || got[0].Source != "ubuntu-oval-usn-jammy" ||
		got[0].SHA256 != "6aa0" || got[0].DownloadedAt == nil || !got[0].DownloadedAt.Equal(at) || got[0].Parser != "ubuntu-oval/1.1.0" {
		t.Fatalf("sources %+v", got)
	}
	// metadata.json itself does not gain the directory fields.
	b, _ := os.ReadFile(filepath.Join(st.Root, "normalized", "ubuntu", "jammy", "metadata.json"))
	if strings.Contains(string(b), `"vendor"`) || strings.Contains(string(b), `"release"`) {
		t.Fatalf("metadata.json changed shape: %s", b)
	}
	// No rules loaded: an empty list, not null.
	if res := resolve(t, tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.10")); res.RuleCoverage.Sources == nil {
		t.Fatal("sources is null")
	}
}
