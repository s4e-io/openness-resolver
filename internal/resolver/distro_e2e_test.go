package resolver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/feed/debian"
	"github.com/s4e-io/openness-resolver/internal/feed/osvdistro"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"

	_ "github.com/s4e-io/openness-resolver/internal/version/rpm"
)

// End-to-end tests with mock data for the RPM and Debian distributions:
// synthetic .openness evidence (testdata/evidence/synthetic) is resolved
// against rules produced by the real parsers from trimmed feed fixtures
// (testdata/feeds). Every vendor's rules are loaded into one rule set, so
// each test also proves a host never picks up another distribution's or
// release's rules.

const repoRoot = "../.."

// fixtureRuleSet parses every feed fixture through the production parsers.
func fixtureRuleSet(t *testing.T) *rules.RuleSet {
	t.Helper()
	var all []rules.PackageVulnerabilityRule
	deb, err := debian.ParseFile(filepath.Join(repoRoot, "testdata/feeds/debian/tracker-sample.json"),
		rules.FeedSourceMetadata{RawObjectID: "debian/fixture"}, map[string]bool{"bookworm": true, "trixie": true})
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, deb.Rules...)
	for _, vendor := range []string{"rocky", "almalinux", "rhel", "opensuse"} {
		files, err := filepath.Glob(filepath.Join(repoRoot, "testdata/feeds/osv", vendor, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("fixtures %s: %v", vendor, err)
		}
		var docs [][]byte
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			docs = append(docs, b)
		}
		res := osvdistro.ParseDocuments(docs, osvdistro.Distros[vendor], nil, rules.FeedSourceMetadata{RawObjectID: vendor + "/fixture"})
		all = append(all, res.Rules...)
	}
	rs := &rules.RuleSet{Rules: all}
	rs.Reindex()
	return rs
}

func resolveEvidence(t *testing.T, name string) *RunResult {
	t.Helper()
	lr, err := evidence.Load(filepath.Join(repoRoot, "testdata/evidence/synthetic", name+".openness"))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	res, err := NewEngine(fixtureRuleSet(t)).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func expectState(t *testing.T, res *RunResult, pkg, cve, state, fixed string) *findings.Finding {
	t.Helper()
	f := mustFinding(t, res, pkg, cve)
	if f.State != state {
		t.Errorf("%s/%s: state=%s, want %s (reasons %v)", pkg, cve, f.State, state, f.Reasons)
	}
	if f.FixedVersion != fixed {
		t.Errorf("%s/%s: fixed=%q, want %q", pkg, cve, f.FixedVersion, fixed)
	}
	return f
}

func expectNoFinding(t *testing.T, res *RunResult, pkg, cve string) {
	t.Helper()
	if f := findFinding(t, res, pkg, cve); f != nil {
		t.Errorf("%s/%s: unexpected finding state=%s release=%s rule=%s", pkg, cve, f.State, f.Release, f.Rule.RuleID)
	}
}

// expectSupported asserts support, coverage and the tested flag. tested is
// true only for releases verified against a real host (testedReleases).
func expectSupported(t *testing.T, res *RunResult, assetRelease string, tested bool) {
	t.Helper()
	if res.PlatformSupport != "supported" {
		t.Fatalf("platform_support=%s (%s)", res.PlatformSupport, res.SupportReason)
	}
	if res.PlatformTested != tested {
		t.Errorf("platform_tested=%v, want %v", res.PlatformTested, tested)
	}
	if res.RuleCoverage.AssetRelease != assetRelease || res.RuleCoverage.State != CoverageCovered {
		t.Errorf("coverage=%+v, want covered %s", res.RuleCoverage, assetRelease)
	}
	for _, f := range res.Findings {
		if f.Release != "" && assetRelease != "" && !strings.HasSuffix(assetRelease, "/"+f.Release) {
			t.Errorf("finding %s/%s uses release %s on %s", f.BinaryPackage, f.CVEID, f.Release, assetRelease)
		}
	}
}

func TestE2EDebian12(t *testing.T) {
	res := resolveEvidence(t, "debian-12-bookworm")
	expectSupported(t, res, "debian/bookworm", true)

	// installed < fixed -> vulnerable, fix available.
	f := expectState(t, res, "libssl3", "CVE-2024-0727", findings.StateVulnerable, "3.0.13-1~deb12u1")
	if f.FixAvailability != findings.FixAvailable || f.DetectionMethod != MethodDebianSourcePackage {
		t.Errorf("fix=%s method=%s", f.FixAvailability, f.DetectionMethod)
	}
	expectState(t, res, "openssl", "CVE-2024-0727", findings.StateVulnerable, "3.0.13-1~deb12u1")
	// installed >= fixed -> fixed.
	expectState(t, res, "libssl3", "CVE-2023-0286", findings.StateFixed, "3.0.8-1")
	expectState(t, res, "libc6", "CVE-2023-4911", findings.StateFixed, "2.36-9+deb12u3")
	// open, no fix -> vulnerable without a fix.
	f = expectState(t, res, "libssl3", "CVE-2025-9230", findings.StateVulnerable, "")
	if f.FixAvailability != findings.FixUnavailable {
		t.Errorf("open CVE fix availability=%s", f.FixAvailability)
	}
	// postponed -> vulnerable, deferred.
	if f := expectState(t, res, "libcurl4", "CVE-2024-2398", findings.StateVulnerable, ""); f.FixAvailability != findings.FixDeferred {
		t.Errorf("postponed fix availability=%s", f.FixAvailability)
	}
	// resolved "0" -> not affected; unimportant -> potentially vulnerable.
	expectState(t, res, "libssl3", "CVE-2025-27587", findings.StateNotApplicable, "")
	expectState(t, res, "zlib1g", "CVE-2023-45853", findings.StatePotentiallyVulnerable, "")
	expectState(t, res, "bash", "CVE-2022-3715", findings.StateUnknown, "")
	// Running kernel decided; the old kernel image on disk is not evaluated.
	expectState(t, res, "linux-image-6.1.0-18-amd64", "CVE-2024-1086", findings.StateFixed, "6.1.76-1")
	expectNoFinding(t, res, "linux-image-6.1.0-17-amd64", "CVE-2024-1086")
	// Release isolation: no trixie or Rocky/RHEL rule reaches a bookworm host.
	for _, f := range res.Findings {
		if f.Distribution != "debian" || f.Release != "bookworm" {
			t.Errorf("finding %s/%s from %s/%s", f.BinaryPackage, f.CVEID, f.Distribution, f.Release)
		}
	}
}

func TestE2EDebian13(t *testing.T) {
	res := resolveEvidence(t, "debian-13-trixie")
	expectSupported(t, res, "debian/trixie", false)
	// Trixie rule (fixed 3.1.5-1), never the bookworm one (3.0.13-1~deb12u1).
	expectState(t, res, "libssl3t64", "CVE-2024-0727", findings.StateFixed, "3.1.5-1")
	// Open on bookworm, fixed on trixie: a trixie host below the fix is
	// vulnerable WITH a fix.
	expectState(t, res, "libssl3t64", "CVE-2025-9230", findings.StateVulnerable, "3.5.4-1~deb13u1")
	expectState(t, res, "libssl3t64", "CVE-2025-27587", findings.StatePotentiallyVulnerable, "")
}

func TestE2EDebian11NotSupported(t *testing.T) {
	res := resolveEvidence(t, "debian-11-bullseye")
	if res.PlatformSupport != "not_supported" || !strings.Contains(res.SupportReason, "bullseye") {
		t.Fatalf("support=%s reason=%q", res.PlatformSupport, res.SupportReason)
	}
	if res.PlatformTested || len(res.Findings) != 0 {
		t.Errorf("tested=%v findings=%d", res.PlatformTested, len(res.Findings))
	}
}

func TestE2ERocky9(t *testing.T) {
	res := resolveEvidence(t, "rocky-9")
	expectSupported(t, res, "rocky/9", true)

	f := expectState(t, res, "openssl-libs", "CVE-2024-0727", findings.StateVulnerable, "1:3.0.7-27.el9")
	if f.DetectionMethod != MethodRPMPackage || f.Comparison == nil || f.Comparison.Comparator != "rpm" {
		t.Errorf("method=%s comparison=%+v", f.DetectionMethod, f.Comparison)
	}
	expectState(t, res, "openssl", "CVE-2024-0727", findings.StateVulnerable, "1:3.0.7-27.el9")
	expectState(t, res, "openssl-libs", "CVE-2023-0286", findings.StateFixed, "1:3.0.1-47.el9_1")
	// Rocky 8 advisory never applies to a Rocky 9 host.
	expectNoFinding(t, res, "openssl-libs", "CVE-2024-5535")
	// Epoch 32 on both sides, release decides.
	expectState(t, res, "bind-libs", "CVE-2023-50387", findings.StateVulnerable, "32:9.16.23-15.el9_4.1")
	// el9_1 < el9_4.1 in the release field.
	expectState(t, res, "tar", "CVE-2022-48303", findings.StateVulnerable, "2:1.34-6.el9_4.1")
	// A tilde pre-release sorts before the final release.
	expectState(t, res, "demo", "CVE-2024-9001", findings.StateVulnerable, "1.0-1.el9")
	// Running kernel fixed; the older installed kernel is skipped.
	expectState(t, res, "kernel-core", "CVE-2024-1086", findings.StateFixed, "0:5.14.0-427.13.1.el9_4")
	for _, f := range res.Findings {
		if f.BinaryPackage == "kernel-core" && f.InstalledVersion != "5.14.0-427.13.1.el9_4" {
			t.Errorf("old kernel evaluated: %s", f.InstalledVersion)
		}
	}
	// Bug-fix errata without CVE and Rocky 10 rules produce nothing.
	for _, f := range res.Findings {
		if f.BinaryPackage == "glibc" {
			t.Errorf("unexpected glibc finding %s from %s", f.CVEID, f.Release)
		}
	}
}

func TestE2EAlmaLinux8(t *testing.T) {
	res := resolveEvidence(t, "almalinux-8")
	expectSupported(t, res, "almalinux/8", true)
	expectState(t, res, "openssl-libs", "CVE-2024-5535", findings.StateVulnerable, "1:1.1.1k-12.el8_9")
	// AlmaLinux 9 advisory never applies to an AlmaLinux 8 host.
	expectNoFinding(t, res, "openssl-libs", "CVE-2024-0727")
	// Modular nodejs: the stream 20 fix decides; the stream 18 fix is
	// rejected even though both share the CVE.
	f := expectState(t, res, "nodejs", "CVE-2024-27983", findings.StateVulnerable, "1:20.12.2-2.module_el8.9.0+3800+a9b4c66d")
	for _, id := range f.RuleIDs {
		if strings.Contains(id, "ALSA-2024:1000") {
			t.Errorf("stream 18 rule must not be applicable: %v", f.RuleIDs)
		}
	}
	// Fixed version without epoch == epoch 0; installed is newer.
	expectState(t, res, "python3-libs", "CVE-2023-40217", findings.StateFixed, "3.6.8-56.el8_9.3")
	expectNoFinding(t, res, "bzip2-libs", "")
}

func TestE2ERHEL9(t *testing.T) {
	res := resolveEvidence(t, "rhel-9")
	expectSupported(t, res, "rhel/9", false)
	// Mainline fix, not the lower EUS fix and not the RHEL 8 fix.
	expectState(t, res, "openssl-libs", "CVE-2024-0727", findings.StateVulnerable, "1:3.0.7-27.el9")
	// installed == fixed -> fixed.
	expectState(t, res, "curl-minimal", "CVE-2024-2398", findings.StateFixed, "7.76.1-29.el9_4")
	// Rocky 9 and RHEL 8 glibc rules never reach a RHEL 9 host.
	expectNoFinding(t, res, "glibc", "CVE-2024-2961")
	for _, f := range res.Findings {
		if f.Distribution != "rhel" {
			t.Errorf("RHEL host matched %s rule %s", f.Distribution, f.Rule.RuleID)
		}
	}
}

func TestE2EOpenSUSELeap156(t *testing.T) {
	res := resolveEvidence(t, "opensuse-leap-15.6")
	expectSupported(t, res, "opensuse/15.6", true)
	expectState(t, res, "libopenssl3", "CVE-2024-4603", findings.StateVulnerable, "3.1.4-150600.5.15.1")
	expectState(t, res, "libopenssl3", "CVE-2024-4741", findings.StateVulnerable, "3.1.4-150600.5.15.1")
	expectState(t, res, "openssl-3", "CVE-2024-4603", findings.StateFixed, "3.1.4-150600.5.15.1")
	// Per-binary versions: each binary is compared with its own fixed version.
	expectState(t, res, "libglib-2_0-0", "CVE-2024-34397", findings.StateVulnerable, "2.78.6-150600.4.3.1")
	expectState(t, res, "gio-branding-upstream", "CVE-2024-34397", findings.StateFixed, "1.0-150600.4.3.1")
	// Installed below the introduced version: not affected, no finding.
	expectNoFinding(t, res, "demo-range", "CVE-2024-9100")
	// Withdrawn advisory produces nothing.
	expectNoFinding(t, res, "libopenssl3", "CVE-2024-9200")
}

func TestE2EUnsupportedRPMFamilies(t *testing.T) {
	cases := []struct {
		id, version, want string
	}{
		{"ol", "9.4", "Oracle"},
		{"centos", "9", "CentOS"},
		{"amzn", "2018.03", "Amazon Linux AMI"},
		{"sles", "15.6", "SLES"},
		{"opensuse-tumbleweed", "20261020", "Tumbleweed"},
	}
	for _, c := range cases {
		lr, err := evidence.Load(filepath.Join(repoRoot, "testdata/evidence/synthetic/rhel-9.openness"))
		if err != nil {
			t.Fatal(err)
		}
		lr.Doc.OperatingSystem.DistributionID = c.id
		lr.Doc.OperatingSystem.VersionID = c.version
		res, err := NewEngine(fixtureRuleSet(t)).Resolve(lr)
		if err != nil {
			t.Fatal(err)
		}
		if res.PlatformSupport != "not_supported" || !strings.Contains(res.SupportReason, c.want) {
			t.Errorf("%s: support=%s reason=%q", c.id, res.PlatformSupport, res.SupportReason)
		}
		if res.PlatformTested || len(res.Findings) != 0 {
			t.Errorf("%s: tested=%v findings=%d", c.id, res.PlatformTested, len(res.Findings))
		}
	}
}

// A supported RPM host with no rules loaded is not an all-clear.
func TestE2ERockyWithoutRulesIsMissing(t *testing.T) {
	lr, err := evidence.Load(filepath.Join(repoRoot, "testdata/evidence/synthetic/rocky-9.openness"))
	if err != nil {
		t.Fatal(err)
	}
	empty := &rules.RuleSet{}
	empty.Reindex()
	res, err := NewEngine(empty).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	cov := res.RuleCoverage
	if cov.State != CoverageMissing || cov.AssetRelease != "rocky/9" || len(cov.Gaps) != 1 || cov.Gaps[0].Kind != GapMissingRules {
		t.Fatalf("coverage=%+v", cov)
	}
	if err := cov.EvaluationError("rocky.openness"); err == nil || !strings.Contains(err.Error(), "feed sync --for rocky.openness") {
		t.Errorf("error=%v", err)
	}
}
