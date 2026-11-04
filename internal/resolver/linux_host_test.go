package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/feed/amazon"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

func alpineHost(versionID string) *tf.Doc {
	return tf.NewUbuntuJammyARM64().SetOS(map[string]any{
		"distribution_id": "alpine", "distribution_name": "Alpine Linux",
		"distribution_version": versionID, "version_id": versionID, "version_codename": "",
	})
}

func apk(src string) []tf.PkgOpt {
	return []tf.PkgOpt{tf.WithPackageManager("apk"), tf.WithSource(src), tf.WithArch("aarch64")}
}

// An Alpine host is evaluated against secdb rules of the branch derived
// from VERSION_ID (3.20.10 -> v3.20). secdb names origin packages, so the
// openssl rule reaches libcrypto3 and libssl3 through the apk origin.
func TestAlpineHostFindings(t *testing.T) {
	doc := alpineHost("3.20.10").
		AddPackage("libcrypto3", "3.3.0-r2", apk("openssl")...).
		AddPackage("libssl3", "3.3.0-r2", apk("openssl")...).
		AddPackage("busybox", "1.36.1-r28", apk("busybox")...).
		AddPackage("zlib", "1.3.1-r1", apk("zlib")...)
	res := resolve(t, doc,
		tf.AlpineRule("CVE-2024-12797", "v3.20", "openssl", "released", "3.3.3-r0"),
		tf.AlpineRule("CVE-2023-42364", "v3.20", "busybox", "released", "1.36.1-r29"),
		tf.AlpineRule("CVE-2022-37434", "v3.20", "zlib", "released", "1.2.12-r2"),
		// Another branch never applies.
		tf.AlpineRule("CVE-2099-0001", "v3.19", "openssl", "released", "9.9.9-r0"),
	)
	if res.PlatformSupport != "supported" || !res.PlatformTested {
		t.Fatalf("support=%s tested=%v (%s)", res.PlatformSupport, res.PlatformTested, res.SupportReason)
	}
	for _, pkg := range []string{"libcrypto3", "libssl3"} {
		f := mustFinding(t, res, pkg, "CVE-2024-12797")
		if f.State != findings.StateVulnerable || f.FixedVersion != "3.3.3-r0" || f.SourcePackage != "openssl" {
			t.Errorf("%s: state=%s fixed=%s src=%s reasons=%v", pkg, f.State, f.FixedVersion, f.SourcePackage, f.Reasons)
		}
		if f.DetectionMethod != MethodAlpineBranchPackage || f.Release != "v3.20" || f.Confidence != "high" {
			t.Errorf("%s: method=%s release=%s confidence=%s", pkg, f.DetectionMethod, f.Release, f.Confidence)
		}
		expectNoFinding(t, res, pkg, "CVE-2099-0001")
	}
	if f := mustFinding(t, res, "busybox", "CVE-2023-42364"); f.State != findings.StateVulnerable {
		t.Errorf("busybox state=%s", f.State)
	}
	if f := mustFinding(t, res, "zlib", "CVE-2022-37434"); f.State != findings.StateFixed {
		t.Errorf("zlib state=%s", f.State)
	}
	cov := res.RuleCoverage
	if cov.State != CoverageCovered || cov.AssetRelease != "alpine/v3.20" {
		t.Errorf("coverage=%+v", cov)
	}
	var hints []string
	for _, g := range res.RemediationGroups {
		hints = append(hints, g.CommandHint)
	}
	if !strings.Contains(strings.Join(hints, "|"), "apk upgrade libcrypto3 libssl3") {
		t.Errorf("hints=%v", hints)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "invariant violation") {
			t.Errorf("note: %s", n)
		}
	}
}

// A subpackage of another origin is not matched by an origin rule.
func TestAlpineHostOriginRuleStaysOnItsOrigin(t *testing.T) {
	doc := alpineHost("3.20.3").AddPackage("libssl3", "3.3.0-r2", apk("libressl")...)
	res := resolve(t, doc, tf.AlpineRule("CVE-2024-12797", "v3.20", "openssl", "released", "3.3.3-r0"))
	expectNoFinding(t, res, "libssl3", "CVE-2024-12797")
}

// A supported Alpine host without rules for its branch is not an all-clear
// and names feed sync, which now fixes it.
func TestRuleCoverageAlpineHostWithoutRules(t *testing.T) {
	doc := alpineHost("3.19.1").AddPackage("busybox", "1.36.1-r15", apk("busybox")...)
	res := resolve(t, doc, tf.UbuntuRule("CVE-C1", "jammy", "openssl", "openssl", "released", "1"))
	cov := res.RuleCoverage
	if cov.State != CoverageMissing || cov.AssetRelease != "alpine/v3.19" {
		t.Fatalf("coverage=%+v", cov)
	}
	if len(cov.Gaps) != 1 || cov.Gaps[0].Release != "alpine/v3.19" || cov.Gaps[0].Kind != GapMissingRules {
		t.Fatalf("gaps=%+v", cov.Gaps)
	}
	if err := cov.EvaluationError("host.openness"); err == nil || !strings.Contains(err.Error(), "feed sync --for host.openness") {
		t.Fatalf("error=%v", err)
	}
}

const amazonUpdateinfo = `<updates>
<update type="security"><id>ALAS2023-2024-512</id><severity>Important</severity>
 <references><reference id="CVE-2024-0727" type="cve"/></references>
 <pkglist><collection short="amazon-linux-2023">
  <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="aarch64"/>
  <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="x86_64"/>
 </collection></pkglist></update>
<update type="security"><id>ALAS2023-2024-600</id><severity>Medium</severity>
 <references><reference id="CVE-2024-2004" type="cve"/></references>
 <pkglist><collection short="amazon-linux-2023">
  <package name="curl-minimal" version="8.5.0" release="1.amzn2023.0.3" epoch="0" arch="aarch64"/>
 </collection></pkglist></update>
<update type="security"><id>ALAS2-2024-700</id>
 <references><reference id="CVE-2024-7000" type="cve"/></references>
 <pkglist><collection short="amazon-linux-2">
  <package name="bash" version="4.2.46" release="34.amzn2" epoch="0" arch="aarch64"/>
 </collection></pkglist></update>
</updates>`

func amazonRules(t *testing.T, release string) []rules.PackageVulnerabilityRule {
	t.Helper()
	res, err := amazon.Parse(strings.NewReader(amazonUpdateinfo), release, rules.FeedSourceMetadata{RawObjectID: "amazon/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Rules
}

func amazonHost(versionID string) *tf.Doc {
	return tf.NewUbuntuJammyARM64().SetOS(map[string]any{
		"distribution_id": "amzn", "distribution_name": "Amazon Linux",
		"distribution_version": versionID, "version_id": versionID, "version_codename": "",
	})
}

func rpm(src string) []tf.PkgOpt {
	return []tf.PkgOpt{tf.WithPackageManager("rpm"), tf.WithSource(src), tf.WithArch("aarch64")}
}

func TestAmazonLinux2023Host(t *testing.T) {
	doc := amazonHost("2023").
		AddPackage("openssl-libs", "1:3.0.8-1.amzn2023.0.10", rpm("openssl")...).
		AddPackage("curl-minimal", "8.5.0-1.amzn2023.0.3", rpm("curl")...).
		AddPackage("bash", "4.2.46-30.amzn2", rpm("bash")...)
	ruleList := append(amazonRules(t, "2023"), amazonRules(t, "2")...)
	res := resolve(t, doc, ruleList...)
	if res.PlatformSupport != "supported" || !res.PlatformTested {
		t.Fatalf("support=%s tested=%v (%s)", res.PlatformSupport, res.PlatformTested, res.SupportReason)
	}
	f := mustFinding(t, res, "openssl-libs", "CVE-2024-0727")
	if f.State != findings.StateVulnerable || f.FixedVersion != "1:3.0.8-1.amzn2023.0.11" || f.DetectionMethod != MethodRPMPackage {
		t.Errorf("openssl-libs: state=%s fixed=%s method=%s", f.State, f.FixedVersion, f.DetectionMethod)
	}
	if len(f.AdvisoryIDs) != 1 || f.AdvisoryIDs[0] != "ALAS2023-2024-512" || f.Urgency != "important" {
		t.Errorf("advisories=%v urgency=%s", f.AdvisoryIDs, f.Urgency)
	}
	if c := mustFinding(t, res, "curl-minimal", "CVE-2024-2004"); c.State != findings.StateFixed {
		t.Errorf("curl-minimal state=%s", c.State)
	}
	// Amazon Linux 2 rules never apply to a 2023 host.
	expectNoFinding(t, res, "bash", "CVE-2024-7000")
	if cov := res.RuleCoverage; cov.State != CoverageCovered || cov.AssetRelease != "amazon/2023" {
		t.Errorf("coverage=%+v", cov)
	}
	if len(res.RemediationGroups) != 1 || res.RemediationGroups[0].CommandHint != "dnf upgrade --releasever=latest openssl-libs" {
		t.Errorf("remediation=%+v", res.RemediationGroups)
	}
}

func TestAmazonLinux2HostUsesYum(t *testing.T) {
	doc := amazonHost("2").AddPackage("bash", "4.2.46-30.amzn2", rpm("bash")...)
	res := resolve(t, doc, amazonRules(t, "2")...)
	if res.PlatformSupport != "supported" || !res.PlatformTested {
		t.Fatalf("support=%s tested=%v", res.PlatformSupport, res.PlatformTested)
	}
	if f := mustFinding(t, res, "bash", "CVE-2024-7000"); f.State != findings.StateVulnerable {
		t.Errorf("bash state=%s", f.State)
	}
	if len(res.RemediationGroups) != 1 || res.RemediationGroups[0].CommandHint != "yum update bash" {
		t.Errorf("remediation=%+v", res.RemediationGroups)
	}
}
