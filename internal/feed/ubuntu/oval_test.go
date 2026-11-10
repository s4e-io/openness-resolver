package ubuntu

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

const sampleOVAL = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.ubuntu.jammy:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 22.04 LTS (jammy) is installed.</title></metadata>
    </definition>
    <definition id="oval:com.ubuntu.jammy:def:685910000000" class="patch" version="1">
      <metadata>
        <title>USN-6859-1 -- OpenSSH vulnerability</title>
        <reference source="USN" ref_id="USN-6859-1" ref_url="https://ubuntu.com/security/notices/USN-6859-1" />
        <reference source="CVE" ref_id="CVE-2024-6387" ref_url="https://www.cve.org/CVERecord?id=CVE-2024-6387" />
        <description>regreSSHion</description>
        <advisory from="security@ubuntu.com">
          <severity>High</severity>
          <issued date="2024-07-01T10:00:00Z" />
          <cve href="https://ubuntu.com/security/CVE-2024-6387" priority="high" usns="6859-1">CVE-2024-6387</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.jammy:def:100" comment="Ubuntu 22.04 LTS (jammy) is installed" />
        <criterion test_ref="oval:com.ubuntu.jammy:tst:685910000000" comment="openssh source package in jammy, is affected and has been fixed (note: '1:8.9p1-3ubuntu0.10')." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.jammy:def:700000000000" class="patch" version="1">
      <metadata>
        <title>USN-7000-1 -- ESM thing</title>
        <reference source="USN" ref_id="USN-7000-1" ref_url="https://ubuntu.com/security/notices/USN-7000-1" />
        <advisory from="security@ubuntu.com">
          <severity>Medium</severity>
          <cve href="https://ubuntu.com/security/CVE-2022-31160" priority="medium">CVE-2022-31160</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.jammy:tst:700000000000" comment="jqueryui source package in esm-apps/jammy, is affected and has been fixed (note: '1.13.1+dfsg-1ubuntu0.1~esm1')." />
        <criterion test_ref="oval:com.ubuntu.jammy:tst:999" comment="'linux-azure' kernel in jammy was vulnerable but has been fixed (note: '5.15.0-1111.120')." />
        <criterion test_ref="oval:com.ubuntu.jammy:tst:998" comment="something entirely unexpected" />
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:685910000000" version="1" check="at least one" comment="Does the 'openssh' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:685910000000" />
      <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:685910000000" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:700000000000" version="1" check="at least one" comment="Does the 'jqueryui' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:700000000000" />
      <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:700000000000" />
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:685910000000" version="1" comment="The 'openssh' package binaries">
      <linux-def:name var_ref="oval:com.ubuntu.jammy:var:685910000000" var_check="at least one" />
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:700000000000" version="1" comment="The 'jqueryui' package binaries">
      <linux-def:name var_ref="oval:com.ubuntu.jammy:var:700000000000" var_check="at least one" />
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:685910000000" version="1" comment="less than">
      <linux-def:evr datatype="debian_evr_string" operation="less than">1:8.9p1-3ubuntu0.10</linux-def:evr>
    </linux-def:dpkginfo_state>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:700000000000" version="1" comment="less than">
      <linux-def:evr datatype="debian_evr_string" operation="less than">1.13.1+dfsg-1ubuntu0.1~esm1</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
  <variables>
    <constant_variable id="oval:com.ubuntu.jammy:var:685910000000" version="1" datatype="string" comment="binaries">
      <value>openssh-client</value>
      <value>openssh-server</value>
    </constant_variable>
    <constant_variable id="oval:com.ubuntu.jammy:var:700000000000" version="1" datatype="string" comment="binaries">
      <value>libjs-jquery-ui</value>
    </constant_variable>
  </variables>
</oval_definitions>`

func TestParseSampleOVAL(t *testing.T) {
	meta := rules.FeedSourceMetadata{RawObjectID: "test-snapshot", SourceURL: "https://example.invalid/oval"}
	res, err := Parse(strings.NewReader(sampleOVAL), meta)
	if err != nil {
		t.Fatal(err)
	}
	// USN-6859-1: 1 CVE x 2 binaries = 2 rules; USN-7000-1: 1 CVE x 1 binary
	// + 1 kernel-flavour rule (linux-azure).
	if len(res.Rules) != 4 {
		t.Fatalf("expected 4 rules, got %d: %+v", len(res.Rules), res.Rules)
	}
	byBin := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range res.Rules {
		byBin[r.PackageName] = r
	}

	ssh := byBin["openssh-client"]
	if ssh.CVEID != "CVE-2024-6387" || ssh.SourcePackage != "openssh" || ssh.Release != "jammy" {
		t.Errorf("openssh rule wrong: %+v", ssh)
	}
	if ssh.FixedVersion != "1:8.9p1-3ubuntu0.10" || ssh.Status != rules.StatusReleased {
		t.Errorf("openssh fix wrong: %+v", ssh)
	}
	if ssh.Comparator != "dpkg" || ssh.SourcePriority != 1 {
		t.Errorf("comparator/priority wrong: %+v", ssh)
	}
	if len(ssh.AdvisoryIDs) != 1 || ssh.AdvisoryIDs[0] != "USN-6859-1" {
		t.Errorf("usn refs wrong: %v", ssh.AdvisoryIDs)
	}
	if ssh.Urgency != "high" {
		t.Errorf("urgency=%q", ssh.Urgency)
	}
	if ssh.PublishedAt == nil {
		t.Error("published date lost")
	}
	// Raw vendor wording must be preserved.
	if !strings.Contains(ssh.VendorNotes, "has been fixed") {
		t.Errorf("vendor notes lost: %q", ssh.VendorNotes)
	}

	jq := byBin["libjs-jquery-ui"]
	if jq.SupportTier != "esm-apps" {
		t.Errorf("esm tier lost: %+v", jq)
	}
	if !strings.HasSuffix(jq.FixedVersion, "~esm1") {
		t.Errorf("esm fixed version wrong: %s", jq.FixedVersion)
	}

	// Kernel-flavour criteria become IsKernel rules keyed by source family.
	kr := byBin[""]
	if !kr.IsKernel || kr.SourcePackage != "linux-azure" || kr.FixedVersion != "5.15.0-1111.120" {
		t.Errorf("kernel rule wrong: %+v", kr)
	}
	if kr.Status != rules.StatusReleased || kr.CVEID != "CVE-2022-31160" {
		t.Errorf("kernel rule status/cve wrong: %+v", kr)
	}

	// Unparsable criteria must be rejected with reasons, not silently
	// skipped.
	if res.Metrics.RejectionReasons["criterion_comment_unparsable"] != 1 {
		t.Errorf("unparsable rejection missing: %v", res.Metrics.RejectionReasons)
	}
	if res.Metrics.CVEsSeen != 2 || res.Metrics.RulesGenerated != 4 {
		t.Errorf("metrics wrong: %+v", res.Metrics)
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := map[string]string{
		"is affected and has been fixed (note: '1.0')":                  rules.StatusReleased,
		"was vulnerable but has been fixed (note: '1.0')":               rules.StatusReleased,
		"is affected and needs fixing":                                  rules.StatusNeeded,
		"is affected, but a decision has been made to defer addressing": rules.StatusDeferred,
		"is not affected":                         rules.StatusNotAffected,
		"does not exist in the release":           rules.StatusDoesNotExist,
		"is affected, but is ignored":             rules.StatusIgnored,
		"went out of standard support":            rules.StatusIgnored,
		"something completely new from Canonical": rules.StatusUnknown,
	}
	for text, want := range cases {
		if got := normalizeStatus(text); got != want {
			t.Errorf("normalizeStatus(%q)=%s, want %s", text, got, want)
		}
	}
}

func TestReleaseAndTier(t *testing.T) {
	cases := []struct{ in, rel, tier string }{
		{"jammy", "jammy", ""},
		{"esm-apps/jammy", "jammy", "esm-apps"},
		{"esm-infra/focal", "focal", "esm-infra"},
	}
	for _, c := range cases {
		rel, tier := releaseAndTier(c.in)
		if rel != c.rel || tier != c.tier {
			t.Errorf("releaseAndTier(%q)=(%s,%s), want (%s,%s)", c.in, rel, tier, c.rel, c.tier)
		}
	}
}

func TestReleaseFromFilename(t *testing.T) {
	if r := releaseFromFilename("com.ubuntu.jammy.usn.oval.xml.bz2"); r != "jammy" {
		t.Errorf("release=%q", r)
	}
}

// Notices whose CVEs are only in the CVE references or the description get
// those CVEs; regression notices and notices that name no CVE stay
// advisory-only.
func TestCVEsOutsideAdvisory(t *testing.T) {
	def := func(id, title, refs, desc string) string {
		return `<definition id="oval:com.ubuntu.jammy:def:` + id + `" class="patch" version="1"><metadata>
<title>` + title + `</title>` + refs + `<description>` + desc + `</description>
<advisory from="security@ubuntu.com"><severity>Medium</severity></advisory></metadata>
<criteria><criterion test_ref="oval:t:1" comment="pkg source package in jammy, is affected and has been fixed (note: '1.0-1ubuntu0.1')." /></criteria></definition>`
	}
	oval := `<?xml version="1.0" encoding="UTF-8"?><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>` +
		def("1", "USN-8779-1 -- Bubblewrap vulnerabilities", `<reference source="USN" ref_id="USN-8779-1" ref_url="u" />`,
			"It was discovered that Bubblewrap mishandled mounts (CVE-2019-12439). It was also found that ... (CVE-2026-87766, CVE-2019-12439)") +
		def("2", "USN-8000-1 -- Example vulnerability", `<reference source="USN" ref_id="USN-8000-1" ref_url="u" /><reference source="CVE" ref_id="CVE-2026-11111" ref_url="u" />`,
			"No ids in the text.") +
		def("3", "USN-7626-2 -- Git regression", `<reference source="USN" ref_id="USN-7626-2" ref_url="u" />`,
			"USN-7626-1 fixed CVE-2025-27613 in Git. The update caused a regression.") +
		def("4", "USN-8226-1 -- kmod update", `<reference source="USN" ref_id="USN-8226-1" ref_url="u" />`,
			"This update disables loading the algif_aead module.") +
		`</definitions>
<tests><linux-def:dpkginfo_test xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:t:1" version="1" check="at least one">
<linux-def:object object_ref="oval:o:1" /><linux-def:state state_ref="oval:s:1" /></linux-def:dpkginfo_test></tests>
<objects><linux-def:dpkginfo_object xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:o:1" version="1"><linux-def:name>pkg</linux-def:name></linux-def:dpkginfo_object></objects>
<states><linux-def:dpkginfo_state xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:s:1" version="1"><linux-def:evr datatype="debian_evr_string" operation="less than">1.0-1ubuntu0.1</linux-def:evr></linux-def:dpkginfo_state></states>
</oval_definitions>`
	res, err := Parse(strings.NewReader(oval), rules.FeedSourceMetadata{RawObjectID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, r := range res.Rules {
		got[r.AdvisoryIDs[0]] = append(got[r.AdvisoryIDs[0]], r.CVEID)
	}
	want := map[string][]string{
		"USN-8779-1": {"CVE-2019-12439", "CVE-2026-87766"},
		"USN-8000-1": {"CVE-2026-11111"},
		"USN-7626-2": {""},
		"USN-8226-1": {""},
	}
	for usn, w := range want {
		if len(got[usn]) != len(w) || strings.Join(got[usn], ",") != strings.Join(w, ",") {
			t.Errorf("%s: CVEs %q, want %q", usn, got[usn], w)
		}
	}
}

func TestRegressionRevertedCVEs(t *testing.T) {
	def := func(id, title, desc string, cves ...string) string {
		var adv string
		for _, c := range cves {
			adv += `<cve href="u" priority="medium">` + c + `</cve>`
		}
		return `<definition id="oval:com.ubuntu.jammy:def:` + id + `" class="patch" version="1"><metadata>
<title>` + title + `</title><reference source="USN" ref_id="` + strings.Fields(title)[0] + `" ref_url="u" /><description>` + desc + `</description>
<advisory from="security@ubuntu.com"><severity>Medium</severity>` + adv + `</advisory></metadata>
<criteria><criterion test_ref="oval:t:1" comment="pkg source package in jammy, is affected and has been fixed (note: '1.0-1ubuntu0.1')." /></criteria></definition>`
	}
	oval := `<?xml version="1.0" encoding="UTF-8"?><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>` +
		def("1", "USN-8018-2 -- Python regression",
			"USN-8018-1 fixed vulnerabilities in python3. That update introduced regressions.  The patches for CVE-2025-15366 and CVE-2025-15367 caused behavior regressions in  IMAP and POP3 handling, which upstream chose to avoid by not backporting them.  Additionally, the patch for CVE-2026-0865 incorrectly rejected horizontal tabs in wsgiref headers. This update fixes these problems.  Original advisory details:  A fix was reverted upstream once (CVE-2026-0865).",
			"CVE-2025-15366", "CVE-2025-15367", "CVE-2026-0865") +
		def("2", "USN-9000-2 -- Example regression",
			"USN-9000-1 fixed CVE-2026-22222. The fix for CVE-2026-22222 was reverted because it broke logins.",
			"CVE-2026-22222") +
		def("3", "USN-9001-1 -- Example vulnerability",
			"An earlier fix for CVE-2026-33333 was reverted; this update fixes it properly.",
			"CVE-2026-33333") +
		`</definitions>
<tests><linux-def:dpkginfo_test xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:t:1" version="1" check="at least one">
<linux-def:object object_ref="oval:o:1" /><linux-def:state state_ref="oval:s:1" /></linux-def:dpkginfo_test></tests>
<objects><linux-def:dpkginfo_object xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:o:1" version="1"><linux-def:name>pkg</linux-def:name></linux-def:dpkginfo_object></objects>
<states><linux-def:dpkginfo_state xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="oval:s:1" version="1"><linux-def:evr datatype="debian_evr_string" operation="less than">1.0-1ubuntu0.1</linux-def:evr></linux-def:dpkginfo_state></states>
</oval_definitions>`
	res, err := Parse(strings.NewReader(oval), rules.FeedSourceMetadata{RawObjectID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, r := range res.Rules {
		got[r.AdvisoryIDs[0]] = append(got[r.AdvisoryIDs[0]], r.CVEID)
	}
	want := map[string][]string{
		// The two CVEs whose patches were not backported get no fixed rule; the
		// CVE the notice really fixes keeps one, also when the repeated original
		// text mentions a revert.
		"USN-8018-2": {"CVE-2026-0865"},
		// Every CVE taken out: the notice stays as an advisory-only rule.
		"USN-9000-2": {""},
		// Only regression notices are read this way.
		"USN-9001-1": {"CVE-2026-33333"},
	}
	for usn, w := range want {
		if strings.Join(got[usn], ",") != strings.Join(w, ",") {
			t.Errorf("%s: CVEs %q, want %q", usn, got[usn], w)
		}
	}
}
