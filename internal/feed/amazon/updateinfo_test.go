package amazon

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// sample is a trimmed copy of the AL2023 updateinfo.xml structure.
const sample = `<?xml version="1.0" ?>
<updates>
<update status="final" version="1.4" author="linux-security@amazon.com" type="security" from="linux-security@amazon.com">
 <id>ALAS2023-2024-512</id>
 <title>Amazon Linux 2023 - ALAS2023-2024-512: Important priority package update for openssl</title>
 <issued date="2024-02-15 21:23:00" />
 <severity>Important</severity>
 <references>
  <reference href="https://example.invalid" id="CVE-2024-0727" type="cve" />
  <reference href="https://example.invalid" id="CVE-2023-6237" type="cve" />
 </references>
 <pkglist><collection short="amazon-linux-2023"><name>Amazon Linux 2023</name>
  <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="aarch64"><filename>a</filename></package>
  <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="x86_64"><filename>a</filename></package>
  <package name="openssl-debuginfo" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="x86_64"><filename>a</filename></package>
  <package name="openssl" version="3.0.8" release="1.amzn2023.0.11" epoch="1" arch="src"><filename>a</filename></package>
 </collection></pkglist>
</update>
<update status="final" version="1.4" type="security">
 <id>ALAS2023-2024-600</id>
 <severity>Medium</severity>
 <references><reference id="CVE-2024-2004" type="cve" /></references>
 <pkglist><collection short="amazon-linux-2023">
  <package name="curl-minimal" version="8.5.0" release="1.amzn2023.0.3" epoch="0" arch="aarch64" />
  <package name="curl-minimal" version="8.5.0" release="1.amzn2023.0.4" epoch="0" arch="x86_64" />
 </collection></pkglist>
</update>
<update status="final" version="1.4" type="bugfix">
 <id>ALAS2023-2024-601</id>
 <references><reference id="CVE-2024-9999" type="cve" /></references>
 <pkglist><collection short="amazon-linux-2023">
  <package name="tzdata" version="2024a" release="1.amzn2023.0.1" epoch="0" arch="noarch" />
 </collection></pkglist>
</update>
<update status="final" version="1.4" type="security">
 <id>ALAS2023-2024-602</id>
 <references></references>
 <pkglist><collection short="amazon-linux-2023">
  <package name="vim-minimal" version="9.0" release="1.amzn2023" epoch="2" arch="aarch64" />
 </collection></pkglist>
</update>
<update status="final" version="1.4" type="security">
 <id>ALAS2-2024-700</id>
 <references><reference id="CVE-2024-7000" type="cve" /></references>
 <pkglist><collection short="amazon-linux-2">
  <package name="bash" version="4.2.46" release="34.amzn2" epoch="0" arch="aarch64" />
 </collection></pkglist>
</update>
</updates>`

func parseSample(t *testing.T, data []byte) *ParseResult {
	t.Helper()
	res, err := Parse(bytes.NewReader(data), "2023", rules.FeedSourceMetadata{RawObjectID: "amazon/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ruleFor(res *ParseResult, name, cve, arch string) *rules.PackageVulnerabilityRule {
	for i := range res.Rules {
		r := &res.Rules[i]
		if r.PackageName == name && r.CVEID == cve && r.Architecture == arch {
			return r
		}
	}
	return nil
}

func TestParseUpdateinfo(t *testing.T) {
	res := parseSample(t, []byte(sample))

	r := ruleFor(res, "openssl-libs", "CVE-2024-0727", "")
	if r == nil {
		t.Fatalf("no arch-free openssl-libs rule: %+v", res.Rules)
	}
	if r.FixedVersion != "1:3.0.8-1.amzn2023.0.11" || r.Status != rules.StatusReleased || r.Comparator != "rpm" {
		t.Errorf("rule=%+v", r)
	}
	if r.Distribution != "amazon" || r.Release != "2023" || r.SourcePackage != "" || r.Urgency != "important" {
		t.Errorf("identity=%s/%s src=%q urgency=%q", r.Distribution, r.Release, r.SourcePackage, r.Urgency)
	}
	if len(r.AdvisoryIDs) != 1 || r.AdvisoryIDs[0] != "ALAS2023-2024-512" ||
		r.SourceURL != "https://alas.aws.amazon.com/AL2023/ALAS2023-2024-512.html" {
		t.Errorf("advisory=%v url=%s", r.AdvisoryIDs, r.SourceURL)
	}
	if r.PublishedAt == nil || r.PublishedAt.Format("2006-01-02") != "2024-02-15" {
		t.Errorf("published=%v", r.PublishedAt)
	}
	if ruleFor(res, "openssl-libs", "CVE-2023-6237", "") == nil {
		t.Error("every CVE of the advisory gets a rule")
	}
	// Debug packages and source rpms are not rules.
	for _, rr := range res.Rules {
		if rr.PackageName == "openssl-debuginfo" || rr.PackageName == "openssl" {
			t.Errorf("unexpected rule for %s", rr.PackageName)
		}
	}
	// Different fixed versions per architecture keep per-arch rules; epoch 0 is omitted.
	if a := ruleFor(res, "curl-minimal", "CVE-2024-2004", "aarch64"); a == nil || a.FixedVersion != "8.5.0-1.amzn2023.0.3" {
		t.Errorf("aarch64 rule=%+v", a)
	}
	if x := ruleFor(res, "curl-minimal", "CVE-2024-2004", "x86_64"); x == nil || x.FixedVersion != "8.5.0-1.amzn2023.0.4" {
		t.Errorf("x86_64 rule=%+v", x)
	}
	if ruleFor(res, "curl-minimal", "CVE-2024-2004", "") != nil {
		t.Error("diverging arch versions must not collapse into one rule")
	}
	// Non-security updates, advisories without a CVE and other releases'
	// collections produce nothing and are counted.
	for _, name := range []string{"tzdata", "vim-minimal", "bash"} {
		for _, rr := range res.Rules {
			if rr.PackageName == name {
				t.Errorf("unexpected rule for %s", name)
			}
		}
	}
	m := res.Metrics
	if m.RecordsParsed != 5 || m.RejectionReasons["non_security_update"] != 1 ||
		m.RejectionReasons["advisory_without_cve"] != 1 || m.RejectionReasons["foreign_collection"] != 1 {
		t.Errorf("metrics=%+v", m)
	}
	if len(res.Rules) != 4 || m.RulesGenerated != 4 {
		t.Errorf("rules=%d generated=%d", len(res.Rules), m.RulesGenerated)
	}
}

func TestParseUpdateinfoGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(sample))
	zw.Close()
	if res := parseSample(t, buf.Bytes()); len(res.Rules) != 4 {
		t.Errorf("gzip rules=%d", len(res.Rules))
	}
}

func TestParseUpdateinfoRelease2(t *testing.T) {
	res, err := Parse(strings.NewReader(sample), "2", rules.FeedSourceMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 || res.Rules[0].PackageName != "bash" || res.Rules[0].Release != "2" ||
		res.Rules[0].SourceURL != "https://alas.aws.amazon.com/AL2/ALAS2-2024-700.html" {
		t.Errorf("rules=%+v", res.Rules)
	}
	if _, err := Parse(strings.NewReader(sample), "2018", rules.FeedSourceMetadata{}); err == nil {
		t.Error("an unsupported release must be refused")
	}
}

func TestParseUpdateinfoMalformed(t *testing.T) {
	if _, err := Parse(strings.NewReader("<updates><update"), "2023", rules.FeedSourceMetadata{}); err == nil {
		t.Error("truncated XML must fail, not produce an empty rule set")
	}
}

func TestMirrorBase(t *testing.T) {
	got, err := MirrorBase("https://cdn.amazonlinux.com/al2023/core/guids/abc/x86_64\n")
	if err != nil || got != "https://cdn.amazonlinux.com/al2023/core/guids/abc/x86_64/" {
		t.Errorf("base=%q err=%v", got, err)
	}
	for _, bad := range []string{"", "http://cdn.amazonlinux.com/al2023/", "https://evil.example/al2023/", "file:///etc/passwd"} {
		if _, err := MirrorBase(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestUpdateinfoHref(t *testing.T) {
	md := `<repomd><data type="primary"><location href="repodata/primary.xml.gz"/></data>` +
		`<data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>`
	if got, err := UpdateinfoHref([]byte(md)); err != nil || got != "repodata/updateinfo.xml.gz" {
		t.Errorf("href=%q err=%v", got, err)
	}
	for _, href := range []string{"../../etc/passwd", "/abs/updateinfo.xml.gz", "https://evil.example/u.xml.gz"} {
		bad := `<repomd><data type="updateinfo"><location href="` + href + `"/></data></repomd>`
		if _, err := UpdateinfoHref([]byte(bad)); err == nil {
			t.Errorf("%q must be refused", href)
		}
	}
	if _, err := UpdateinfoHref([]byte(`<repomd></repomd>`)); err == nil {
		t.Error("missing updateinfo must fail")
	}
}
