package osvdistro

import (
	"archive/zip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// zipFixture packs testdata/feeds/osv/<vendor>/*.json into an all.zip so the
// archive path of ParseFile is exercised exactly as after a download.
func zipFixture(t *testing.T, vendor string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("../../../testdata/feeds/osv", vendor, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures for %s: %v", vendor, err)
	}
	sort.Strings(files)
	out := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.Create(filepath.Base(p))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return out
}

func parseVendor(t *testing.T, vendor string, releases ...string) *ParseResult {
	t.Helper()
	set := map[string]bool{}
	for _, r := range releases {
		set[r] = true
	}
	res, err := ParseFile(zipFixture(t, vendor), Distros[vendor], set, rules.FeedSourceMetadata{RawObjectID: vendor + "/test/all.zip"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func find(res *ParseResult, pred func(r rules.PackageVulnerabilityRule) bool) []rules.PackageVulnerabilityRule {
	var out []rules.PackageVulnerabilityRule
	for _, r := range res.Rules {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func TestEcosystemReleaseMapping(t *testing.T) {
	cases := []struct {
		vendor, eco, want string
		ok                bool
	}{
		{"rocky", "Rocky Linux:9", "9", true},
		{"rocky", "Rocky Linux:8", "8", true},
		{"rocky", "AlmaLinux:9", "", false},
		{"almalinux", "AlmaLinux:8", "8", true},
		{"rhel", "Red Hat:enterprise_linux:9::baseos", "9", true},
		{"rhel", "Red Hat:enterprise_linux:8::appstream", "8", true},
		{"rhel", "Red Hat:rhel_eus:9.2::baseos", "", false},
		{"rhel", "Red Hat:enterprise_linux:10.2", "", false},
		{"opensuse", "openSUSE:Leap 15.6", "15.6", true},
		{"opensuse", "openSUSE:Tumbleweed", "", false},
		{"opensuse", "SUSE:Linux Enterprise Server 15 SP6-LTSS", "", false},
	}
	for _, c := range cases {
		got, ok := Distros[c.vendor].Release(c.eco)
		if got != c.want || ok != c.ok {
			t.Errorf("%s %q -> %q %v, want %q %v", c.vendor, c.eco, got, ok, c.want, c.ok)
		}
	}
}

func TestRockySourceRules(t *testing.T) {
	res := parseVendor(t, "rocky", "8", "9")
	if strings.Join(res.Releases, ",") != "8,9" {
		t.Fatalf("releases=%v (Rocky 10 must be filtered)", res.Releases)
	}
	ssl := find(res, func(r rules.PackageVulnerabilityRule) bool { return r.SourcePackage == "openssl" && r.Release == "9" })
	if len(ssl) != 2 {
		t.Fatalf("rocky 9 openssl rules=%d", len(ssl))
	}
	for _, r := range ssl {
		if r.PackageName != "" || r.Ecosystem != "rpm" || r.Comparator != "rpm" || r.Distribution != "rocky" || r.Status != rules.StatusReleased {
			t.Errorf("unexpected rule %+v", r)
		}
		if len(r.AdvisoryIDs) != 1 || !strings.HasPrefix(r.AdvisoryIDs[0], "RLSA-") {
			t.Errorf("advisory ids %v", r.AdvisoryIDs)
		}
	}
	if res.Metrics.RejectionReasons["advisory_without_cve"] != 1 {
		t.Errorf("bug-fix errata without CVE must be rejected: %v", res.Metrics.RejectionReasons)
	}
	if got := find(res, func(r rules.PackageVulnerabilityRule) bool { return r.CVEID == "CVE-2023-0286" }); len(got) != 1 || got[0].Urgency != "important" {
		t.Errorf("urgency from summary: %+v", got)
	}
}

func TestAlmaBinaryRules(t *testing.T) {
	res := parseVendor(t, "almalinux", "8", "9")
	libs := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return r.PackageName == "openssl-libs" && r.Release == "8"
	})
	if len(libs) != 1 || libs[0].FixedVersion != "1:1.1.1k-12.el8_9" || libs[0].SourcePackage != "" {
		t.Fatalf("alma openssl-libs rules=%+v", libs)
	}
	if got := find(res, func(r rules.PackageVulnerabilityRule) bool { return strings.HasSuffix(r.PackageName, "-debuginfo") }); len(got) != 0 {
		t.Errorf("debuginfo packages must be skipped: %d", len(got))
	}
	node := find(res, func(r rules.PackageVulnerabilityRule) bool { return r.PackageName == "nodejs" })
	if len(node) != 2 {
		t.Errorf("both module streams must produce rules: %d", len(node))
	}
}

func TestRHELMainlineOnly(t *testing.T) {
	res := parseVendor(t, "rhel", "8", "9")
	libs9 := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return r.PackageName == "openssl-libs" && r.Release == "9"
	})
	if len(libs9) != 1 {
		t.Fatalf("baseos+appstream must dedupe and EUS must be skipped: %+v", libs9)
	}
	if libs9[0].FixedVersion != "1:3.0.7-27.el9" {
		t.Errorf("fixed=%q", libs9[0].FixedVersion)
	}
	libs8 := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return r.PackageName == "openssl-libs" && r.Release == "8"
	})
	if len(libs8) != 1 || libs8[0].FixedVersion != "1:1.1.1k-12.el8_9" {
		t.Errorf("rhel 8 rule=%+v", libs8)
	}
	for _, r := range res.Rules {
		if r.Distribution != "rhel" || r.Vendor != "rhel" {
			t.Errorf("rule %s distribution %q", r.RuleID, r.Distribution)
		}
	}
}

func TestOpenSUSEBinariesAndRanges(t *testing.T) {
	res := parseVendor(t, "opensuse", "15.5", "15.6")
	// Every binary shares the fixed version: one source-level rule per CVE.
	src := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return r.Release == "15.6" && r.SourcePackage == "openssl-3"
	})
	if len(src) != 2 {
		t.Fatalf("openssl-3 rules=%+v", src)
	}
	for _, r := range src {
		if r.PackageName != "" || r.FixedVersion != "3.1.4-150600.5.15.1" {
			t.Errorf("uniform binaries must collapse to a source rule: %+v", r)
		}
	}
	// A binary with its own version keeps per-binary rules for all binaries.
	glib := find(res, func(r rules.PackageVulnerabilityRule) bool { return r.SourcePackage == "glib2" })
	var names []string
	for _, r := range glib {
		names = append(names, r.PackageName+"="+r.FixedVersion)
	}
	sort.Strings(names)
	want := "gio-branding-upstream=1.0-150600.4.3.1,glib2-tools=2.78.6-150600.4.3.1,libglib-2_0-0=2.78.6-150600.4.3.1"
	if strings.Join(names, ",") != want {
		t.Fatalf("glib2 rules=%v", names)
	}
	leap155 := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return r.Release == "15.5" && r.SourcePackage == "openssl-3"
	})
	if len(leap155) != 2 || leap155[0].FixedVersion != "3.0.8-150500.5.30.1" {
		t.Errorf("leap 15.5 rules=%+v", leap155)
	}
	rng := find(res, func(r rules.PackageVulnerabilityRule) bool { return r.SourcePackage == "demo-range" })
	if len(rng) != 1 || rng[0].IntroducedVersion != "2.0-150600.1.1" {
		t.Errorf("introduced must be kept: %+v", rng)
	}
	if res.Metrics.RejectionReasons["withdrawn"] != 1 {
		t.Errorf("withdrawn advisories must be rejected: %v", res.Metrics.RejectionReasons)
	}
	if got := find(res, func(r rules.PackageVulnerabilityRule) bool {
		return strings.Contains(r.RawStatus, "SUSE:Linux Enterprise")
	}); len(got) != 0 {
		t.Errorf("SLES module entries must be skipped: %d", len(got))
	}
}

func TestIntervals(t *testing.T) {
	ivs := intervals([]osvEvent{{Introduced: "0"}, {Fixed: "1.2-1"}, {Introduced: "2.0-1"}, {Fixed: "2.3-1"}, {Introduced: "3.0-1"}})
	if len(ivs) != 3 {
		t.Fatalf("intervals=%+v", ivs)
	}
	if ivs[0].introduced != "" || ivs[0].fixed != "1.2-1" || ivs[1].introduced != "2.0-1" || ivs[1].fixed != "2.3-1" || ivs[2].fixed != "" {
		t.Errorf("intervals=%+v", ivs)
	}
}

func TestPublishPerRelease(t *testing.T) {
	res := parseVendor(t, "rocky", "8", "9")
	store := rules.NewStore(t.TempDir())
	if err := Publish(store, Distros["rocky"], res, rules.FeedSourceMetadata{SourceName: "osv-rocky"}); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"8", "9"} {
		list, err := store.LoadRules("rocky", rel)
		if err != nil || len(list) == 0 {
			t.Errorf("rocky/%s: %d rules, err %v", rel, len(list), err)
		}
	}
}
