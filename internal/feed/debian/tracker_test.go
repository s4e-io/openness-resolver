package debian

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

const fixture = "../../../testdata/feeds/debian/tracker-sample.json"

func parseFixture(t *testing.T, releases map[string]bool) *ParseResult {
	t.Helper()
	res, err := ParseFile(fixture, rules.FeedSourceMetadata{RawObjectID: "debian/test/json"}, releases)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ruleByID(res *ParseResult, id string) *rules.PackageVulnerabilityRule {
	for i := range res.Rules {
		if res.Rules[i].RuleID == id {
			return &res.Rules[i]
		}
	}
	return nil
}

func TestParseStatusMapping(t *testing.T) {
	res := parseFixture(t, map[string]bool{"bookworm": true, "trixie": true})
	cases := []struct {
		id, status, fixed string
	}{
		{"debian:bookworm:CVE-2024-0727:openssl", rules.StatusReleased, "3.0.13-1~deb12u1"},
		{"debian:trixie:CVE-2024-0727:openssl", rules.StatusReleased, "3.1.5-1"},
		{"debian:bookworm:CVE-2025-9230:openssl", rules.StatusNeeded, ""},
		{"debian:bookworm:CVE-2025-27587:openssl", rules.StatusNotAffected, ""},
		{"debian:trixie:CVE-2025-27587:openssl", rules.StatusIgnored, ""},
		{"debian:bookworm:CVE-2023-45853:zlib", rules.StatusIgnored, ""},
		{"debian:bookworm:CVE-2024-2398:curl", rules.StatusDeferred, ""},
		{"debian:bookworm:CVE-2022-3715:bash", rules.StatusUnknown, ""},
	}
	for _, c := range cases {
		r := ruleByID(res, c.id)
		if r == nil {
			t.Fatalf("missing rule %s", c.id)
		}
		if r.Status != c.status || r.FixedVersion != c.fixed {
			t.Errorf("%s: status=%s fixed=%q, want %s %q", c.id, r.Status, r.FixedVersion, c.status, c.fixed)
		}
		if r.Ecosystem != "dpkg" || r.Comparator != "dpkg" || r.Distribution != "debian" || r.PackageName != "" || r.SourcePackage == "" {
			t.Errorf("%s: identity %+v", c.id, r)
		}
		if r.RawStatus == "" {
			t.Errorf("%s: raw status must be preserved", c.id)
		}
	}
	if r := ruleByID(res, "debian:bookworm:CVE-2024-2398:curl"); r.VendorNotes == "" {
		t.Error("nodsa reason must be preserved in vendor notes")
	}
}

func TestParseReleaseFilter(t *testing.T) {
	res := parseFixture(t, map[string]bool{"bookworm": true, "trixie": true})
	if len(res.Releases) != 2 || res.Releases[0] != "bookworm" || res.Releases[1] != "trixie" {
		t.Fatalf("releases=%v", res.Releases)
	}
	for _, r := range res.Rules {
		if r.Release == "sid" || r.Release == "bullseye" {
			t.Fatalf("release %s must be filtered: %s", r.Release, r.RuleID)
		}
	}
	all := parseFixture(t, nil)
	if ruleByID(all, "debian:sid:CVE-2024-0727:openssl") == nil {
		t.Error("a nil release set keeps every codename")
	}
}

func TestParseRejectsPlaceholders(t *testing.T) {
	res := parseFixture(t, map[string]bool{"bookworm": true})
	if res.Metrics.RejectionReasons["non_cve_identifier"] != 1 {
		t.Errorf("rejections=%v", res.Metrics.RejectionReasons)
	}
	for _, r := range res.Rules {
		if r.CVEID == "" || r.CVEID[:4] != "CVE-" {
			t.Errorf("non-CVE rule %s", r.RuleID)
		}
	}
}

func TestPublishPerRelease(t *testing.T) {
	res := parseFixture(t, map[string]bool{"bookworm": true, "trixie": true})
	store := rules.NewStore(t.TempDir())
	if err := Publish(store, res, rules.FeedSourceMetadata{SourceName: "debian-security-tracker"}); err != nil {
		t.Fatal(err)
	}
	rs, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rs.ForSourcePackage("dpkg", "debian", "bookworm", "openssl")); got != 4 {
		t.Errorf("bookworm openssl rules=%d, want 4", got)
	}
	if got := len(rs.ForSourcePackage("dpkg", "debian", "trixie", "openssl")); got != 4 {
		t.Errorf("trixie openssl rules=%d, want 4", got)
	}
}
