package msrc

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

func TestParseSampleOct2026(t *testing.T) {
	res, err := ParseFile("testdata/2026-Oct-sample.json", rules.FeedSourceMetadata{RawObjectID: "raw/microsoft/test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Month != "2026-Oct" {
		t.Fatalf("month %q", res.Month)
	}
	want := map[string]bool{"windows_server_2022": true, "windows_server_2025": true, "windows_11_24h2": true, "windows_11_25h2": true, "windows_10_22h2": true, "windows_server_2019": true}
	for _, p := range res.Products {
		if !want[p] {
			t.Errorf("unexpected product %s", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing products %v", want)
	}
	if res.Metrics.CVEsSeen != 3 {
		t.Fatalf("cves %d", res.Metrics.CVEsSeen)
	}

	byID := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range res.Rules {
		byID[r.RuleID] = r
	}
	// Server 2022 full install, CVE-2026-100201: KB5126655 fixes at 20348.5761.
	r, ok := byID["msrc:CVE-2026-100201:11923:KB5126655"]
	if !ok {
		t.Fatalf("rule missing; have %d rules", len(res.Rules))
	}
	if r.Ecosystem != "winbuild" || r.Comparator != "winbuild" || r.Distribution != "windows" || r.Release != "windows_server_2022" {
		t.Fatalf("identity %+v", r)
	}
	if r.FixedVersion != "20348.5761" || r.PackageName != "windows" || r.Architecture != "" {
		t.Fatalf("fixed/pkg/arch %+v", r)
	}
	if len(r.AdvisoryIDs) != 1 || r.AdvisoryIDs[0] != "KB5126655" || len(r.Supersedes) != 1 || r.Supersedes[0] != "KB5122882" {
		t.Fatalf("kb %v supersedes %v", r.AdvisoryIDs, r.Supersedes)
	}
	if !r.RestartRequired || r.Status != rules.StatusReleased || r.RawStatus != "Security Update" {
		t.Fatalf("restart/status %+v", r)
	}
	if r.Urgency != "important" {
		t.Fatalf("urgency %q", r.Urgency)
	}
	// Win11 24H2 x64 and Server 2025 share build 26100 but have different UBR streams.
	w11 := byID["msrc:CVE-2026-100200:12390:KB5127648"]
	srv := byID["msrc:CVE-2026-100200:12436:KB5126646"]
	if w11.FixedVersion != "26100.9711" || w11.Architecture != "amd64" || w11.Release != "windows_11_24h2" {
		t.Fatalf("win11 %+v", w11)
	}
	if srv.FixedVersion != "26100.33650" || srv.Release != "windows_server_2025" {
		t.Fatalf("srv2025 %+v", srv)
	}
	if byID["msrc:CVE-2026-100200:12389:KB5127648"].Architecture != "arm64" {
		t.Fatal("arm64 product must carry arm64 arch")
	}
	if r.PublishedAt == nil || r.UpdatedAt == nil {
		t.Fatal("dates")
	}
}

func TestWindowsProductFromCPE(t *testing.T) {
	cases := map[string][2]string{
		"cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*":                {"windows_server_2022", ""},
		"cpe:2.3:o:microsoft:windows_11_24H2:*:*:*:*:*:*:x64:*":                  {"windows_11_24h2", "amd64"},
		"cpe:2.3:o:microsoft:windows_10_22H2:*:*:*:*:*:*:x86:*":                  {"windows_10_22h2", "386"},
		"cpe:2.3:a:microsoft:.net:4.8:*:*:*:*:*:*:*":                             {"", ""},
		"cpe:2.3:a:microsoft:azl3_httpd_2.4.68-1:*:*:*:*:*:*:*:*":                {"", ""},
		"cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.26434:*:*:*:*:*:x64:*": {"windows_server_2012", "amd64"},
	}
	for cpe, want := range cases {
		key, arch, ok := windowsProductFromCPE(cpe)
		if (want[0] == "") == ok || key != want[0] || arch != want[1] {
			t.Errorf("%s: got (%q,%q,%v) want %v", cpe, key, arch, ok, want)
		}
	}
}

func TestMergeRulesNewerWins(t *testing.T) {
	old := []rules.PackageVulnerabilityRule{{RuleID: "a", FixedVersion: "1.1"}, {RuleID: "b", FixedVersion: "1.1"}}
	fresh := []rules.PackageVulnerabilityRule{{RuleID: "b", FixedVersion: "1.2"}, {RuleID: "c", FixedVersion: "1.0"}}
	got := MergeRules(old, fresh)
	if len(got) != 3 || got[1].RuleID != "b" || got[1].FixedVersion != "1.2" {
		t.Fatalf("%+v", got)
	}
}

func TestParseFixupsAndNonOSBuilds(t *testing.T) {
	doc := `{
 "DocumentTracking": {"Identification": {"ID": {"Value": "2025-Dec"}}, "CurrentReleaseDate": "2025-12-09T08:00:00Z"},
 "ProductTree": {"FullProductName": [
  {"ProductID": "20438", "CPE": "cpe:2.3:o:microsoft:windows_11_2H2:10.0.26200.7462:*:*:*:*:*:x64:*", "Value": "Windows 11 Version 25H2 for x64-based Systems"},
  {"ProductID": "10378", "CPE": "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.25815:*:*:*:*:*:x64:*", "Value": "Windows Server 2012"}
 ]},
 "Vulnerability": [{"CVE": "CVE-2025-000001", "ReleaseDate": "0001-01-01T00:00:00", "Remediations": [
  {"Type": 2, "SubType": "Security Update", "FixedBuild": "10.0.26200.7462", "Description": {"Value": "5072033"}, "ProductID": ["20438"]},
  {"Type": 2, "SubType": "IE Cumulative", "FixedBuild": "1.003", "Description": {"Value": "5049994"}, "ProductID": ["10378"]},
  {"Type": 2, "SubType": "Monthly Rollup", "FixedBuild": "6.2.9200.25815", "Description": {"Value": "5072000"}, "ProductID": ["10378"]}
 ]}]
}`
	res, err := Parse(strings.NewReader(doc), rules.FeedSourceMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Products, ",") != "windows_11_25h2,windows_server_2012" {
		t.Fatalf("products %v", res.Products)
	}
	if len(res.Rules) != 2 || res.Skipped["non_os_fixed_build"] != 1 {
		t.Fatalf("rules %d skipped %v", len(res.Rules), res.Skipped)
	}
	for _, r := range res.Rules {
		if r.PublishedAt == nil || r.PublishedAt.Year() != 2025 {
			t.Fatalf("0001-01-01 release date must fall back to the document date: %v", r.PublishedAt)
		}
	}
	if fixupProductKey("windows_11_2h2", "Windows 11 Version 24H2 for x64-based Systems") != "windows_11_2h2" {
		t.Fatal("a fixup must only apply when the product name confirms it")
	}
}
