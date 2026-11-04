package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
)

const sampleNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="192.0.2.10">
      <HostProperties>
        <tag name="operating-system">Linux Kernel 6.8 on Ubuntu 22.04</tag>
      </HostProperties>
      <ReportItem pluginID="1001" pluginName="USN-7278-1: OpenSSL" pluginFamily="Ubuntu Local Security Checks" severity="2" port="0">
        <risk_factor>Medium</risk_factor>
        <cve>CVE-2024-13176</cve>
        <cve>CVE-2024-2511</cve>
      </ReportItem>
      <ReportItem pluginID="1002" pluginName="USN-6859-1: OpenSSH" pluginFamily="Ubuntu Local Security Checks" severity="4" port="0">
        <risk_factor>Critical</risk_factor>
        <cve>CVE-2024-6387</cve>
      </ReportItem>
      <ReportItem pluginID="1003" pluginName="cups busybox thing" pluginFamily="Ubuntu Local Security Checks" severity="3" port="0">
        <risk_factor>High</risk_factor>
        <cve>CVE-2099-0001</cve>
      </ReportItem>
      <ReportItem pluginID="2000" pluginName="Remote banner" pluginFamily="General" severity="1" port="631">
        <risk_factor>Low</risk_factor>
        <cve>CVE-2099-9999</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func writeFindings(t *testing.T, dir string) string {
	t.Helper()
	doc := findingsDoc{
		AssetID: "9a205c4f2ab2d87a",
		Findings: []findings.Finding{
			// Agreement: both vulnerable, host scope.
			{CVEID: "CVE-2024-13176", Scope: "host", State: findings.StateVulnerable, DetectionMethod: "ubuntu_source_package_fixed_version"},
			{CVEID: "CVE-2024-6387", Scope: "host", State: findings.StateVulnerableRuntime, DetectionMethod: "ubuntu_source_package_fixed_version"},
			// Only resolver, kernel.
			{CVEID: "CVE-2025-21709", Scope: "host", State: findings.StateVulnerable, DetectionMethod: "ubuntu_running_kernel_fixed_version"},
			// Resolver decided fixed; Nessus flags CVE-2024-2511 -> nessus_flagged_resolver_fixed.
			{CVEID: "CVE-2024-2511", Scope: "host", State: findings.StateFixed, DetectionMethod: "ubuntu_source_package_fixed_version"},
			// Container-only vuln matching a nessus CVE -> scope mismatch bucket.
			{CVEID: "CVE-2099-0001", Scope: "container", State: findings.StateVulnerable, DetectionMethod: "alpine_branch_package_fixed_version"},
		},
	}
	raw, _ := json.Marshal(doc)
	p := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseNessus(t *testing.T) {
	nr, err := ParseNessus(strings.NewReader(sampleNessus), "")
	if err != nil {
		t.Fatal(err)
	}
	if nr.Host != "192.0.2.10" || !nr.LocalChecksPresent {
		t.Errorf("host/local checks wrong: %+v", nr)
	}
	if !strings.Contains(nr.OSInfo, "Ubuntu 22.04") {
		t.Errorf("os info=%q", nr.OSInfo)
	}
	// Severity taken as the strongest signal (attr vs risk_factor).
	if nr.CVEs["CVE-2024-6387"].MaxSeverity != 4 {
		t.Errorf("severity=%d", nr.CVEs["CVE-2024-6387"].MaxSeverity)
	}
	// The General-family remote banner CVE is not a local check.
	if nr.CVEs["CVE-2099-9999"].LocalCheck {
		t.Error("remote banner CVE must not be a local check")
	}
	local := nr.CVESet(true)
	if containsStr(local, "CVE-2099-9999") {
		t.Errorf("local-only set must exclude remote CVE: %v", local)
	}
	if !containsStr(local, "CVE-2024-13176") {
		t.Errorf("local set missing package CVE: %v", local)
	}
}

func TestCompareDiff(t *testing.T) {
	dir := t.TempDir()
	fp := writeFindings(t, dir)
	rv, err := LoadResolverView(fp)
	if err != nil {
		t.Fatal(err)
	}
	nr, _ := ParseNessus(strings.NewReader(sampleNessus), "")
	d := Compare(rv, nr, true)

	if got := d.Counts["agreement"]; got != 2 {
		t.Errorf("agreement=%d, want 2 (13176, 6387)", got)
	}
	if !containsStr(d.OnlyResolver, "CVE-2025-21709") || !containsStr(d.OnlyResolverKernel, "CVE-2025-21709") {
		t.Errorf("kernel-only-resolver missing: %+v", d)
	}
	if !containsStr(d.NessusVsResolverFixed, "CVE-2024-2511") {
		t.Errorf("nessus-flagged-resolver-fixed must contain CVE-2024-2511: %v", d.NessusVsResolverFixed)
	}
	if !containsStr(d.NessusMatchedContainerOnly, "CVE-2099-0001") {
		t.Errorf("container-scope match missing: %v", d.NessusMatchedContainerOnly)
	}
	// The remote-only CVE must not appear anywhere in a local-only compare.
	if containsStr(d.OnlyNessus, "CVE-2099-9999") {
		t.Errorf("remote CVE leaked into local-only diff: %v", d.OnlyNessus)
	}
}

func TestCompareUncredentialedWarning(t *testing.T) {
	uncred := strings.ReplaceAll(sampleNessus, "Ubuntu Local Security Checks", "General")
	nr, err := ParseNessus(strings.NewReader(uncred), "")
	if err != nil {
		t.Fatal(err)
	}
	if nr.LocalChecksPresent {
		t.Error("no local checks should be detected in an uncredentialed report")
	}
	// local-only comparison yields an empty nessus set.
	if len(nr.CVESet(true)) != 0 {
		t.Errorf("local-only set must be empty: %v", nr.CVESet(true))
	}
}
