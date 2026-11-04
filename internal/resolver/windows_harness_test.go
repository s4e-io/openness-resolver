package resolver_test

// Differential test harness for Windows OS resolution.
//
// testdata/msrc holds real MSRC CVRF monthly documents (January 2023 to
// October 2026) trimmed to a handful of CVEs per product by
// testdata/msrc/trim.py. The production path (msrc.Parse -> rules ->
// platform.ResolveWindowsProduct -> resolver) is run against synthetic hosts
// in the collector's os_inventory shape, at many patch levels per product,
// and its vulnerable CVE set is compared with a deliberately simple oracle
// that reads the same CVRF JSON on its own: it selects products by MSRC
// product name (not CPE), parses FixedBuild itself and applies the rules
// below without calling any resolver, platform or winbuild code.
//
// Oracle rules (the specification):
//   - a CVE applies when a Vendor Fix (Type 2) lists a product whose name is
//     the host's MSRC product name (Server Core and Desktop Experience are
//     the same product) and whose architecture is the host's or unspecified;
//   - the fixed build must be on the host's servicing branch; enablement
//     package builds share one branch (19041-19045, 22621/22631, 26100/26200);
//   - fixed builds below 6000 are component versions (IE Cumulative), not OS
//     builds, and are ignored;
//   - a host whose UBR equals a hotpatch fixed build (and no regular one) is
//     hotpatch enrolled: for a CVE with a hotpatch fix only hotpatch fixes
//     count, otherwise only regular fixes count;
//   - the host is vulnerable when its UBR is below the highest counted fix.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/feed/msrc"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

const harnessDir = "testdata/msrc"

// harnessMonths is the fixture order, oldest first.
var harnessMonths = []string{"2023-Jan", "2023-Oct", "2023-Dec", "2024-Oct", "2025-Dec", "2026-Jul", "2026-Aug", "2026-Sep", "2026-Oct"}

// winHost is one synthetic Windows host as the collector reports it.
type winHost struct {
	id          string
	msrcName    string // MSRC product name without arch / Server Core suffix (oracle input)
	build       int
	arch        string
	productName string // Win32_OperatingSystem.Caption
	productType int    // 1 workstation, 2 domain controller, 3 server
	installType string // registry InstallationType
	display     string // registry DisplayVersion
	wantKey     string // MSRC product key the resolver must pick
}

var harnessHosts = []winHost{
	{"srv2008", "windows server 2008", 6003, "amd64", "Microsoft Windows Server 2008 Standard", 3, "Server", "", "windows_server_2008_sp2"},
	{"srv2008r2", "windows server 2008 r2", 7601, "amd64", "Microsoft Windows Server 2008 R2 Standard", 3, "Server", "", "windows_server_2008_r2"},
	{"srv2012", "windows server 2012", 9200, "amd64", "Microsoft Windows Server 2012 Standard", 3, "Server", "", "windows_server_2012"},
	{"srv2012-core", "windows server 2012", 9200, "amd64", "Microsoft Windows Server 2012 Datacenter", 3, "Server Core", "", "windows_server_2012"},
	{"srv2012r2", "windows server 2012 r2", 9600, "amd64", "Microsoft Windows Server 2012 R2 Standard", 3, "Server", "", "windows_server_2012_r2"},
	{"srv2016", "windows server 2016", 14393, "amd64", "Microsoft Windows Server 2016 Standard", 3, "Server", "", "windows_server_2016"},
	{"srv2019", "windows server 2019", 17763, "amd64", "Microsoft Windows Server 2019 Datacenter", 3, "Server", "1809", "windows_server_2019"},
	{"srv2019-core", "windows server 2019", 17763, "amd64", "Microsoft Windows Server 2019 Datacenter", 3, "Server Core", "1809", "windows_server_2019"},
	{"srv2022", "windows server 2022", 20348, "amd64", "Microsoft Windows Server 2022 Datacenter", 3, "Server", "21H2", "windows_server_2022"},
	{"srv2022-core", "windows server 2022", 20348, "amd64", "Microsoft Windows Server 2022 Datacenter", 3, "Server Core", "21H2", "windows_server_2022"},
	{"srv2022-dc", "windows server 2022", 20348, "amd64", "Microsoft Windows Server 2022 Standard", 2, "Server", "21H2", "windows_server_2022"},
	{"srv23h2-core", "windows server 2022, 23h2 edition", 25398, "amd64", "Microsoft Windows Server Datacenter", 3, "Server Core", "23H2", "windows_server_23h2"},
	{"srv2025", "windows server 2025", 26100, "amd64", "Microsoft Windows Server 2025 Datacenter", 3, "Server", "24H2", "windows_server_2025"},
	{"srv2025-core", "windows server 2025", 26100, "amd64", "Microsoft Windows Server 2025 Datacenter", 3, "Server Core", "24H2", "windows_server_2025"},
	{"srv2025-dc", "windows server 2025", 26100, "amd64", "Microsoft Windows Server 2025 Standard", 2, "Server", "24H2", "windows_server_2025"},
	{"win10-1507", "windows 10", 10240, "amd64", "Microsoft Windows 10 Enterprise 2015 LTSB", 1, "Client", "", "windows_10_1507"},
	{"win10-1607", "windows 10 version 1607", 14393, "amd64", "Microsoft Windows 10 Enterprise 2016 LTSB", 1, "Client", "", "windows_10_1607"},
	{"win10-1809", "windows 10 version 1809", 17763, "amd64", "Microsoft Windows 10 Enterprise LTSC 2019", 1, "Client", "", "windows_10_1809"},
	{"win10-20h2", "windows 10 version 20h2", 19042, "arm64", "Microsoft Windows 10 Pro", 1, "Client", "20H2", "windows_10_20h2"},
	{"win10-21h1", "windows 10 version 21h1", 19043, "amd64", "Microsoft Windows 10 Pro", 1, "Client", "21H1", "windows_10_21h1"},
	{"win10-21h2", "windows 10 version 21h2", 19044, "amd64", "Microsoft Windows 10 Enterprise LTSC 2021", 1, "Client", "21H2", "windows_10_21h2"},
	{"win10-22h2", "windows 10 version 22h2", 19045, "amd64", "Microsoft Windows 10 Pro", 1, "Client", "22H2", "windows_10_22h2"},
	{"win11-21h2", "windows 11 version 21h2", 22000, "amd64", "Microsoft Windows 11 Enterprise", 1, "Client", "21H2", "windows_11_21h2"},
	{"win11-22h2", "windows 11 version 22h2", 22621, "amd64", "Microsoft Windows 11 Pro", 1, "Client", "22H2", "windows_11_22h2"},
	{"win11-23h2", "windows 11 version 23h2", 22631, "amd64", "Microsoft Windows 11 Pro", 1, "Client", "23H2", "windows_11_23h2"},
	{"win11-24h2", "windows 11 version 24h2", 26100, "amd64", "Microsoft Windows 11 Pro", 1, "Client", "24H2", "windows_11_24h2"},
	{"win11-24h2-arm", "windows 11 version 24h2", 26100, "arm64", "Microsoft Windows 11 Pro", 1, "Client", "24H2", "windows_11_24h2"},
	{"win11-25h2", "windows 11 version 25h2", 26200, "amd64", "Microsoft Windows 11 Enterprise", 1, "Client", "25H2", "windows_11_25h2"},
	{"win11-26h1", "windows 11 version 26h1", 28000, "amd64", "Microsoft Windows 11 Pro", 1, "Client", "26H1", "windows_11_26h1"},
}

// harnessUnmapped lists product keys present in the fixtures that must not
// map from a host build (end of servicing before the feed window).
var harnessUnmapped = map[string]bool{"windows_7": true, "windows_8.1": true}

func (h winHost) doc(ubr any) *tf.Doc {
	os := map[string]any{
		"product_name":      h.productName,
		"build_number":      strconv.Itoa(h.build),
		"ubr":               ubr,
		"os_build":          fmt.Sprintf("%d.%v", h.build, ubr),
		"product_type":      h.productType,
		"installation_type": h.installType,
		"architecture":      h.arch,
		"display_version":   h.display,
		"version_id":        h.display,
	}
	if ubr == nil {
		os["os_build"] = strconv.Itoa(h.build)
	}
	return tf.NewWindowsServer2022("0").SetOS(os)
}

// --- production side ---

var harnessRuleSet *rules.RuleSet

func loadHarnessRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	if harnessRuleSet != nil {
		return harnessRuleSet
	}
	var all []rules.PackageVulnerabilityRule
	for _, m := range harnessMonths {
		res, err := msrc.ParseFile(filepath.Join(harnessDir, m+".json"), rules.FeedSourceMetadata{RawObjectID: "test/microsoft/" + m})
		if err != nil {
			t.Fatalf("parse %s: %v", m, err)
		}
		if res.Month != m {
			t.Fatalf("fixture %s carries month %q", m, res.Month)
		}
		all = msrc.MergeRules(all, res.Rules)
	}
	rs := &rules.RuleSet{Rules: all}
	rs.Reindex()
	harnessRuleSet = rs
	return rs
}

func resolveHost(t *testing.T, h winHost, ubr any) *resolver.RunResult {
	t.Helper()
	lr, err := h.doc(ubr).Load()
	if err != nil {
		t.Fatalf("%s: load evidence: %v", h.id, err)
	}
	res, err := resolver.NewEngine(loadHarnessRules(t)).Resolve(lr)
	if err != nil {
		t.Fatalf("%s: resolve: %v", h.id, err)
	}
	return res
}

func vulnerableSet(t *testing.T, h winHost, res *resolver.RunResult) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range res.Findings {
		if f.DetectionMethod != resolver.MethodMSRCFixedBuild {
			continue
		}
		switch f.State {
		case findings.StateVulnerable:
			out[f.CVEID] = true
		case findings.StateFixed, findings.StateNotApplicable:
		default:
			t.Errorf("%s: finding %s has state %s: %v", h.id, f.CVEID, f.State, f.Reasons)
		}
	}
	return out
}

// --- oracle side (no production code below this line) ---

type oracleRow struct {
	month    string
	cve      string
	name     string
	arch     string
	build    int
	ubr      int
	hotpatch bool
}

var oracleRows []oracleRow

func loadOracle(t *testing.T) []oracleRow {
	t.Helper()
	if oracleRows != nil {
		return oracleRows
	}
	var doc struct {
		ProductTree struct {
			FullProductName []struct {
				ProductID string
				Value     string
			}
		}
		Vulnerability []struct {
			CVE          string
			Remediations []struct {
				Type       int
				SubType    string
				FixedBuild string
				ProductID  []string
			}
		}
	}
	var out []oracleRow
	for _, m := range harnessMonths {
		data, err := os.ReadFile(filepath.Join(harnessDir, m+".json"))
		if err != nil {
			t.Fatal(err)
		}
		doc.ProductTree.FullProductName = nil
		doc.Vulnerability = nil
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		names := map[string][2]string{}
		for _, p := range doc.ProductTree.FullProductName {
			n, a := oracleProductName(p.Value)
			names[p.ProductID] = [2]string{n, a}
		}
		for _, v := range doc.Vulnerability {
			for _, r := range v.Remediations {
				if r.Type != 2 {
					continue
				}
				parts := strings.Split(strings.TrimSpace(r.FixedBuild), ".")
				if len(parts) < 2 {
					continue
				}
				b, err1 := strconv.Atoi(parts[len(parts)-2])
				u, err2 := strconv.Atoi(parts[len(parts)-1])
				if err1 != nil || err2 != nil || b < 6000 {
					continue
				}
				for _, pid := range r.ProductID {
					na, ok := names[pid]
					if !ok {
						continue
					}
					out = append(out, oracleRow{month: m, cve: v.CVE, name: na[0], arch: na[1], build: b, ubr: u,
						hotpatch: strings.Contains(strings.ToLower(r.SubType), "hotpatch")})
				}
			}
		}
	}
	oracleRows = out
	return out
}

// oracleProductName turns "Windows 10 Version 22H2 for x64-based Systems"
// into ("windows 10 version 22h2", "amd64").
func oracleProductName(value string) (string, string) {
	v := strings.ToLower(value)
	v = strings.ReplaceAll(v, " (server core installation)", "")
	arch := ""
	switch {
	case strings.Contains(v, "x64-based"):
		arch = "amd64"
	case strings.Contains(v, "arm64-based"):
		arch = "arm64"
	case strings.Contains(v, "32-bit"):
		arch = "386"
	}
	if i := strings.Index(v, " for "); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v), arch
}

func oracleBranch(build int) int {
	switch {
	case build >= 19041 && build <= 19045:
		return 19041
	case build == 22621 || build == 22631:
		return 22621
	case build == 26100 || build == 26200:
		return 26100
	}
	return build
}

// hostRows returns the oracle rows that concern host h at all.
func hostRows(t *testing.T, h winHost) []oracleRow {
	var out []oracleRow
	for _, r := range loadOracle(t) {
		if r.name == h.msrcName && (r.arch == "" || r.arch == h.arch) && oracleBranch(r.build) == oracleBranch(h.build) {
			out = append(out, r)
		}
	}
	return out
}

func oracleExpected(t *testing.T, h winHost, ubr int) map[string]bool {
	rows := hostRows(t, h)
	onHot, onRegular := false, false
	for _, r := range rows {
		if r.ubr == ubr {
			if r.hotpatch {
				onHot = true
			} else {
				onRegular = true
			}
		}
	}
	hotHost := onHot && !onRegular
	byCVE := map[string][]oracleRow{}
	for _, r := range rows {
		byCVE[r.cve] = append(byCVE[r.cve], r)
	}
	out := map[string]bool{}
	for cve, rs := range byCVE {
		hasHot := false
		for _, r := range rs {
			hasHot = hasHot || r.hotpatch
		}
		useHot := hotHost && hasHot
		maxFix := -1
		for _, r := range rs {
			if r.hotpatch == useHot && r.ubr > maxFix {
				maxFix = r.ubr
			}
		}
		if maxFix >= 0 && ubr < maxFix {
			out[cve] = true
		}
	}
	return out
}

// patchLevels derives the UBRs to test a host at from its own oracle rows.
func patchLevels(t *testing.T, h winHost) (levels map[string]int, sweep []int) {
	rows := hostRows(t, h)
	levels = map[string]int{"unpatched": 1}
	uniq := map[int]bool{1: true}
	byMonth := map[string]int{}
	minJan := -1
	maxAll := 0
	for _, r := range rows {
		uniq[r.ubr], uniq[r.ubr-1] = true, true
		if r.ubr > byMonth[r.month] {
			byMonth[r.month] = r.ubr
		}
		if r.ubr > maxAll {
			maxAll = r.ubr
		}
		if r.month == "2023-Jan" && (minJan < 0 || r.ubr < minJan) {
			minJan = r.ubr
		}
	}
	if maxAll > 0 {
		levels["patched"] = maxAll
	}
	if minJan > 0 {
		levels["jan2023"] = minJan - 1
	}
	var months []string
	for _, m := range harnessMonths {
		if _, ok := byMonth[m]; ok {
			months = append(months, m)
		}
	}
	if len(months) >= 2 {
		levels["one_month_behind"] = byMonth[months[len(months)-2]]
	}
	for u := range uniq {
		if u > 0 {
			sweep = append(sweep, u)
		}
	}
	sort.Ints(sweep)
	return levels, sweep
}

func setDiff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// --- tests ---

func TestWindowsHarnessEveryFixtureProductIsCovered(t *testing.T) {
	rs := loadHarnessRules(t)
	hosted := map[string]bool{}
	for _, h := range harnessHosts {
		hosted[h.wantKey] = true
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		seen[r.Release] = true
		if !hosted[r.Release] && !harnessUnmapped[r.Release] {
			t.Errorf("fixture product %s has rules but no harness host maps to it", r.Release)
		}
	}
	if seen["windows_11_2h2"] {
		t.Error("windows_11_2h2 (MSRC CPE typo for 25H2) must be folded into windows_11_25h2")
	}
	for _, r := range rs.Rules {
		if b, _ := strconv.Atoi(strings.Split(r.FixedVersion, ".")[0]); b < 6000 {
			t.Errorf("rule %s carries a non OS fixed build %s", r.RuleID, r.FixedVersion)
		}
	}
	for key := range hosted {
		if !seen[key] {
			t.Errorf("harness host product %s has no fixture rules", key)
		}
	}
}

func TestWindowsHarnessDifferential(t *testing.T) {
	combos, vulnerableCombos := 0, 0
	for _, h := range harnessHosts {
		levels, sweep := patchLevels(t, h)
		if len(sweep) < 3 {
			t.Errorf("%s: fixture gives only %d patch levels", h.id, len(sweep))
		}
		for _, ubr := range sweep {
			res := resolveHost(t, h, ubr)
			if res.PlatformSupport != "supported" || res.Platform.Codename != h.wantKey {
				t.Fatalf("%s@%d: support=%s key=%q reason=%q", h.id, ubr, res.PlatformSupport, res.Platform.Codename, res.SupportReason)
			}
			want := oracleExpected(t, h, ubr)
			got := vulnerableSet(t, h, res)
			if missing, extra := setDiff(want, got), setDiff(got, want); len(missing)+len(extra) > 0 {
				t.Errorf("%s@%d.%d: resolver missed %v, reported extra %v", h.id, h.build, ubr, missing, extra)
			}
			combos++
			if len(want) > 0 {
				vulnerableCombos++
				checkUpdateCard(t, h, ubr, res, len(want))
			}
		}
		// Named levels: the oracle itself must agree with their meaning.
		if u, ok := levels["patched"]; ok {
			if got := vulnerableSet(t, h, resolveHost(t, h, u)); len(got) != 0 || len(oracleExpected(t, h, u)) != 0 {
				t.Errorf("%s: fully patched host (UBR %d) must have no OS CVEs, got %v", h.id, u, got)
			}
		}
		if u, ok := levels["jan2023"]; ok {
			want := oracleExpected(t, h, u)
			all := map[string]bool{}
			for _, r := range hostRows(t, h) {
				if !r.hotpatch {
					all[r.cve] = true
				}
			}
			if len(setDiff(all, want)) != 0 {
				t.Errorf("%s: a January 2023 host must be exposed to every fixture CVE, missing %v", h.id, setDiff(all, want))
			}
		}
		if u, ok := levels["one_month_behind"]; ok {
			if len(oracleExpected(t, h, u)) == 0 {
				t.Errorf("%s: one month behind (UBR %d) must not look clean", h.id, u)
			}
		}
	}
	if combos < 300 {
		t.Errorf("harness ran only %d host x patch level combinations", combos)
	}
	t.Logf("harness: %d hosts, %d host x patch level combinations, %d with OS CVEs", len(harnessHosts), combos, vulnerableCombos)
}

func checkUpdateCard(t *testing.T, h winHost, ubr int, res *resolver.RunResult, n int) {
	t.Helper()
	for _, g := range res.RemediationGroups {
		if g.Action != findings.ActionInstallUpdate {
			continue
		}
		if g.Closes.Count == nil || *g.Closes.Count != n {
			t.Errorf("%s@%d: update card closes %v, want %d", h.id, ubr, g.Closes.CVEIDs, n)
		}
		if len(g.Targets) != 1 || !strings.HasPrefix(g.Targets[0].TargetVersion, strconv.Itoa(h.build)+".") {
			t.Errorf("%s@%d: update card target %+v must be on build %d", h.id, ubr, g.Targets, h.build)
		}
		return
	}
	t.Errorf("%s@%d: %d vulnerable OS CVEs but no install_update card", h.id, ubr, n)
}

func hostByID(t *testing.T, id string) winHost {
	t.Helper()
	for _, h := range harnessHosts {
		if h.id == id {
			return h
		}
	}
	t.Fatalf("no harness host %s", id)
	return winHost{}
}

// Server Core and the domain controller role are the same MSRC product as
// the Desktop Experience install: identical CVE sets at every patch level.
func TestWindowsHarnessServerVariantsMatch(t *testing.T) {
	pairs := [][2]string{{"srv2022", "srv2022-core"}, {"srv2022", "srv2022-dc"}, {"srv2025", "srv2025-core"}, {"srv2025", "srv2025-dc"}, {"srv2019", "srv2019-core"}, {"srv2012", "srv2012-core"}}
	for _, p := range pairs {
		a, b := hostByID(t, p[0]), hostByID(t, p[1])
		_, sweep := patchLevels(t, a)
		for _, ubr := range sweep {
			ga, gb := vulnerableSet(t, a, resolveHost(t, a, ubr)), vulnerableSet(t, b, resolveHost(t, b, ubr))
			if d1, d2 := setDiff(ga, gb), setDiff(gb, ga); len(d1)+len(d2) > 0 {
				t.Errorf("%s vs %s at UBR %d differ: %v / %v", p[0], p[1], ubr, d1, d2)
			}
		}
	}
	// July 2026 lists CVE-2026-33842 for Server 2022 Desktop Experience only
	// (MSRC omitted the Server Core product for most of that month). A Server
	// Core host is still reported: conservative, it is one MSRC product.
	core := hostByID(t, "srv2022-core")
	if !vulnerableSet(t, core, resolveHost(t, core, 1))["CVE-2026-33842"] {
		t.Error("server core host must still report the desktop-only listed CVE-2026-33842")
	}
}

// Build 26100 is both Windows 11 24H2 and Server 2025, on different UBR
// streams: the SKU must pick the stream.
func TestWindowsHarness26100ClientVsServer(t *testing.T) {
	client, server := hostByID(t, "win11-24h2"), hostByID(t, "srv2025")
	cl, _ := patchLevels(t, client)
	sl, _ := patchLevels(t, server)
	cu := cl["patched"]
	if got := vulnerableSet(t, client, resolveHost(t, client, cu)); len(got) != 0 {
		t.Fatalf("patched 24H2 client must be clean: %v", got)
	}
	res := resolveHost(t, server, cu)
	if res.Platform.Codename != "windows_server_2025" {
		t.Fatalf("server SKU on 26100 mapped to %q", res.Platform.Codename)
	}
	if len(vulnerableSet(t, server, res)) == 0 {
		t.Fatalf("Server 2025 at the client UBR %d must not look clean (server stream reaches %d)", cu, sl["patched"])
	}
	if res := resolveHost(t, client, sl["patched"]); res.Platform.Codename != "windows_11_24h2" {
		t.Fatalf("client SKU on 26100 mapped to %q", res.Platform.Codename)
	}
}

// MSRC published Windows 10 21H2 October 2023 fixes as 10.0.19041.3570.
func TestWindowsHarnessSiblingBuildFix(t *testing.T) {
	h := hostByID(t, "win10-21h2")
	if !vulnerableSet(t, h, resolveHost(t, h, 3569))["CVE-2023-35349"] {
		t.Fatal("19044.3569 must be vulnerable to CVE-2023-35349 (fixed as 19041.3570)")
	}
	if vulnerableSet(t, h, resolveHost(t, h, 3570))["CVE-2023-35349"] {
		t.Fatal("19044.3570 must be fixed for CVE-2023-35349")
	}
}

// A hotpatch enrolled host on the August 2026 hotpatch build is fixed for
// the CVEs that hotpatch covers; a CVE with only a regular fix (December
// 2025 CVE-2025-64679, fixed in 26100.6899) is decided by that fix.
func TestWindowsHarnessHotpatchHost(t *testing.T) {
	cases := []struct {
		host string
		ubr  int
		cve  string
		vuln bool
	}{
		{"srv2025", 33222, "CVE-2026-70346", false}, // on the hotpatch build
		{"srv2025", 33221, "CVE-2026-70346", true},
		{"srv2025", 33295, "CVE-2026-70346", true}, // not a hotpatch build: regular update decides
		{"win11-24h2", 9106, "CVE-2026-70347", false},
		{"srv2022", 5440, "CVE-2026-70347", false},
		{"win11-24h2", 7392, "CVE-2025-62571", false}, // December 2025 hotpatch build
		{"win11-24h2", 7092, "CVE-2025-62571", true},  // November hotpatch build, one month behind
		{"win11-24h2", 7392, "CVE-2025-64679", false}, // regular fix only, older than the host
		{"win11-24h2", 6898, "CVE-2025-64679", true},
	}
	for _, tc := range cases {
		h := hostByID(t, tc.host)
		got := vulnerableSet(t, h, resolveHost(t, h, tc.ubr))[tc.cve]
		if got != tc.vuln {
			t.Errorf("%s@%d %s: vulnerable=%v, want %v", tc.host, tc.ubr, tc.cve, got, tc.vuln)
		}
	}
}

// Hosts the resolver cannot place must say so: not_supported with a reason
// and a platform unknown, never an empty clean result.
func TestWindowsHarnessUnmappedIsNotClean(t *testing.T) {
	cases := []struct {
		h      winHost
		ubr    any
		reason string
	}{
		{winHost{"future", "", 99999, "amd64", "Microsoft Windows 12 Pro", 1, "Client", "", ""}, 100, "not in the MSRC product map"},
		{winHost{"win7", "", 7601, "amd64", "Microsoft Windows 7 Professional", 1, "Client", "", ""}, 26000, "January 2023"},
		{winHost{"win81", "", 9600, "amd64", "Microsoft Windows 8.1 Pro", 1, "Client", "", ""}, 21000, "January 2023"},
		{winHost{"srv1909", "", 18363, "amd64", "Microsoft Windows Server Datacenter", 3, "Server Core", "1909", ""}, 1500, "not in the MSRC product map"},
		{winHost{"win11-on-server-build", "", 20348, "amd64", "Microsoft Windows 11 Pro", 1, "Client", "", ""}, 100, "no client product"},
		{hostByID(t, "srv2022"), nil, "UBR missing"},
		{hostByID(t, "win11-24h2"), nil, "UBR missing"},
	}
	for _, tc := range cases {
		res := resolveHost(t, tc.h, tc.ubr)
		if res.PlatformSupport == "supported" || !strings.Contains(res.SupportReason, tc.reason) {
			t.Errorf("%s: support=%s reason=%q, want not supported with %q", tc.h.id, res.PlatformSupport, res.SupportReason, tc.reason)
		}
		if len(res.Findings) != 0 {
			t.Errorf("%s: %d findings for an unplaced host", tc.h.id, len(res.Findings))
		}
		found := false
		for _, u := range res.Unknowns {
			if u.Kind == "platform" && u.Reason == res.SupportReason {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: unknowns must carry the platform reason: %+v", tc.h.id, res.Unknowns)
		}
	}
}
