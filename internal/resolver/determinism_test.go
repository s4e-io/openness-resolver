package resolver

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// Rocky Linux published CVE-2025-5318 for libssh in RLSA-2025:18275 and
// again in RLSA-2025:20943 with the same fixed version. Resolving the same
// evidence twice must name the same advisory and rule; before, the choice
// followed Go map iteration order.
func TestSameFixInTwoAdvisoriesIsDeterministic(t *testing.T) {
	plat := platform.PlatformContext{DistributionID: "rocky", DistributionVersion: "9.0", Architecture: "arm64"}
	p := pkgs.InstalledPackage{
		Ecosystem: "rpm", Name: "libssh", RawVersion: "0.9.6-3.el9", Architecture: "aarch64", SourcePackage: "libssh",
		Source: pkgs.SourceRelationship{SourcePackage: "libssh", Confidence: "direct"},
	}
	mk := func(adv string) *rules.PackageVulnerabilityRule {
		return &rules.PackageVulnerabilityRule{
			RuleID: "rocky:9:" + adv + ":CVE-2025-5318:src:libssh", Ecosystem: "rpm", Vendor: "rocky", Distribution: "rocky",
			Release: "9", SourcePackage: "libssh", Status: rules.StatusReleased, FixedVersion: "0:0.10.4-15.el9_7",
			Comparator: "rpm", CVEID: "CVE-2025-5318", AdvisoryIDs: []string{adv},
		}
	}
	candidates := map[string]*rules.PackageVulnerabilityRule{}
	for _, adv := range []string{"RLSA-2025:20943", "RLSA-2025:18275", "RLSA-2025:30001"} {
		r := mk(adv)
		candidates[r.RuleID] = r
	}
	e := &Engine{}
	want := ""
	for i := 0; i < 200; i++ {
		fs := e.decidePackage(&RunResult{}, p, candidates, plat, MethodRPMPackage)
		if len(fs) != 1 || len(fs[0].RuleIDs) == 0 {
			t.Fatalf("findings=%+v", fs)
		}
		got := fs[0].RuleIDs[0] + " " + fs[0].AdvisoryIDs[0]
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("run %d chose %s, earlier %s", i, got, want)
		}
	}
}
