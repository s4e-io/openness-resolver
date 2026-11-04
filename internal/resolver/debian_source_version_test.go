package resolver

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// Debian tracker fixed versions are source versions. A binary that carries
// its own epoch (bsdutils 1:2.38.1-5+b1, built from util-linux 2.38.1-5,
// as shipped on the debian:12.0 image) must be compared through its source
// version, otherwise the epoch makes every util-linux fix read as applied.
func TestDebianTrackerComparesSourceVersion(t *testing.T) {
	plat := platform.PlatformContext{DistributionID: "debian", DistributionVersion: "12", Codename: "bookworm", Architecture: "arm64"}
	rule := &rules.PackageVulnerabilityRule{
		RuleID:        "debian:bookworm:CVE-2024-28085:util-linux",
		Ecosystem:     "dpkg",
		Vendor:        "debian",
		Distribution:  "debian",
		Release:       "bookworm",
		SourcePackage: "util-linux",
		Status:        rules.StatusReleased,
		FixedVersion:  "2.38.1-5+deb12u1",
		Comparator:    "dpkg",
		CVEID:         "CVE-2024-28085",
	}
	pkg := func(name, raw, srcVer string) pkgs.InstalledPackage {
		return pkgs.InstalledPackage{
			Ecosystem: "dpkg", Name: name, RawVersion: raw, Architecture: "arm64",
			SourcePackage: "util-linux",
			Source:        pkgs.SourceRelationship{BinaryPackage: name, SourcePackage: "util-linux", SourceVersion: srcVer, Confidence: "direct"},
		}
	}
	cases := []struct {
		name, raw, src, want string
	}{
		{"bsdutils", "1:2.38.1-5+b1", "2.38.1-5", findings.StateVulnerable},         // epoch binary, old source
		{"bsdutils", "1:2.38.1-5+deb12u3", "2.38.1-5+deb12u3", findings.StateFixed}, // epoch binary, fixed source
		{"libmount1", "2.38.1-5+b1", "2.38.1-5", findings.StateVulnerable},          // binNMU of the old source
		{"libmount1", "2.38.1-5+b1", "", findings.StateVulnerable},                  // no source version: binary version
		{"libmount1", "2.38.1-5+deb12u1", "", findings.StateFixed},
	}
	for _, c := range cases {
		ev := EvaluateRule(pkg(c.name, c.raw, c.src), plat, rule)
		if ev.state != c.want {
			t.Errorf("%s %s (source %q): state=%s want %s reasons=%v", c.name, c.raw, c.src, ev.state, c.want, ev.reasons)
		}
		if c.src != "" && ev.comparison != nil && ev.comparison.Installed != c.src {
			t.Errorf("%s: compared %s, want source version %s", c.name, ev.comparison.Installed, c.src)
		}
	}

	// Other vendors keep comparing the binary version.
	rpmRule := *rule
	rpmRule.Distribution, rpmRule.Release, rpmRule.Comparator, rpmRule.Ecosystem = "rocky", "9", "rpm", "rpm"
	p := pkgs.InstalledPackage{Ecosystem: "rpm", Name: "util-linux", RawVersion: "2.37.4-20.el9", Source: pkgs.SourceRelationship{SourceVersion: "9.9-9"}}
	if v, via := comparableInstalledVersion(p, &rpmRule); v != "2.37.4-20.el9" || via {
		t.Errorf("rpm rule compared %s (via source %v)", v, via)
	}
}
