package platform

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

func osrec(id, verID, verStr, arch string) evidence.OperatingSystem {
	return evidence.OperatingSystem{
		DistributionID:      id,
		VersionID:           verID,
		DistributionVersion: verStr,
		Architecture:        arch,
		KernelVersion:       "6.8.0-106-generic",
	}
}

func TestUbuntu2204ARM64(t *testing.T) {
	p := FromOS(osrec("ubuntu", "22.04", "22.04.4 LTS (Jammy Jellyfish)", "arm64"), evidence.Kernel{})
	if p.DistributionID != "ubuntu" || p.Codename != "jammy" || p.Architecture != "arm64" {
		t.Fatalf("unexpected context: %+v", p)
	}
	if p.CodenameSource != "version_string" {
		t.Errorf("codename source=%q", p.CodenameSource)
	}
	if s, _ := p.Support(); s != Supported {
		t.Errorf("support=%v, want supported", s)
	}
}

func TestUbuntu2204AMD64UnameArch(t *testing.T) {
	p := FromOS(osrec("ubuntu", "22.04", "22.04.4 LTS (Jammy Jellyfish)", "x86_64"), evidence.Kernel{})
	if p.Architecture != "amd64" {
		t.Errorf("arch=%q, want amd64", p.Architecture)
	}
	if p.RawArchitecture != "x86_64" {
		t.Errorf("raw arch not preserved: %q", p.RawArchitecture)
	}
}

func TestUbuntu2404(t *testing.T) {
	p := FromOS(osrec("ubuntu", "24.04", "24.04.1 LTS (Noble Numbat)", "amd64"), evidence.Kernel{})
	if p.Codename != "noble" {
		t.Errorf("codename=%q, want noble", p.Codename)
	}
	if s, _ := p.Support(); s != Supported {
		t.Errorf("want supported")
	}
}

// Debian must not be treated as Ubuntu even when the release looks similar.
func TestDebianIsNotUbuntu(t *testing.T) {
	p := FromOS(osrec("debian", "12", "12 (bookworm)", "amd64"), evidence.Kernel{})
	if p.DistributionID != "debian" {
		t.Fatalf("distribution=%q", p.DistributionID)
	}
	if p.Codename != "bookworm" {
		t.Errorf("codename=%q, want bookworm", p.Codename)
	}
	if p.RuleRelease() != "bookworm" {
		t.Errorf("rule release=%q, want bookworm", p.RuleRelease())
	}
	if s, reason := p.Support(); s != Supported {
		t.Errorf("debian 12 must be supported, got %v (%s)", s, reason)
	}
}

func TestMissingCodenameFallsBackToVersionMap(t *testing.T) {
	p := FromOS(osrec("ubuntu", "22.04", "", "arm64"), evidence.Kernel{})
	if p.Codename != "jammy" || p.CodenameSource != "version_map" {
		t.Errorf("codename=%q source=%q", p.Codename, p.CodenameSource)
	}
}

func TestExplicitVersionCodenameWins(t *testing.T) {
	os := osrec("ubuntu", "22.04", "22.04.4 LTS (Jammy Jellyfish)", "arm64")
	os.VersionCodename = "jammy"
	p := FromOS(os, evidence.Kernel{})
	if p.CodenameSource != "os_release" {
		t.Errorf("source=%q, want os_release", p.CodenameSource)
	}
}

func TestUnknownArchitecturePreserved(t *testing.T) {
	p := FromOS(osrec("ubuntu", "22.04", "", "sparc99"), evidence.Kernel{})
	if p.Architecture != "sparc99" {
		t.Errorf("unknown arch must be preserved, got %q", p.Architecture)
	}
}

func TestMalformedOSRelease(t *testing.T) {
	p := FromOS(evidence.OperatingSystem{}, evidence.Kernel{})
	if probs := p.Validate(); len(probs) != 3 {
		t.Errorf("expected 3 validation problems, got %v", probs)
	}
	if s, _ := p.Support(); s != UnknownState {
		t.Errorf("support=%v, want unknown", s)
	}
}

func TestUnknownDistributionNotSupported(t *testing.T) {
	p := FromOS(osrec("gentoo", "2.14", "", "amd64"), evidence.Kernel{})
	if s, _ := p.Support(); s != NotSupported {
		t.Errorf("want not_supported, got %v", s)
	}
}

func TestDistroAliases(t *testing.T) {
	p := FromOS(osrec("amzn", "2023", "", "x86_64"), evidence.Kernel{})
	if p.DistributionID != "amazon" {
		t.Errorf("alias not applied: %q", p.DistributionID)
	}
	if s, _ := p.Support(); s != Supported {
		t.Errorf("want supported, got %v", s)
	}
}

func TestArchitectureCompatible(t *testing.T) {
	cases := []struct {
		asset, other string
		want         bool
	}{
		{"arm64", "arm64", true},
		{"arm64", "aarch64", true},
		{"amd64", "x86_64", true},
		{"arm64", "amd64", false},
		{"arm64", "all", true},
		{"arm64", "", true},
		{"amd64", "noarch", true},
	}
	for _, c := range cases {
		if got := ArchitectureCompatible(c.asset, c.other); got != c.want {
			t.Errorf("ArchitectureCompatible(%q,%q)=%v, want %v", c.asset, c.other, got, c.want)
		}
	}
}

func TestAlpineRuleRelease(t *testing.T) {
	cases := []struct {
		name string
		p    PlatformContext
		want string
	}{
		{"host point release", FromOS(osrec("alpine", "3.20.10", "", "aarch64"), evidence.Kernel{}), "v3.20"},
		{"host minor only", FromOS(osrec("alpine", "3.22", "", "x86_64"), evidence.Kernel{}), "v3.22"},
		{"host edge", FromOS(osrec("alpine", "3.21_alpha20240923", "", "x86_64"), evidence.Kernel{}), ""},
		{"image branch", PlatformContext{DistributionID: "alpine", DistributionVersion: "3.19", Codename: "v3.19"}, "v3.19"},
	}
	for _, c := range cases {
		if got := c.p.RuleRelease(); got != c.want {
			t.Errorf("%s: rule release=%q, want %q", c.name, got, c.want)
		}
	}
	for in, want := range map[string]string{"3.20.10": "v3.20", "v3.18": "v3.18", "3": "", "": "", "edge": "", "3.x": ""} {
		if got := AlpineBranch(in); got != want {
			t.Errorf("AlpineBranch(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestAmazonLinuxSupport(t *testing.T) {
	for _, v := range []string{"2", "2023"} {
		p := FromOS(osrec("amzn", v, v, "aarch64"), evidence.Kernel{})
		if s, reason := p.Support(); s != Supported || p.RuleRelease() != v {
			t.Errorf("amazon %s: support=%s (%s) release=%q", v, s, reason, p.RuleRelease())
		}
	}
	p := FromOS(osrec("amzn", "2018.03", "2018.03", "x86_64"), evidence.Kernel{})
	if s, reason := p.Support(); s != NotSupported || !strings.Contains(reason, "end of life") {
		t.Errorf("amazon 2018.03: support=%s reason=%q", s, reason)
	}
}
