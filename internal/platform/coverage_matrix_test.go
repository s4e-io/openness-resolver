package platform

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

func TestSupportMatrixNewDistributions(t *testing.T) {
	cases := []struct {
		id, version, verStr string
		want                SupportState
		release             string
	}{
		{"debian", "12", "12 (bookworm)", Supported, "bookworm"},
		{"debian", "13", "13 (trixie)", Supported, "trixie"},
		{"debian", "11", "11 (bullseye)", NotSupported, "bullseye"},
		{"rocky", "8.10", "8.10 (Green Obsidian)", Supported, "8"},
		{"rocky", "9.4", "9.4 (Blue Onyx)", Supported, "9"},
		{"rocky", "10.0", "10.0", NotSupported, "10"},
		{"almalinux", "8.9", "8.9", Supported, "8"},
		{"almalinux", "9.4", "9.4", Supported, "9"},
		{"rhel", "8.10", "8.10 (Ootpa)", Supported, "8"},
		{"rhel", "9.4", "9.4 (Plow)", Supported, "9"},
		{"opensuse-leap", "15.5", "15.5", Supported, "15.5"},
		{"opensuse-leap", "15.6", "15.6", Supported, "15.6"},
		{"opensuse-tumbleweed", "20261020", "", NotSupported, "20261020"},
		{"sles", "15.6", "15-SP6", NotSupported, ""},
		{"centos", "9", "9", NotSupported, ""},
		{"ol", "9.4", "9.4", NotSupported, ""},
		{"amzn", "2018.03", "2018.03", NotSupported, ""},
	}
	for _, c := range cases {
		p := FromOS(osrec(c.id, c.version, c.verStr, "x86_64"), evidence.Kernel{})
		got, reason := p.Support()
		if got != c.want {
			t.Errorf("%s %s: support=%s (%s), want %s", c.id, c.version, got, reason, c.want)
		}
		if got == NotSupported && reason == "" {
			t.Errorf("%s %s: not_supported needs a reason", c.id, c.version)
		}
		if c.release != "" && p.RuleRelease() != c.release {
			t.Errorf("%s %s: rule release=%q, want %q", c.id, c.version, p.RuleRelease(), c.release)
		}
		if p.Tested() && c.want != Supported {
			t.Errorf("%s %s: an unsupported platform must not be marked tested", c.id, c.version)
		}
	}
}

func TestUnsupportedReasonsAreSpecific(t *testing.T) {
	for id, want := range map[string]string{"ol": "ELSA", "centos": "CentOS", "sles": "module"} {
		p := FromOS(osrec(id, "9", "9", "x86_64"), evidence.Kernel{})
		if _, reason := p.Support(); !strings.Contains(reason, want) {
			t.Errorf("%s: reason=%q, want mention of %q", id, reason, want)
		}
	}
}

func TestPlatformTestedList(t *testing.T) {
	cases := []struct {
		name string
		p    PlatformContext
		want bool
	}{
		{"ubuntu 22.04", FromOS(osrec("ubuntu", "22.04", "22.04.4 LTS (Jammy Jellyfish)", "arm64"), evidence.Kernel{}), true},
		{"ubuntu 24.04", FromOS(osrec("ubuntu", "24.04", "24.04 LTS (Noble Numbat)", "amd64"), evidence.Kernel{}), false},
		{"ubuntu 20.04", FromOS(osrec("ubuntu", "20.04", "20.04.6 LTS (Focal Fossa)", "amd64"), evidence.Kernel{}), false},
		{"alpine 3.20 host", FromOS(osrec("alpine", "3.20.10", "", "aarch64"), evidence.Kernel{}), true},
		{"alpine 3.19 host", FromOS(osrec("alpine", "3.19.1", "", "x86_64"), evidence.Kernel{}), false},
		{"alpine 3.13 unsupported", FromOS(osrec("alpine", "3.13.0", "", "x86_64"), evidence.Kernel{}), false},
		{"debian 12", FromOS(osrec("debian", "12", "12 (bookworm)", "amd64"), evidence.Kernel{}), true},
		{"debian 13", FromOS(osrec("debian", "13", "13 (trixie)", "amd64"), evidence.Kernel{}), false},
		{"rocky 9", FromOS(osrec("rocky", "9.3", "9.3 (Blue Onyx)", "aarch64"), evidence.Kernel{}), true},
		{"rocky 8", FromOS(osrec("rocky", "8.10", "8.10 (Green Obsidian)", "aarch64"), evidence.Kernel{}), false},
		{"almalinux 8", FromOS(osrec("almalinux", "8.10", "8.10", "aarch64"), evidence.Kernel{}), true},
		{"almalinux 9", FromOS(osrec("almalinux", "9.4", "9.4", "aarch64"), evidence.Kernel{}), false},
		{"opensuse leap 15.6", FromOS(osrec("opensuse-leap", "15.6", "15.6", "aarch64"), evidence.Kernel{}), true},
		{"opensuse leap 15.5", FromOS(osrec("opensuse-leap", "15.5", "15.5", "aarch64"), evidence.Kernel{}), false},
		{"amazon 2023", FromOS(osrec("amzn", "2023", "2023", "aarch64"), evidence.Kernel{}), true},
		{"amazon 2", FromOS(osrec("amzn", "2", "2", "aarch64"), evidence.Kernel{}), true},
		{"amazon 2018.03", FromOS(osrec("amzn", "2018.03", "2018.03", "aarch64"), evidence.Kernel{}), false},
		{"rhel 9", FromOS(osrec("rhel", "9.4", "9.4", "x86_64"), evidence.Kernel{}), false},
		{"windows 2022", PlatformContext{DistributionID: "windows", DistributionVersion: "21H2", Codename: "windows_server_2022", WindowsBuild: "20348.2582"}, true},
		{"windows 2019", PlatformContext{DistributionID: "windows", DistributionVersion: "1809", Codename: "windows_server_2019", WindowsBuild: "17763.6054"}, false},
	}
	for _, c := range cases {
		if got := c.p.Tested(); got != c.want {
			t.Errorf("%s: tested=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestTestedReleasesAreSupported(t *testing.T) {
	for distro, list := range testedReleases {
		if distro == "windows" {
			continue
		}
		for _, r := range list {
			if r == "*" {
				continue
			}
			found := false
			for _, s := range productionSupportedReleases[distro] {
				if s == r {
					found = true
				}
			}
			if !found {
				t.Errorf("tested release %s %s is not in the support matrix", distro, r)
			}
		}
	}
}
