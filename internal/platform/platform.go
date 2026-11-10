// Package platform implements Task 1 of the resolver backlog:
// distribution / release / architecture applicability.
//
// It normalizes /etc/os-release + uname evidence into a canonical
// PlatformContext and decides whether the resolver has production rule
// support for the platform. Debian rules are never applied to Ubuntu and
// vice versa: applicability is always keyed on the normalized
// DistributionID + release, never on package-name similarity.
package platform

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

// PlatformContext is the canonical asset platform model.
type PlatformContext struct {
	DistributionID      string `json:"distribution_id"`
	DistributionVersion string `json:"distribution_version"`
	Codename            string `json:"codename"`
	Architecture        string `json:"architecture"`
	KernelVersion       string `json:"kernel_version"`

	// Raw values are preserved exactly as collected.
	RawDistributionID      string `json:"raw_distribution_id"`
	RawDistributionVersion string `json:"raw_distribution_version"`
	RawVersionID           string `json:"raw_version_id"`
	RawArchitecture        string `json:"raw_architecture"`

	// CodenameSource records how the codename was determined:
	// "os_release", "version_string", "version_map", "windows_product",
	// or "" (unknown).
	CodenameSource string `json:"codename_source"`

	// WindowsBuild is "<build>.<ubr>" for Windows hosts; Codename then holds
	// the MSRC product key (windows_server_2022, ...).
	WindowsBuild string `json:"windows_build,omitempty"`
	// windowsReason explains an unmapped Windows host (not serialized).
	windowsReason string
}

// SupportState is the production-support decision for a platform.
type SupportState string

const (
	Supported    SupportState = "supported"
	NotSupported SupportState = "not_supported"
	UnknownState SupportState = "unknown"
)

// knownDistributions is the normalization allowlist from the task spec.
var knownDistributions = map[string]bool{
	"ubuntu": true, "debian": true, "alpine": true, "rhel": true, "windows": true,
	"rocky": true, "almalinux": true, "centos": true, "fedora": true,
	"oracle": true, "amazon": true, "sles": true, "opensuse": true,
}

// Known reports whether id is a normalized distribution id the resolver recognizes.
func Known(id string) bool { return knownDistributions[id] }

// distroAliases maps vendor os-release ID spellings to canonical IDs.
var distroAliases = map[string]string{
	"ol":                       "oracle",
	"amzn":                     "amazon",
	"opensuse-leap":            "opensuse",
	"opensuse-tumbleweed":      "opensuse",
	"redhat":                   "rhel",
	"red hat enterprise linux": "rhel",
}

// ubuntuCodenames maps Ubuntu VERSION_ID to release codename.
var ubuntuCodenames = map[string]string{
	"16.04": "xenial",
	"18.04": "bionic",
	"20.04": "focal",
	"22.04": "jammy",
	"24.04": "noble",
	"25.04": "plucky",
}

// debianCodenames maps Debian VERSION_ID to release codename.
var debianCodenames = map[string]string{
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
}

// productionSupportedReleases is the production support matrix. A release
// listed here has a host package evaluator and an enabled advisory source:
//
//	ubuntu     Ubuntu USN OVAL (per codename)
//	alpine     Alpine secdb (per branch; hosts and container images)
//	debian     Debian Security Tracker JSON (per codename)
//	rocky      OSV "Rocky Linux:<major>" (RESF errata)
//	almalinux  OSV "AlmaLinux:<major>" (AlmaLinux errata)
//	rhel       OSV "Red Hat:enterprise_linux:<major>::<repo>" (Red Hat errata)
//	opensuse   OSV "openSUSE:Leap <version>" (SUSE/openSUSE updates)
//	amazon     Amazon Linux core repository updateinfo.xml (ALAS, per release)
//
// Whether a release was verified against a real host is a separate
// question, answered by testedReleases.
var productionSupportedReleases = map[string][]string{
	"ubuntu":    {"20.04", "22.04", "24.04"},
	"alpine":    {"3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20", "3.21", "3.22"},
	"debian":    {"12", "13"},
	"rocky":     {"8", "9"},
	"almalinux": {"8", "9"},
	"rhel":      {"8", "9"},
	"opensuse":  {"15.5", "15.6", "16.0"},
	"amazon":    {"2", "2023"},
}

// testedReleases lists the releases verified against real hosts: a real
// collector scan of that platform was resolved end to end and checked.
// Everything else in productionSupportedReleases is covered by mock data
// (synthetic evidence and trimmed feed fixtures) only. This list must only
// grow with a real scan; never add a release because its unit tests pass.
//
// Container images are not judged by this list (an image is not the host
// platform); Alpine images of every listed branch were resolved for real.
//
//	ubuntu 22.04          real host
//	windows_server_2022   real host (MSRC product key)
//	alpine 3.20           real alpine:3.20 and alpine:3.20.0 images scanned as hosts (linux/arm64)
//	debian 12             real debian:12 and debian:12.5 images scanned as hosts (linux/arm64)
//	rocky 9               real rockylinux:9 (9.3) image scanned as a host (linux/arm64)
//	almalinux 8           real almalinux:8 (8.10) image scanned as a host (linux/arm64)
//	opensuse 15.6         real opensuse/leap:15.6 image scanned as a host, also with
//	                      older openssl-3 and libxml2 builds installed (linux/arm64)
//	amazon 2, 2023        real amazonlinux:2 and amazonlinux:2023 images scanned as hosts (linux/arm64)
var testedReleases = map[string][]string{
	"ubuntu":    {"22.04"},
	"windows":   {"windows_server_2022"},
	"alpine":    {"3.20"},
	"debian":    {"12"},
	"rocky":     {"9"},
	"almalinux": {"8"},
	"opensuse":  {"15.6"},
	"amazon":    {"2", "2023"},
}

// unsupportedReasons explains, per distribution, why a recognized platform
// has no production support. Reported verbatim as support_reason.
var unsupportedReasons = map[string]string{
	"centos": "CentOS (Stream) publishes no machine-readable security advisory feed; " +
		"Red Hat, Rocky and AlmaLinux advisories use different release strings and are not applied to it",
	"oracle": "Oracle Linux ELSA (OVAL) advisories have no parser yet; " +
		"Red Hat, Rocky and AlmaLinux advisories are not applied to it",
	"sles": "SLES advisories in OSV are split per module and LTSS product; " +
		"selecting them needs module subscription evidence the collector does not emit yet",
	"fedora": "no Fedora advisory source is wired yet",
}

// unsupportedReleaseReasons explains specific releases of a supported
// distribution that are left out of the matrix.
var unsupportedReleaseReasons = map[string]map[string]string{
	"debian": {
		"11": "Debian 11 (bullseye) is past Debian LTS; the Debian Security Tracker no longer publishes bullseye data (ELTS is not covered)",
	},
	"amazon": {
		"2018": "Amazon Linux AMI (2018.03) is end of life; only Amazon Linux 2 and Amazon Linux 2023 updateinfo is wired",
	},
}

// archAliases normalizes architecture spellings to the dpkg-style canon.
var archAliases = map[string]string{
	"x86_64":  "amd64",
	"amd64":   "amd64",
	"aarch64": "arm64",
	"arm64":   "arm64",
	"armv7l":  "armhf",
	"armhf":   "armhf",
	"i386":    "i386",
	"i686":    "i386",
	"ppc64le": "ppc64el",
	"ppc64el": "ppc64el",
	"s390x":   "s390x",
	"riscv64": "riscv64",
	"noarch":  "all",
	"all":     "all",
}

// NormalizeArchitecture maps uname/rpm/dpkg spellings to a canonical value.
// Unknown values are preserved as lowercase raw so mismatches surface instead
// of being silently dropped.
func NormalizeArchitecture(raw string) string {
	a := strings.ToLower(strings.TrimSpace(raw))
	if canon, ok := archAliases[a]; ok {
		return canon
	}
	return a
}

// ArchitectureCompatible reports whether a package/rule architecture is
// applicable to the asset architecture. "all" (arch-independent) matches
// everything; empty rule arch means the rule does not constrain arch.
func ArchitectureCompatible(assetArch, otherArch string) bool {
	if otherArch == "" {
		return true
	}
	a := NormalizeArchitecture(assetArch)
	o := NormalizeArchitecture(otherArch)
	return o == "all" || a == o
}

var codenameParenRe = regexp.MustCompile(`\(([A-Za-z]+)[^)]*\)`)

// FromOS builds a PlatformContext from .openness operating_system + kernel data.
func FromOS(os evidence.OperatingSystem, kernel evidence.Kernel) PlatformContext {
	ctx := PlatformContext{
		RawDistributionID:      os.DistributionID,
		RawDistributionVersion: os.DistributionVersion,
		RawVersionID:           os.VersionID,
		RawArchitecture:        os.Architecture,
		KernelVersion:          os.KernelVersion,
	}
	if ctx.KernelVersion == "" {
		ctx.KernelVersion = kernel.RunningKernel
	}

	id := strings.ToLower(strings.TrimSpace(os.DistributionID))
	if alias, ok := distroAliases[id]; ok {
		id = alias
	}
	ctx.DistributionID = id

	ctx.DistributionVersion = strings.TrimSpace(os.VersionID)
	if ctx.DistributionVersion == "" {
		// Fall back to the leading numeric portion of the version string.
		fields := strings.Fields(os.DistributionVersion)
		if len(fields) > 0 && fields[0] != "" && fields[0][0] >= '0' && fields[0][0] <= '9' {
			ctx.DistributionVersion = fields[0]
		}
	}

	ctx.Architecture = NormalizeArchitecture(os.Architecture)

	if id == "windows" {
		wp := ResolveWindowsProduct(os)
		ctx.Codename = wp.Key
		ctx.WindowsBuild = wp.Build
		ctx.windowsReason = wp.Reason
		if ctx.Codename != "" {
			ctx.CodenameSource = "windows_product"
		}
		if ctx.DistributionVersion == "" {
			ctx.DistributionVersion = strings.TrimSpace(os.DisplayVersion)
		}
		if ctx.DistributionVersion == "" {
			ctx.DistributionVersion = wp.Build
		}
		return ctx
	}

	// Codename resolution order: explicit os-release field, parenthesized
	// codename in the version string, then a distro-specific version map.
	switch {
	case os.VersionCodename != "":
		ctx.Codename = strings.ToLower(strings.TrimSpace(os.VersionCodename))
		ctx.CodenameSource = "os_release"
	default:
		if m := codenameParenRe.FindStringSubmatch(os.DistributionVersion); m != nil {
			ctx.Codename = strings.ToLower(m[1])
			ctx.CodenameSource = "version_string"
		} else if id == "ubuntu" {
			if cn, ok := ubuntuCodenames[ctx.DistributionVersion]; ok {
				ctx.Codename = cn
				ctx.CodenameSource = "version_map"
			}
		} else if id == "debian" {
			if cn, ok := debianCodenames[majorVersion(ctx.DistributionVersion)]; ok {
				ctx.Codename = cn
				ctx.CodenameSource = "version_map"
			}
		}
	}
	return ctx
}

// Validate reports structural problems with the platform evidence.
func (p PlatformContext) Validate() []string {
	var problems []string
	if p.DistributionID == "" {
		problems = append(problems, "distribution_id missing")
	} else if !knownDistributions[p.DistributionID] {
		problems = append(problems, fmt.Sprintf("distribution %q is not in the known distribution set", p.DistributionID))
	}
	if p.DistributionVersion == "" {
		problems = append(problems, "distribution version missing")
	}
	if p.Architecture == "" {
		problems = append(problems, "architecture missing")
	}
	return problems
}

// Support decides production rule support for the platform. Unsupported
// distributions return NotSupported; incomplete evidence returns UnknownState.
func (p PlatformContext) Support() (SupportState, string) {
	if p.DistributionID == "" {
		return UnknownState, "distribution id missing from evidence"
	}
	if !knownDistributions[p.DistributionID] {
		return NotSupported, fmt.Sprintf("distribution %q is not supported", p.DistributionID)
	}
	if p.DistributionID == "windows" {
		if p.Codename == "" || p.WindowsBuild == "" {
			reason := p.windowsReason
			if reason == "" {
				reason = "windows product could not be mapped"
			}
			return NotSupported, reason
		}
		return Supported, ""
	}
	releases, ok := productionSupportedReleases[p.DistributionID]
	if !ok {
		if reason, ok := unsupportedReasons[p.DistributionID]; ok {
			return NotSupported, fmt.Sprintf("%s is recognized but not supported: %s", p.DistributionID, reason)
		}
		return NotSupported, fmt.Sprintf("distribution %q is recognized but has no production rule support yet", p.DistributionID)
	}
	if p.DistributionID == "opensuse" && strings.Contains(strings.ToLower(p.RawDistributionID), "tumbleweed") {
		return NotSupported, "openSUSE Tumbleweed is a rolling release; only openSUSE Leap releases are supported"
	}
	if p.DistributionVersion == "" {
		return UnknownState, "distribution release missing from evidence"
	}
	if reason, ok := unsupportedReleaseReasons[p.DistributionID][majorVersion(p.DistributionVersion)]; ok {
		return NotSupported, reason
	}
	for _, r := range releases {
		if p.DistributionVersion == r || strings.HasPrefix(p.DistributionVersion, r+".") {
			return Supported, ""
		}
	}
	if p.DistributionID == "ubuntu" {
		if reason := ubuntuReleaseReason(p.DistributionVersion); reason != "" {
			return NotSupported, reason
		}
	}
	return NotSupported, fmt.Sprintf("%s %s is not in the supported release set %v", p.DistributionID, p.DistributionVersion, releases)
}

// ubuntuPublishedReleases are the Ubuntu releases Canonical publishes USN OVAL
// for (security-metadata.canonical.com/oval, checked November 2026). Every
// other release from 12.04 on is end of life and has no published data.
var ubuntuPublishedReleases = map[string]bool{
	"14.04": true, "16.04": true, "18.04": true, "20.04": true, "22.04": true, "24.04": true,
	"24.10": true, "25.04": true, "25.10": true, "26.04": true,
}

// ubuntuReleaseReason explains an Ubuntu release outside the support matrix:
// Canonical publishes no data for it, or publishes data this resolver does not
// cover yet. "" for a version that is not a known Ubuntu release (YY.MM).
func ubuntuReleaseReason(version string) string {
	v := ubuntuYYMM(version)
	if v == "" {
		return ""
	}
	if ubuntuPublishedReleases[v] {
		return fmt.Sprintf("Canonical publishes security data for Ubuntu %s, but this release is not covered yet", v)
	}
	if v < "12.04" || v > "26.04" {
		return "" // older than any data, or newer than this table: the generic reason
	}
	return fmt.Sprintf("Canonical does not publish security data (OVAL) for Ubuntu %s, an end-of-life release; upgrade to a supported Ubuntu LTS release", v)
}

// ubuntuYYMM returns the YY.MM of an Ubuntu VERSION_ID ("20.10", "18.04.6"),
// "" when it is not one.
func ubuntuYYMM(version string) string {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return ""
	}
	for _, c := range parts[0] + parts[1] {
		if c < '0' || c > '9' {
			return ""
		}
	}
	if m := parts[1]; m != "04" && m != "10" {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// Tested reports whether the platform is supported AND was verified against
// a real host (see testedReleases). Supported platforms that were only
// exercised with mock data report false.
func (p PlatformContext) Tested() bool {
	if state, _ := p.Support(); state != Supported {
		return false
	}
	for _, r := range testedReleases[p.DistributionID] {
		switch {
		case r == "*":
			return true
		case p.DistributionID == "windows":
			if p.Codename == r {
				return true
			}
		case p.DistributionVersion == r || strings.HasPrefix(p.DistributionVersion, r+"."):
			return true
		}
	}
	return false
}

// RuleRelease is the release key vendor rules for this platform are stored
// and matched under:
//
//	ubuntu, debian            codename (jammy, bookworm)
//	alpine                    branch (v3.19): Codename for an image, derived
//	                          from VERSION_ID (3.19.1) for a host
//	windows                   MSRC product key, kept in Codename
//	rocky, almalinux, rhel    major version (8, 9)
//	amazon                    release (2, 2023)
//	opensuse                  Leap version (15.6)
//
// Rocky, AlmaLinux and RHEL keys look alike but rules are also keyed by
// distribution, so a RHEL host never matches Rocky or AlmaLinux rules.
func (p PlatformContext) RuleRelease() string {
	switch p.DistributionID {
	case "rocky", "almalinux", "rhel", "amazon":
		return majorVersion(p.DistributionVersion)
	case "alpine":
		if alpineBranchRe.MatchString(p.Codename) {
			return p.Codename
		}
		return AlpineBranch(p.DistributionVersion)
	case "opensuse":
		parts := strings.SplitN(p.DistributionVersion, ".", 3)
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return p.DistributionVersion
	default:
		return p.Codename
	}
}

var alpineBranchRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+$`)

// AlpineBranch maps an Alpine VERSION_ID to its release branch, the key
// secdb publishes under: 3.20.10 and 3.20 are both v3.20. It returns ""
// when the version has no major.minor form (edge, unknown).
func AlpineBranch(version string) string {
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(version), "v"), ".", 3)
	if len(parts) < 2 || !isDigits(parts[0]) || !isDigits(parts[1]) {
		return ""
	}
	return "v" + parts[0] + "." + parts[1]
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// majorVersion returns the text before the first dot ("9.4" -> "9").
func majorVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// DebianCodename returns the codename for a Debian VERSION_ID.
func DebianCodename(versionID string) (string, bool) {
	cn, ok := debianCodenames[majorVersion(versionID)]
	return cn, ok
}

// SupportedReleases returns the supported releases of a distribution.
func SupportedReleases(distributionID string) []string {
	return append([]string(nil), productionSupportedReleases[distributionID]...)
}

// UbuntuCodename returns the codename for an Ubuntu VERSION_ID.
func UbuntuCodename(versionID string) (string, bool) {
	cn, ok := ubuntuCodenames[versionID]
	return cn, ok
}
