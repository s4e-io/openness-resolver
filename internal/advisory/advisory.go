// Package advisory carries urgent vulnerabilities the vendors' feeds do not describe yet.
//
// A feed (the Ubuntu OVAL, the Debian tracker, the NVD) can lag a day or more behind a
// disclosure. An advisory is a small, hand-checked record shipped with the resolver: the
// versions that fix the CVE per vendor package, and the version lines that are affected for
// Java installs found on disk. It is evaluated next to the feeds, not instead of them: for a
// package the advisory's rules join the feed's rules for the same CVE and merge into one
// finding (the highest fixed version wins), so the feed taking over later changes nothing
// but the advisory id; a rule that proves wrong is fixed by editing data/advisories.json.
// Advisory rules never count towards rule coverage: a host without feed data stays missing.
package advisory

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

//go:embed data/advisories.json
var dataFile []byte

// Advisory is one urgent vulnerability.
type Advisory struct {
	ID    string `json:"id"`
	CVE   string `json:"cve"`
	Title string `json:"title"`
	// Severity is the rating the finding gets when no vendor decides it.
	Severity     string `json:"severity"`
	SeverityNote string `json:"severity_note,omitempty"`
	// Condition says what else has to hold for the host to be exploitable, in words.
	Condition  string   `json:"condition,omitempty"`
	Mitigation string   `json:"mitigation,omitempty"`
	References []string `json:"references,omitempty"`
	// Architectures lists the CPU architectures that are affected (x86_64, arm64);
	// empty means all.
	Architectures []string      `json:"architectures,omitempty"`
	Instances     *InstanceSpec `json:"instances,omitempty"`
	Packages      []PackageFix  `json:"packages,omitempty"`
}

// InstanceSpec says which software instances found on disk are affected.
type InstanceSpec struct {
	// ProductKey is the collector catalog product, "java-runtime".
	ProductKey string `json:"product_key"`
	Lines      []Line `json:"lines"`
}

// Line is one feature release line (a Java major version).
type Line struct {
	Major int `json:"major"`
	// From is the first affected version of the line.
	From string `json:"from"`
	// Fixed is the first fixed version; empty means no fix exists for the line.
	Fixed string `json:"fixed,omitempty"`
}

// PackageFix is the fixed version of one source package of one distribution release.
type PackageFix struct {
	Ecosystem     string `json:"ecosystem"`
	Distribution  string `json:"distribution"`
	Release       string `json:"release"`
	SourcePackage string `json:"source_package"`
	Fixed         string `json:"fixed"`
	Advisory      string `json:"advisory,omitempty"`
	SupportTier   string `json:"support_tier,omitempty"`
}

type file struct {
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
}

// Set is the loaded advisories.
type Set struct {
	Version    string
	Advisories []Advisory
	rules      []rules.PackageVulnerabilityRule
	byKey      map[string][]*rules.PackageVulnerabilityRule
}

// Builtin returns the advisories compiled into this build.
func Builtin() *Set {
	s, err := Parse(dataFile)
	if err != nil {
		panic("advisory: data/advisories.json: " + err.Error())
	}
	return s
}

// Parse reads an advisory file.
func Parse(raw []byte) (*Set, error) {
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	s := &Set{Version: f.Version, Advisories: f.Advisories, byKey: map[string][]*rules.PackageVulnerabilityRule{}}
	for _, a := range f.Advisories {
		if a.ID == "" || a.CVE == "" {
			return nil, fmt.Errorf("an advisory needs id and cve")
		}
		for _, p := range a.Packages {
			if p.Ecosystem == "" || p.Distribution == "" || p.Release == "" || p.SourcePackage == "" || p.Fixed == "" {
				return nil, fmt.Errorf("%s: a package entry needs ecosystem, distribution, release, source_package and fixed", a.ID)
			}
			s.rules = append(s.rules, a.rule(p))
		}
	}
	for i := range s.rules {
		r := &s.rules[i]
		k := key(r.Ecosystem, r.Distribution, r.Release, r.SourcePackage)
		s.byKey[k] = append(s.byKey[k], r)
	}
	return s, nil
}

func key(eco, distro, release, src string) string {
	return strings.Join([]string{eco, distro, release, src}, "|")
}

// rule turns one package entry into a normalized rule. It has no binary package name, so it
// applies to every binary built from the source package.
func (a Advisory) rule(p PackageFix) rules.PackageVulnerabilityRule {
	adv := p.Advisory
	if adv == "" {
		adv = a.ID
	}
	return rules.PackageVulnerabilityRule{
		RuleID:         "zz-advisory:" + a.ID + ":" + p.Distribution + ":" + p.Release + ":" + p.SourcePackage,
		Ecosystem:      p.Ecosystem,
		Vendor:         p.Distribution,
		Distribution:   p.Distribution,
		Release:        p.Release,
		SourcePackage:  p.SourcePackage,
		Status:         rules.StatusReleased,
		RawStatus:      adv,
		FixedVersion:   p.Fixed,
		Comparator:     p.Ecosystem,
		CVEID:          a.CVE,
		AdvisoryIDs:    []string{adv},
		Urgency:        "high",
		SupportTier:    p.SupportTier,
		VendorNotes:    a.Title,
		SourcePriority: 1,
	}
}

// ForSourcePackage returns the advisory rules of one source package.
func (s *Set) ForSourcePackage(eco, distro, release, src string) []*rules.PackageVulnerabilityRule {
	if s == nil {
		return nil
	}
	return s.byKey[key(eco, distro, release, src)]
}

// Verdicts of EvaluateInstance.
const (
	NotAffected = "not_affected"
	Affected    = "affected"
	Fixed       = "fixed"
	Unknown     = "unknown"
)

// EvaluateInstance judges the version of a Java install (the JAVA_VERSION of its release
// file, "17.0.21", "21.0.13.1", "1.8.0_391"). fixed is the first fixed version of the line,
// "" when the line has none.
func (a Advisory) EvaluateInstance(version string) (verdict, fixed string) {
	if a.Instances == nil {
		return NotAffected, ""
	}
	major, ok := javaMajor(version)
	if !ok {
		return Unknown, ""
	}
	for _, l := range a.Instances.Lines {
		if l.Major != major {
			continue
		}
		if cmpDotted(version, l.From) < 0 {
			return NotAffected, ""
		}
		if l.Fixed != "" && cmpDotted(version, l.Fixed) >= 0 {
			return Fixed, l.Fixed
		}
		return Affected, l.Fixed
	}
	return NotAffected, ""
}

// AffectsArchitecture says whether the CPU architecture (x86_64, amd64, arm64, aarch64, "")
// can be hit. An unknown architecture counts as affected: nothing is hidden for lack of data.
func (a Advisory) AffectsArchitecture(arch string) bool {
	arch = normalizeArch(arch)
	if len(a.Architectures) == 0 || arch == "" {
		return true
	}
	for _, x := range a.Architectures {
		if normalizeArch(x) == arch {
			return true
		}
	}
	return false
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x86_64", "amd64", "x64", "x86-64":
		return "x86_64"
	case "arm64", "aarch64":
		return "arm64"
	}
	return strings.ToLower(strings.TrimSpace(arch))
}

// javaMajor reads the feature release of a Java version: 17 from "17.0.21", 8 from
// "1.8.0_391", 21 from "21".
func javaMajor(version string) (int, bool) {
	parts := dotted(version)
	if len(parts) == 0 {
		return 0, false
	}
	if parts[0] == 1 && len(parts) > 1 {
		return parts[1], true
	}
	return parts[0], true
}

// dotted returns the leading numeric dotted parts of a version; a suffix after the numbers
// ("+9", "-ea", "_391") is ignored.
func dotted(version string) []int {
	v := strings.TrimSpace(version)
	var out []int
	for _, field := range strings.Split(v, ".") {
		end := 0
		for end < len(field) && field[end] >= '0' && field[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		n, err := strconv.Atoi(field[:end])
		if err != nil {
			break
		}
		out = append(out, n)
		if end < len(field) {
			break
		}
	}
	return out
}

// cmpDotted compares two versions by their numeric parts, a missing part being 0.
func cmpDotted(a, b string) int {
	x, y := dotted(a), dotted(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		switch {
		case p < q:
			return -1
		case p > q:
			return 1
		}
	}
	return 0
}
