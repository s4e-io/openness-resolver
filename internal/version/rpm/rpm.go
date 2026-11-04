// Package rpm implements RPM package version comparison
// ([epoch:]version-release) as pure Go, following rpmvercmp() in rpm's
// rpmio/rpmvercmp.c (rpm >= 4.15, which added the caret separator).
//
// Semantics:
//   - A missing epoch is 0. "0:1.0-1" == "1.0-1".
//   - Epoch is compared numerically first, then version, then release, each
//     with rpmvercmp.
//   - rpmvercmp splits a string into alternating numeric and alphabetic
//     segments; every other character is a separator. Numeric segments
//     compare numerically (leading zeros ignored) and always sort newer than
//     alphabetic segments.
//   - "~" sorts before everything, including the end of the string
//     ("1.0~rc1" < "1.0").
//   - "^" sorts after the end of the string but before any other segment
//     ("1.0" < "1.0^git1" < "1.0.1").
//   - A release missing on either side is not compared (rpm's behaviour
//     when a dependency names only epoch:version).
//
// The production resolver never shells out to rpm.
package rpm

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/version"
)

// Comparator implements version.VersionComparator for the rpm ecosystem.
type Comparator struct{}

func init() { version.Register(Comparator{}) }

// Ecosystem returns "rpm".
func (Comparator) Ecosystem() string { return "rpm" }

// Compare compares two RPM EVR strings.
func (Comparator) Compare(installed, fixed string) (int, error) {
	return Compare(installed, fixed)
}

// EVR is a parsed epoch:version-release.
type EVR struct {
	Epoch   string
	Version string
	Release string
}

// Parse splits "[epoch:]version[-release]". The release is the text after
// the last "-"; RPM forbids "-" inside version and release.
func Parse(v string) (EVR, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return EVR{}, fmt.Errorf("empty version string")
	}
	e := EVR{Epoch: "0"}
	rest := v
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		epoch := rest[:i]
		if epoch == "" {
			return EVR{}, fmt.Errorf("version %q has empty epoch", v)
		}
		for i := 0; i < len(epoch); i++ {
			if !isDigit(epoch[i]) {
				return EVR{}, fmt.Errorf("version %q has non-numeric epoch %q", v, epoch)
			}
		}
		e.Epoch = epoch
		rest = rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		e.Release = rest[i+1:]
		rest = rest[:i]
		if e.Release == "" {
			return EVR{}, fmt.Errorf("version %q has empty release", v)
		}
	}
	if rest == "" {
		return EVR{}, fmt.Errorf("version %q has empty version part", v)
	}
	if strings.ContainsAny(rest, ": \t") {
		return EVR{}, fmt.Errorf("version %q contains an invalid character", v)
	}
	e.Version = rest
	return e, nil
}

// Compare compares two EVR strings and returns -1, 0 or 1.
func Compare(a, b string) (int, error) {
	ea, err := Parse(a)
	if err != nil {
		return 0, err
	}
	eb, err := Parse(b)
	if err != nil {
		return 0, err
	}
	return CompareEVR(ea, eb), nil
}

// CompareEVR compares two parsed EVRs.
func CompareEVR(a, b EVR) int {
	if c := compareNumeric(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := Vercmp(a.Version, b.Version); c != 0 {
		return c
	}
	if a.Release == "" || b.Release == "" {
		return 0
	}
	return Vercmp(a.Release, b.Release)
}

// Vercmp is rpmvercmp: it compares one version or release field.
func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		for one < len(a) && !isAlnum(a[one]) && a[one] != '~' && a[one] != '^' {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) && b[two] != '~' && b[two] != '^' {
			two++
		}

		// Tilde sorts before everything else, including the end.
		if at(a, one) == '~' || at(b, two) == '~' {
			if at(a, one) != '~' {
				return 1
			}
			if at(b, two) != '~' {
				return -1
			}
			one++
			two++
			continue
		}

		// Caret is like tilde, except that the end of a string sorts
		// before it.
		if at(a, one) == '^' || at(b, two) == '^' {
			if one >= len(a) {
				return -1
			}
			if two >= len(b) {
				return 1
			}
			if a[one] != '^' {
				return 1
			}
			if b[two] != '^' {
				return -1
			}
			one++
			two++
			continue
		}

		if !(one < len(a) && two < len(b)) {
			break
		}

		s1, s2 := one, two
		isNum := isDigit(a[s1])
		if isNum {
			for s1 < len(a) && isDigit(a[s1]) {
				s1++
			}
			for s2 < len(b) && isDigit(b[s2]) {
				s2++
			}
		} else {
			for s1 < len(a) && isAlpha(a[s1]) {
				s1++
			}
			for s2 < len(b) && isAlpha(b[s2]) {
				s2++
			}
		}
		seg1, seg2 := a[one:s1], b[two:s2]
		if seg2 == "" {
			// Segment types differ: numeric is newer than alphabetic.
			if isNum {
				return 1
			}
			return -1
		}
		var rc int
		if isNum {
			rc = compareNumeric(seg1, seg2)
		} else {
			rc = strings.Compare(seg1, seg2)
		}
		if rc != 0 {
			return rc
		}
		one, two = s1, s2
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if one >= len(a) {
		return -1
	}
	return 1
}

// compareNumeric compares digit strings of any length without overflow.
func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// IsModular reports whether a release carries a modularity stream marker
// (".module+el8...", ".module_el8...").
func IsModular(v string) bool {
	return strings.Contains(v, ".module+") || strings.Contains(v, ".module_")
}
