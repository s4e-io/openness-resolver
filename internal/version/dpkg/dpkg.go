// Package dpkg implements Debian package version comparison
// (epoch:upstream-version-debian-revision) as pure Go, following the
// algorithm in dpkg's lib/dpkg/version.c (Debian Policy 5.6.12).
//
// The production resolver never shells out to dpkg; the implementation is
// validated against native `dpkg --compare-versions` through the fixture
// corpus in testdata/dpkg/corpus.txt.
package dpkg

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/version"
)

// Comparator implements version.VersionComparator for the dpkg ecosystem.
type Comparator struct{}

func init() { version.Register(Comparator{}) }

// Ecosystem returns "dpkg".
func (Comparator) Ecosystem() string { return "dpkg" }

// Compare compares two Debian version strings.
func (Comparator) Compare(installed, fixed string) (int, error) {
	return Compare(installed, fixed)
}

type parsedVersion struct {
	epoch    string
	upstream string
	revision string
}

// parse splits epoch:upstream-revision. A missing epoch is "0"; a missing
// revision is "0" (Debian policy: absence of debian_revision is equivalent
// to a revision of 0, so "1.0" == "1.0-0").
func parse(v string) (parsedVersion, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return parsedVersion{}, fmt.Errorf("empty version string")
	}
	p := parsedVersion{epoch: "0", revision: "0"}
	rest := v
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		epoch := rest[:i]
		if epoch == "" {
			return parsedVersion{}, fmt.Errorf("version %q has empty epoch", v)
		}
		for _, c := range epoch {
			if c < '0' || c > '9' {
				return parsedVersion{}, fmt.Errorf("version %q has non-numeric epoch %q", v, epoch)
			}
		}
		p.epoch = epoch
		rest = rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		p.revision = rest[i+1:]
		rest = rest[:i]
		if p.revision == "" {
			return parsedVersion{}, fmt.Errorf("version %q has empty debian revision", v)
		}
	}
	if rest == "" {
		return parsedVersion{}, fmt.Errorf("version %q has empty upstream version", v)
	}
	p.upstream = rest
	for _, c := range p.upstream {
		if !isDigit(byte(c)) && !isAlpha(byte(c)) && !strings.ContainsRune(".-+~:_", c) {
			return parsedVersion{}, fmt.Errorf("version %q contains invalid character %q in upstream version", v, c)
		}
	}
	return p, nil
}

// Compare compares two Debian version strings and returns -1, 0 or 1.
func Compare(a, b string) (int, error) {
	pa, err := parse(a)
	if err != nil {
		return 0, err
	}
	pb, err := parse(b)
	if err != nil {
		return 0, err
	}
	if c := compareNumericString(pa.epoch, pb.epoch); c != 0 {
		return c, nil
	}
	if c := verrevcmp(pa.upstream, pb.upstream); c != 0 {
		return sign(c), nil
	}
	return sign(verrevcmp(pa.revision, pb.revision)), nil
}

// compareNumericString compares two non-negative integers of arbitrary size.
func compareNumericString(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return sign(strings.Compare(a, b))
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order gives the dpkg sort weight of a character: '~' sorts before
// everything (including end of string), letters before non-letters.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// verrevcmp is a direct port of dpkg's verrevcmp().
func verrevcmp(a, b string) int {
	i, j := 0, 0
	byteAt := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := order(byteAt(a, i))
			bc := order(byteAt(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}
