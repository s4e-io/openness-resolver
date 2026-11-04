// Package winbuild compares Windows OS build identities of the form
// "<build>.<ubr>" (for example "20348.5761"), optionally prefixed with the
// "10.0." major.minor that MSRC FixedBuild values carry.
//
// Cumulative servicing means the UBR only grows inside one servicing branch,
// so "installed < fixed" is a plain integer comparison of the UBR once both
// sides are on the same branch. Builds of different servicing branches are
// not comparable: Compare returns ErrBuildMismatch so the caller can treat the
// rule as not applicable instead of guessing.
//
// Some feature updates are enablement packages on top of one base build and
// keep receiving the very same cumulative update, so their UBR is shared
// (see servicingBranch). MSRC CVRF documents mix those build numbers: the
// October 2023 document lists Windows 10 21H2 fixes as 10.0.19041.3570 and
// the December 2023 one lists Windows 11 23H2 fixes as 10.0.22621.2861.
package winbuild

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/version"
)

// Ecosystem is the comparator id used in rules and findings.
const Ecosystem = "winbuild"

// ErrBuildMismatch is returned when the two versions belong to different
// Windows builds (servicing branches).
var ErrBuildMismatch = errors.New("winbuild: different Windows builds are not comparable")

// Build is a parsed build identity.
type Build struct {
	Build int
	UBR   int
}

func (b Build) String() string { return fmt.Sprintf("%d.%d", b.Build, b.UBR) }

// Parse accepts "26100.9711", "10.0.26100.9711" or "6.3.9600.22748". The last
// two dotted integers are build and UBR; anything before them is ignored.
func Parse(s string) (Build, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Build{}, errors.New("winbuild: empty version")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return Build{}, fmt.Errorf("winbuild: %q is not <build>.<ubr>", s)
	}
	b, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil || b <= 0 {
		return Build{}, fmt.Errorf("winbuild: bad build number in %q", s)
	}
	u, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || u < 0 {
		return Build{}, fmt.Errorf("winbuild: bad UBR in %q", s)
	}
	return Build{Build: b, UBR: u}, nil
}

// servicingBranch maps build numbers that share one cumulative update (one
// UBR stream) to the base build of that branch. Evidence from the MSRC feed:
// the same KB is published as 19044.x and 19045.x, as 22621.x and 22631.x,
// and as 26100.x and 26200.x (KB5120994: 26100.9106 and 26200.9106).
var servicingBranch = map[int]int{
	19041: 19041, 19042: 19041, 19043: 19041, 19044: 19041, 19045: 19041,
	22621: 22621, 22631: 22621,
	26100: 26100, 26200: 26100,
}

// Branch returns the servicing branch base of a build number; builds outside
// the enablement-package families are their own branch.
func Branch(build int) int {
	if b, ok := servicingBranch[build]; ok {
		return b
	}
	return build
}

// SameBranch reports whether two builds receive the same cumulative updates.
func (b Build) SameBranch(o Build) bool { return Branch(b.Build) == Branch(o.Build) }

// Comparator implements version.VersionComparator.
type Comparator struct{}

func (Comparator) Ecosystem() string { return Ecosystem }

// Compare returns -1/0/1 for installed vs fixed on the same servicing branch
// and ErrBuildMismatch when the branches differ.
func (Comparator) Compare(installed, fixed string) (int, error) {
	a, err := Parse(installed)
	if err != nil {
		return 0, err
	}
	b, err := Parse(fixed)
	if err != nil {
		return 0, err
	}
	if !a.SameBranch(b) {
		return 0, fmt.Errorf("%w: installed build %d, fixed build %d", ErrBuildMismatch, a.Build, b.Build)
	}
	switch {
	case a.UBR < b.UBR:
		return -1, nil
	case a.UBR > b.UBR:
		return 1, nil
	}
	return 0, nil
}

// SameBuild reports whether two version strings are on the same servicing
// branch (see servicingBranch), i.e. whether Compare can decide them.
// Unparseable input is "not the same build".
func SameBuild(a, b string) bool {
	x, err := Parse(a)
	if err != nil {
		return false
	}
	y, err := Parse(b)
	if err != nil {
		return false
	}
	return x.SameBranch(y)
}

// OnBuild restates version v on the given build number, keeping its UBR:
// OnBuild("19041.3570", 19044) is "19044.3570". It returns v unchanged when
// it does not parse or belongs to another servicing branch.
func OnBuild(v string, build int) string {
	x, err := Parse(v)
	if err != nil || Branch(x.Build) != Branch(build) {
		return v
	}
	return Build{Build: build, UBR: x.UBR}.String()
}

func init() { version.Register(Comparator{}) }
