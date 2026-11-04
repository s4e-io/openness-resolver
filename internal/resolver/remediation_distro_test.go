package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
)

// Remediation cards on RPM hosts name the host's own package manager; an
// apt-get hint on Rocky or openSUSE is a command that cannot run there.
func TestRemediationHintFollowsDistribution(t *testing.T) {
	cases := map[string]string{
		"rocky-9":            "dnf upgrade ",
		"almalinux-8":        "dnf upgrade ",
		"rhel-9":             "dnf upgrade ",
		"opensuse-leap-15.6": "zypper update ",
		"debian-12-bookworm": "apt-get install --only-upgrade ",
	}
	for name, prefix := range cases {
		res := resolveEvidence(t, name)
		n := 0
		for _, g := range res.RemediationGroups {
			if g.Action != findings.ActionUpgradePackages || g.CommandHint == "" || g.CommandHint == "reboot" {
				continue
			}
			n++
			if !strings.HasPrefix(g.CommandHint, prefix) {
				t.Errorf("%s: card %s hint %q, want prefix %q", name, g.SourcePackage, g.CommandHint, prefix)
			}
		}
		if n == 0 {
			t.Errorf("%s: no upgrade card with a hint", name)
		}
	}
}

// The target version of an RPM binary is the highest fixed version under
// rpm ordering. dpkg cannot even order an rpm caret build (1.0^1), so the
// card lost its target version when dpkg ordering was used for rpm.
func TestHigherVersionUsesComparator(t *testing.T) {
	if got, ok := higherVersion("rpm", "1.0^1-1", "1.0.1-1"); !ok || got != "1.0.1-1" {
		t.Errorf("rpm: got %q ok=%v, want 1.0.1-1", got, ok)
	}
	if _, ok := higherVersion("dpkg", "1.0^1-1", "1.0.1-1"); ok {
		t.Errorf("dpkg ordered an rpm caret version")
	}
	b := &binaryRollup{comparator: "rpm"}
	b.considerFixed("1:3.0.7-27.el9")
	b.considerFixed("1:3.0.7-28.el9_4")
	b.considerFixed("1:3.0.7-24.el9")
	if b.target != "1:3.0.7-28.el9_4" || b.uncertain {
		t.Errorf("rpm rollup target=%q uncertain=%v", b.target, b.uncertain)
	}
}

// Debian open and postponed issues have no fix: they must be on no card (a
// client would count the card as an update), and the upgrade cards close
// only what an upgrade fixes.
func TestNoFixFindingsAreOnNoCard(t *testing.T) {
	res := resolveEvidence(t, "debian-12-bookworm")
	byFinding := map[string]findings.RemediationGroup{}
	for _, g := range res.RemediationGroups {
		for _, id := range g.Closes.FindingIDs {
			byFinding[id] = g
		}
	}
	sawNoFix, sawUpgrade := false, false
	for _, f := range res.Findings {
		if f.State != findings.StateVulnerable || f.Scope != "host" {
			continue
		}
		g, ok := byFinding[f.FindingID]
		switch f.FixAvailability {
		case findings.FixUnavailable, findings.FixDeferred:
			sawNoFix = true
			if ok {
				t.Errorf("%s/%s (fix %s) on %s card", f.BinaryPackage, f.CVEID, f.FixAvailability, g.Action)
			}
		case findings.FixAvailable:
			sawUpgrade = true
			if !ok || g.Action != findings.ActionUpgradePackages {
				t.Errorf("%s/%s with a fix on card %q", f.BinaryPackage, f.CVEID, g.Action)
			}
		}
	}
	if !sawNoFix || !sawUpgrade {
		t.Fatalf("fixture lacks both kinds: nofix=%v upgrade=%v", sawNoFix, sawUpgrade)
	}
	if _, _, ok := remediationInvariant(res); !ok {
		t.Error("remediation invariant broken")
	}
}
