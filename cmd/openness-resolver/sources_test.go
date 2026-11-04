package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// feed sync --for picks the vendor-wide source of the host distribution.
func TestSourcesForEvidenceNewDistributions(t *testing.T) {
	cases := map[string]string{
		"debian-12-bookworm": "debian-security-tracker",
		"debian-13-trixie":   "debian-security-tracker",
		"rocky-9":            "osv-rocky",
		"almalinux-8":        "osv-almalinux",
		"rhel-9":             "osv-rhel",
		"opensuse-leap-15.6": "osv-opensuse",
	}
	for name, want := range cases {
		srcs, notes, err := sourcesForEvidence(filepath.Join("../../testdata/evidence/synthetic", name+".openness"), 24)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(srcs) != 1 || srcs[0].ID != want {
			t.Errorf("%s: sources=%v notes=%v, want %s", name, srcs, notes, want)
		}
	}
}

func TestSourcesForEvidenceUnsupportedReleaseNote(t *testing.T) {
	srcs, notes, err := sourcesForEvidence("../../testdata/evidence/synthetic/debian-11-bullseye.openness", 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || !strings.Contains(strings.Join(notes, " "), "bullseye") {
		t.Errorf("sources=%v notes=%v", srcs, notes)
	}
}

func TestWantedReleases(t *testing.T) {
	deb := wantedReleases("debian")
	if !deb["bookworm"] || !deb["trixie"] || deb["bullseye"] || deb["12"] {
		t.Errorf("debian=%v", deb)
	}
	rocky := wantedReleases("rocky")
	if !rocky["8"] || !rocky["9"] || rocky["10"] {
		t.Errorf("rocky=%v", rocky)
	}
	if leap := wantedReleases("opensuse"); !leap["15.6"] {
		t.Errorf("opensuse=%v", leap)
	}
}

// resolve loads the host release and image distributions only; a shared
// data directory with every distribution synced must not be read in full.
func TestRuleFilesForLoadsOnlyTheAssetReleases(t *testing.T) {
	dir := t.TempDir()
	store := rules.NewStore(dir)
	for _, vr := range [][2]string{{"debian", "bookworm"}, {"debian", "trixie"}, {"rocky", "9"}, {"opensuse", "15.6"}, {"pypi", "pypi"}} {
		r := rules.PackageVulnerabilityRule{RuleID: vr[0] + ":" + vr[1], Distribution: vr[0], Release: vr[1]}
		if vr[0] == "pypi" {
			r.Distribution, r.Release = "", ""
		}
		if err := store.SaveRules(vr[0], vr[1], []rules.PackageVulnerabilityRule{r}, rules.FeedSourceMetadata{}); err != nil {
			t.Fatal(err)
		}
	}
	lr, err := evidence.Load("../../testdata/evidence/synthetic/debian-12-bookworm.openness")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := store.LoadFiltered(ruleFilesFor(lr))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs.Rules {
		got = append(got, r.RuleID)
	}
	if strings.Join(got, ",") != "debian:bookworm,pypi:pypi" {
		t.Errorf("loaded %v, want debian:bookworm and pypi:pypi", got)
	}

	// A distribution seen in a container image keeps all of its releases.
	keep := ruleFileFilter("ubuntu/jammy", map[string]bool{"alpine": true})
	for _, c := range []struct {
		vendor, release string
		want            bool
	}{
		{"ubuntu", "jammy", true}, {"ubuntu", "noble", false}, {"alpine", "v3.19", true},
		{"alpine", "v3.20", true}, {"debian", "bookworm", false}, {"microsoft", "2026-Oct", true},
	} {
		if keep(c.vendor, c.release) != c.want {
			t.Errorf("keep(%s, %s) = %v", c.vendor, c.release, !c.want)
		}
	}
}

// The registry syncs every Alpine and Amazon release the platform table
// claims, so `feed sync --vendor <v>` never leaves a supported release out.
func TestRegistryCoversSupportedReleases(t *testing.T) {
	ids := map[string]bool{}
	for _, s := range rules.Registry() {
		if s.Enabled {
			ids[s.ID] = true
		}
	}
	for _, v := range platform.SupportedReleases("alpine") {
		b := platform.AlpineBranch(v)
		if !ids["alpine-secdb-"+b] || !ids["alpine-secdb-"+b+"-community"] {
			t.Errorf("alpine %s: no enabled secdb sources for %s", v, b)
		}
	}
	for _, v := range platform.SupportedReleases("amazon") {
		if !ids["amazon-updateinfo-"+v] {
			t.Errorf("amazon %s: no enabled updateinfo source", v)
		}
	}
}
