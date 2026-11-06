package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"

	_ "github.com/s4e-io/openness-resolver/internal/version/rpm"
)

func debianRule(cve, release, src, fixed string) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID: "debian:" + release + ":" + cve + ":" + src, Ecosystem: "dpkg", Vendor: "debian", Distribution: "debian",
		Release: release, SourcePackage: src, Status: rules.StatusReleased, FixedVersion: fixed,
		Comparator: "dpkg", CVEID: cve, SourcePriority: 1,
	}
}

func rockyRule(cve, release, pkg, fixed string) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID: "rocky:" + release + ":" + cve + ":" + pkg, Ecosystem: "rpm", Vendor: "rocky", Distribution: "rocky",
		Release: release, PackageName: pkg, Status: rules.StatusReleased, FixedVersion: fixed,
		Comparator: "rpm", CVEID: cve, SourcePriority: 1,
	}
}

// coveredUbuntuHost is a jammy host whose own release has rules, so the
// coverage state only reflects the containers.
func coveredUbuntuHost() *tf.Doc {
	return tf.NewUbuntuJammyARM64().AddPackage("openssl", "3.0.2-0ubuntu1.15")
}

var hostRule = tf.UbuntuRule("CVE-HOST", "jammy", "openssl", "openssl", "released", "3.0.2-0ubuntu1.15")

func TestContainerImagesEvaluatedByOSRelease(t *testing.T) {
	cases := []struct {
		name      string
		spec      tf.ContainerSpec
		rules     []rules.PackageVulnerabilityRule
		pkg, cve  string
		wantState string
		method    string
		release   string
		absentCVE string // a rule of another release that must not apply
	}{
		{
			// Distroless debian12 ships VERSION_ID without VERSION_CODENAME;
			// the codename comes from the same map the host path uses.
			name: "debian 12 without codename",
			spec: tf.ContainerSpec{
				ID: "d1", Name: "d1", Digest: "sha256:deb12", ImageRef: "gcr.io/distroless/base-debian12", State: "running",
				Packages:  [][3]string{{"libssl3", "3.0.11-1~deb12u1", "dpkg"}},
				Sources:   map[string][2]string{"libssl3": {"openssl", ""}},
				OSRelease: map[string]any{"id": "debian", "version_id": "12", "pretty_name": "Distroless"},
			},
			rules: []rules.PackageVulnerabilityRule{
				debianRule("CVE-D1", "bookworm", "openssl", "3.0.13-1~deb12u1"),
				debianRule("CVE-D2", "trixie", "openssl", "3.5.0-1"),
			},
			pkg: "libssl3", cve: "CVE-D1", wantState: findings.StateVulnerable,
			method: MethodDebianSourcePackage, release: "bookworm", absentCVE: "CVE-D2",
		},
		{
			// The source version is compared, not the binary epoch version.
			name: "debian 12 source version",
			spec: tf.ContainerSpec{
				ID: "d2", Name: "d2", Digest: "sha256:deb12b", ImageRef: "debian:12", State: "running",
				Packages:  [][3]string{{"bsdutils", "1:2.38.1-5+b1", "dpkg"}},
				Sources:   map[string][2]string{"bsdutils": {"util-linux", "2.38.1-5"}},
				OSRelease: map[string]any{"id": "debian", "version_id": "12", "version_codename": "bookworm"},
			},
			rules: []rules.PackageVulnerabilityRule{debianRule("CVE-D3", "bookworm", "util-linux", "2.38.1-5+deb12u1")},
			pkg:   "bsdutils", cve: "CVE-D3", wantState: findings.StateVulnerable,
			method: MethodDebianSourcePackage, release: "bookworm",
		},
		{
			name: "ubuntu 24.04",
			spec: tf.ContainerSpec{
				ID: "u1", Name: "u1", Digest: "sha256:noble", ImageRef: "ubuntu:24.04", State: "running",
				Packages:  [][3]string{{"libssl3t64", "3.0.13-0ubuntu3", "dpkg"}},
				Sources:   map[string][2]string{"libssl3t64": {"openssl", ""}},
				OSRelease: map[string]any{"id": "ubuntu", "version_id": "24.04", "version_codename": "noble", "id_like": "debian"},
			},
			rules: []rules.PackageVulnerabilityRule{
				tf.UbuntuRule("CVE-U1", "noble", "openssl", "libssl3t64", "released", "3.0.13-0ubuntu3.4"),
				tf.UbuntuRule("CVE-U2", "jammy", "openssl", "libssl3t64", "released", "9.9.9"),
			},
			pkg: "libssl3t64", cve: "CVE-U1", wantState: findings.StateVulnerable,
			method: MethodUbuntuSourcePackage, release: "noble", absentCVE: "CVE-U2",
		},
		{
			name: "rocky 9",
			spec: tf.ContainerSpec{
				ID: "r1", Name: "r1", Digest: "sha256:rocky9", ImageRef: "rockylinux:9", State: "exited",
				Packages:  [][3]string{{"openssl-libs", "1:3.0.7-24.el9", "rpm"}},
				OSRelease: map[string]any{"id": "rocky", "version_id": "9.3", "id_like": "rhel centos fedora"},
			},
			rules: []rules.PackageVulnerabilityRule{
				rockyRule("CVE-R1", "9", "openssl-libs", "1:3.0.7-27.el9"),
				rockyRule("CVE-R2", "8", "openssl-libs", "1:9.9.9-1.el8"),
			},
			pkg: "openssl-libs", cve: "CVE-R1", wantState: findings.StateVulnerable,
			method: MethodRPMPackage, release: "9", absentCVE: "CVE-R2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := coveredUbuntuHost().AddContainer(tc.spec)
			res := resolve(t, doc, append(tc.rules, hostRule)...)
			f := mustFinding(t, res, tc.pkg, tc.cve)
			if f.State != tc.wantState || f.DetectionMethod != tc.method || f.Release != tc.release {
				t.Errorf("state=%s method=%s release=%s", f.State, f.DetectionMethod, f.Release)
			}
			if f.Scope != "container" || f.ImageDigest != tc.spec.Digest || len(f.ContainerIDs) != 1 || f.ContainerIDs[0] != tc.spec.ID {
				t.Errorf("container identity: scope=%s digest=%s ids=%v", f.Scope, f.ImageDigest, f.ContainerIDs)
			}
			if tc.absentCVE != "" && findFinding(t, res, tc.pkg, tc.absentCVE) != nil {
				t.Errorf("rule of another release applied: %s", tc.absentCVE)
			}
			if cov := res.RuleCoverage; cov.State != CoverageCovered || len(cov.Gaps) != 0 {
				t.Errorf("coverage=%+v", cov)
			}
			for _, n := range res.Notes {
				if strings.Contains(n, "not evaluated") {
					t.Errorf("unexpected note %q", n)
				}
			}
		})
	}
}

func TestContainerNotCoveredGap(t *testing.T) {
	debPkgs := [][3]string{{"libssl1.1", "1.1.1n-0+deb11u5", "dpkg"}}
	cases := []struct {
		name   string
		spec   tf.ContainerSpec
		reason string
	}{
		{
			name: "unsupported release",
			spec: tf.ContainerSpec{ID: "c1", Name: "c1", Digest: "sha256:deb11", ImageRef: "debian:11", State: "running",
				Packages: debPkgs, OSRelease: map[string]any{"id": "debian", "version_id": "11", "version_codename": "bullseye"}},
			reason: "past Debian LTS",
		},
		{
			name: "no rules loaded",
			spec: tf.ContainerSpec{ID: "c2", Name: "c2", Digest: "sha256:alma9", ImageRef: "almalinux:9", State: "running",
				Packages: [][3]string{{"bash", "5.1.8-9.el9", "rpm"}}, OSRelease: map[string]any{"id": "almalinux", "version_id": "9.4"}},
			reason: "no rules loaded for almalinux/9",
		},
		{
			name: "no os-release",
			spec: tf.ContainerSpec{ID: "c3", Name: "c3", Digest: "sha256:old", ImageRef: "debian:12", State: "running",
				Packages: debPkgs},
			reason: "no os-release in the image; package family debian-family",
		},
		{
			name: "distribution without evaluator",
			spec: tf.ContainerSpec{ID: "c4", Name: "c4", Digest: "sha256:centos", ImageRef: "centos:7", State: "running",
				Packages: [][3]string{{"bash", "4.2.46-35.el7_9", "rpm"}}, OSRelease: map[string]any{"id": "centos", "version_id": "7"}},
			reason: "has no container package evaluator",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			second := tc.spec
			second.ID, second.Name = tc.spec.ID+"b", tc.spec.Name+"b"
			doc := coveredUbuntuHost().AddContainer(tc.spec).AddContainer(second)
			res := resolve(t, doc, hostRule)
			cov := res.RuleCoverage
			if cov.State != CoveragePartial || cov.AssetRelease != "ubuntu/jammy" {
				t.Fatalf("state=%s asset_release=%s gaps=%+v", cov.State, cov.AssetRelease, cov.Gaps)
			}
			if cov.EvaluationError("e.openness") != nil {
				t.Fatal("a container gap must not fail the run")
			}
			if len(cov.Gaps) != 1 {
				t.Fatalf("gaps=%+v", cov.Gaps)
			}
			g := cov.Gaps[0]
			if g.Kind != GapContainerNotCovered || g.Release != "container:"+tc.spec.ImageRef || g.Count != 2 ||
				!strings.Contains(g.Detail, tc.spec.Digest) || !strings.Contains(g.Detail, tc.reason) {
				t.Errorf("gap=%+v", g)
			}
			if !strings.Contains(cov.Reason, "container image "+tc.spec.ImageRef) {
				t.Errorf("reason=%q", cov.Reason)
			}
			found := false
			for _, u := range res.Unknowns {
				if u.Subject == g.Release && strings.HasPrefix(u.Reason, GapContainerNotCovered+": ") {
					found = true
				}
			}
			if !found {
				t.Errorf("unknowns=%+v", res.Unknowns)
			}
			for _, f := range res.Findings {
				if f.Scope == "container" {
					t.Errorf("unexpected container finding %+v", f)
				}
			}
		})
	}
}

// An image without packages (scratch) keeps its note and is not a gap.
func TestScratchImageIsNotAGap(t *testing.T) {
	doc := coveredUbuntuHost().AddContainer(tf.ContainerSpec{ID: "s1", Name: "s1", Digest: "sha256:scratch", ImageRef: "app:1", State: "running"})
	res := resolve(t, doc, hostRule)
	if res.RuleCoverage.State != CoverageCovered {
		t.Fatalf("coverage=%+v", res.RuleCoverage)
	}
}

// Only the evaluated image's release fills asset_release when the host
// has no release of its own.
func TestContainerReleaseFillsAssetRelease(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().SetOS(map[string]any{"distribution_id": "fooos", "version_id": "1"}).
		AddPackage("x", "1.0").
		AddContainer(tf.ContainerSpec{ID: "d1", Name: "d1", Digest: "sha256:deb12", ImageRef: "debian:12", State: "running",
			Packages: [][3]string{{"libssl3", "3.0.11-1~deb12u1", "dpkg"}}, Sources: map[string][2]string{"libssl3": {"openssl", ""}},
			OSRelease: map[string]any{"id": "debian", "version_id": "12"}})
	res := resolve(t, doc, debianRule("CVE-D1", "bookworm", "openssl", "3.0.13-1~deb12u1"))
	mustFinding(t, res, "libssl3", "CVE-D1")
	if res.RuleCoverage.AssetRelease != "debian/bookworm" {
		t.Fatalf("coverage=%+v", res.RuleCoverage)
	}
}
