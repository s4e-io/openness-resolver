package kernel

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

func hostPkg(name, src, ver string) pkgs.InstalledPackage {
	return pkgs.InstalledPackage{
		Scope: pkgs.ScopeHost, Ecosystem: "dpkg", Name: name,
		SourcePackage: src, RawVersion: ver, Architecture: "arm64",
		EvidenceID: "ev-" + name,
	}
}

func TestImagePackageName(t *testing.T) {
	cases := []struct {
		version string
		flavour string
		want    string
		ok      bool
	}{
		// HWE pocket revisions carry '~'. The new ABI is the digits before '.' or '~'.
		{"6.8.0-110.110~22.04.1", "generic", "linux-image-6.8.0-110-generic", true},
		{"5.15.0-100.110~20.04.1", "generic", "linux-image-5.15.0-100-generic", true},
		// Epoch is not part of the image name.
		{"1:6.8.0-110.110~22.04.1", "generic", "linux-image-6.8.0-110-generic", true},
		{"6.8.0-110.110~22.04.1", "", "", false},
		{"6.8.0", "generic", "", false},
	}
	for _, tc := range cases {
		got, ok := ImagePackageName(tc.version, tc.flavour)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ImagePackageName(%q, %q)=%q,%v want %q,%v", tc.version, tc.flavour, got, ok, tc.want, tc.ok)
		}
	}
}

func TestBuildHWEKernel(t *testing.T) {
	idx := pkgs.NewIndex([]pkgs.InstalledPackage{
		hostPkg("linux-image-6.8.0-106-generic", "linux-signed-hwe-6.8", "6.8.0-106.106~22.04.1"),
		hostPkg("linux-modules-6.8.0-106-generic", "linux-hwe-6.8", "6.8.0-106.106~22.04.1"),
		hostPkg("linux-image-6.5.0-41-generic", "linux-signed-hwe-6.5", "6.5.0-41.41~22.04.2"),
		hostPkg("linux-image-generic-hwe-22.04", "linux-meta-hwe-6.8", "6.8.0-106.106~22.04.1"), // meta, excluded
		hostPkg("openssh-client", "openssh", "1:8.9p1-3ubuntu0.7"),
	})
	k := &evidence.Kernel{RunningKernel: "6.8.0-106-generic", RebootRequired: true}
	c := Build(k, idx)
	if c.VersionABI != "6.8.0-106" || c.Flavour != "generic" {
		t.Errorf("uname parse: %+v", c)
	}
	// Unsigned family via the modules package, signed prefix stripped.
	if c.SourceFamily != "linux-hwe-6.8" {
		t.Errorf("source family=%q", c.SourceFamily)
	}
	if c.PackageVersion != "6.8.0-106.106~22.04.1" {
		t.Errorf("package version=%q", c.PackageVersion)
	}
	if !c.RebootRequired {
		t.Error("reboot flag lost")
	}
	// Meta-package excluded; two versioned images found; running one marked.
	if len(c.InstalledImages) != 2 {
		t.Fatalf("installed images=%d: %+v", len(c.InstalledImages), c.InstalledImages)
	}
	running := 0
	for _, img := range c.InstalledImages {
		if img.Running {
			running++
			if img.PackageName != "linux-image-6.8.0-106-generic" {
				t.Errorf("wrong running image: %+v", img)
			}
		}
	}
	if running != 1 {
		t.Errorf("running images=%d", running)
	}
}

func TestBuildGAKernelSignedFamily(t *testing.T) {
	idx := pkgs.NewIndex([]pkgs.InstalledPackage{
		hostPkg("linux-image-5.15.0-113-generic", "linux-signed", "5.15.0-113.123"),
	})
	c := Build(&evidence.Kernel{RunningKernel: "5.15.0-113-generic"}, idx)
	if c.SourceFamily != "linux" {
		t.Errorf("linux-signed must normalize to linux, got %q", c.SourceFamily)
	}
}

func TestBuildCustomKernel(t *testing.T) {
	c := Build(&evidence.Kernel{RunningKernel: "6.9.0-custom+"}, pkgs.NewIndex(nil))
	if c.SourceFamily != "" || len(c.Notes) == 0 {
		t.Errorf("custom kernel must be unmapped with a note: %+v", c)
	}
}

func TestBuildMissingKernelEvidence(t *testing.T) {
	c := Build(nil, pkgs.NewIndex(nil))
	if c.RunningKernel != "" || len(c.Notes) == 0 {
		t.Errorf("missing evidence must be noted: %+v", c)
	}
}

func TestNewerInstalledImage(t *testing.T) {
	idx := pkgs.NewIndex([]pkgs.InstalledPackage{
		hostPkg("linux-image-6.8.0-100-generic", "linux-signed-hwe-6.8", "6.8.0-100.100~22.04.1"),
		hostPkg("linux-modules-6.8.0-100-generic", "linux-hwe-6.8", "6.8.0-100.100~22.04.1"),
		hostPkg("linux-image-6.8.0-106-generic", "linux-hwe-6.8", "6.8.0-106.106~22.04.1"),
	})
	c := Build(&evidence.Kernel{RunningKernel: "6.8.0-100-generic"}, idx)
	cmp := func(a, b string) (int, error) {
		// simple stub: compare by ABI number embedded in version
		if a == b {
			return 0, nil
		}
		if a < b {
			return -1, nil
		}
		return 1, nil
	}
	img := c.NewerInstalledImage("6.8.0-104.104~22.04.1", cmp)
	if img == nil || img.PackageName != "linux-image-6.8.0-106-generic" {
		t.Errorf("newer installed image: %+v", img)
	}
	if img2 := c.NewerInstalledImage("6.8.0-200.200", cmp); img2 != nil {
		t.Errorf("no image satisfies fix, got %+v", img2)
	}
}
