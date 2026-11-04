package containers

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

func contRec(id, digest, ref, state string, packages []evidence.ContainerPackage) evidence.TypedRecord[evidence.ContainerValue] {
	return evidence.TypedRecord[evidence.ContainerValue]{
		EvidenceID: "ev-" + id,
		Value: evidence.ContainerValue{
			ContainerID: id, Name: id, Runtime: "docker",
			ImageDigest: digest, ImageReference: ref, State: state,
			Packages: packages, PackageCount: len(packages),
		},
	}
}

func alpinePkgs318() []evidence.ContainerPackage {
	return []evidence.ContainerPackage{
		{Name: "alpine-baselayout", RawVersionString: "3.4.3-r1", PackageManager: "apk", Architecture: "x86_64"},
		{Name: "busybox", RawVersionString: "1.36.1-r5", PackageManager: "apk", Architecture: "x86_64"},
	}
}

// Same digest with different tags must form one group.
func TestSameDigestMultipleTags(t *testing.T) {
	inv := BuildInventory([]evidence.TypedRecord[evidence.ContainerValue]{
		contRec("c1", "sha256:aaa", "img:latest", "running", alpinePkgs318()),
		contRec("c2", "sha256:aaa", "img:v2", "running", alpinePkgs318()),
	})
	if len(inv.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(inv.Groups))
	}
	if len(inv.Groups[0].Containers) != 2 {
		t.Errorf("group must hold both containers")
	}
	// Packages counted once per image, not per container.
	if len(inv.Groups[0].Packages) != 2 {
		t.Errorf("packages duplicated: %d", len(inv.Groups[0].Packages))
	}
}

// Same tag, different digest -> separate groups (tags are not identity).
func TestSameTagDifferentDigest(t *testing.T) {
	inv := BuildInventory([]evidence.TypedRecord[evidence.ContainerValue]{
		contRec("c1", "sha256:aaa", "img:latest", "running", alpinePkgs318()),
		contRec("c2", "sha256:bbb", "img:latest", "running", alpinePkgs318()),
	})
	if len(inv.Groups) != 2 {
		t.Fatalf("expected 2 groups (digest is identity, not tag), got %d", len(inv.Groups))
	}
}

func TestMissingDigest(t *testing.T) {
	inv := BuildInventory([]evidence.TypedRecord[evidence.ContainerValue]{
		contRec("c1", "", "img:latest", "running", alpinePkgs318()),
	})
	if len(inv.Groups) != 0 || len(inv.MissingDigest) != 1 {
		t.Errorf("groups=%d missing=%d", len(inv.Groups), len(inv.MissingDigest))
	}
}

func TestStoppedAndRunningContainers(t *testing.T) {
	inv := BuildInventory([]evidence.TypedRecord[evidence.ContainerValue]{
		contRec("c1", "sha256:aaa", "img", "exited", alpinePkgs318()),
		contRec("c2", "sha256:aaa", "img", "running", alpinePkgs318()),
	})
	g := inv.Groups[0]
	if got := g.RunningContainerIDs(); len(got) != 1 || got[0] != "c2" {
		t.Errorf("running ids=%v", got)
	}
	if got := g.ContainerIDs(); len(got) != 2 {
		t.Errorf("all ids=%v", got)
	}
}

func TestAlpineBranchInference(t *testing.T) {
	cases := []struct {
		name     string
		packages []evidence.ContainerPackage
		want     string
	}{
		{"3.18 via baselayout r1", []evidence.ContainerPackage{
			{Name: "alpine-baselayout", RawVersionString: "3.4.3-r1", PackageManager: "apk"},
		}, "v3.18"},
		{"3.19 via baselayout r2", []evidence.ContainerPackage{
			{Name: "alpine-baselayout", RawVersionString: "3.4.3-r2", PackageManager: "apk"},
		}, "v3.19"},
		{"3.14 via baselayout+busybox", []evidence.ContainerPackage{
			{Name: "alpine-baselayout", RawVersionString: "3.2.0-r16", PackageManager: "apk"},
			{Name: "busybox", RawVersionString: "1.33.1-r6", PackageManager: "apk"},
		}, "v3.14"},
		{"ambiguous 3.2.0 without busybox", []evidence.ContainerPackage{
			{Name: "alpine-baselayout", RawVersionString: "3.2.0-r16", PackageManager: "apk"},
		}, ""},
		{"no anchors", []evidence.ContainerPackage{
			{Name: "curl", RawVersionString: "8.4.0-r0", PackageManager: "apk"},
		}, ""},
	}
	for _, c := range cases {
		branch, conf, _ := inferAlpineBranch(c.packages)
		if branch != c.want {
			t.Errorf("%s: branch=%q, want %q", c.name, branch, c.want)
		}
		if c.want != "" && conf != "inferred" {
			t.Errorf("%s: confidence=%q, want inferred", c.name, conf)
		}
	}
}

func TestDetectDistro(t *testing.T) {
	if d := detectDistro(alpinePkgs318()); d != "alpine" {
		t.Errorf("distro=%q", d)
	}
	if d := detectDistro([]evidence.ContainerPackage{{Name: "libc6", PackageManager: "dpkg"}}); d != "debian-family" {
		t.Errorf("distro=%q", d)
	}
	if d := detectDistro(nil); d != "" {
		t.Errorf("distro=%q for scratch image", d)
	}
}
