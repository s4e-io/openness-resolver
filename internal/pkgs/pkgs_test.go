package pkgs

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

func strp(s string) *string { return &s }

func rec(v evidence.PackageValue) evidence.TypedRecord[evidence.PackageValue] {
	return evidence.TypedRecord[evidence.PackageValue]{EvidenceID: "ev1", Value: v}
}

// Task 2 required raw-version preservation cases.
func TestRawVersionPreservation(t *testing.T) {
	cases := []struct {
		raw   string
		epoch string
		pm    string
	}{
		{"1:8.9p1-3ubuntu0.16", "1", "dpkg"},
		{"3.0.7-30.el9_2", "", "rpm"},
		{"2:1.18.0-6ubuntu14.7", "2", "dpkg"},
		{"1.2.3~rc1-0ubuntu1", "", "dpkg"},
		{"1.2.13-r1", "", "apk"},
	}
	for _, c := range cases {
		p, err := FromHostRecord(rec(evidence.PackageValue{
			Name:             "x",
			RawVersionString: c.raw,
			Epoch:            strp(c.epoch),
			PackageManager:   c.pm,
			Architecture:     "arm64",
		}))
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if p.RawVersion != c.raw {
			t.Errorf("raw version mutated: %q -> %q", c.raw, p.RawVersion)
		}
		if p.Epoch != c.epoch {
			t.Errorf("%s: epoch=%q, want %q", c.raw, p.Epoch, c.epoch)
		}
	}
}

func TestIdentityIncludesScopeArchVersion(t *testing.T) {
	host, _ := FromHostRecord(rec(evidence.PackageValue{Name: "openssl", RawVersionString: "3.0.2-0ubuntu1.15", PackageManager: "dpkg", Architecture: "arm64"}))
	cont, _ := FromContainerPackage(evidence.ContainerPackage{Name: "openssl", RawVersionString: "3.0.2-0ubuntu1.15", PackageManager: "dpkg", Architecture: "arm64"}, "sha256:abc", "ev2")
	if host.IdentityKey() == cont.IdentityKey() {
		t.Error("host and container identities must differ")
	}
	a, _ := FromHostRecord(rec(evidence.PackageValue{Name: "libssl3", RawVersionString: "3.0.2-0ubuntu1.15", PackageManager: "dpkg", Architecture: "arm64"}))
	b, _ := FromHostRecord(rec(evidence.PackageValue{Name: "libssl3", RawVersionString: "3.0.2-0ubuntu1.15", PackageManager: "dpkg", Architecture: "amd64"}))
	if a.IdentityKey() == b.IdentityKey() {
		t.Error("architecture must be part of identity")
	}
}

// Task 3: direct source mapping from dpkg metadata.
func TestSourceMappingDirect(t *testing.T) {
	p, _ := FromHostRecord(rec(evidence.PackageValue{
		Name: "libssl3", RawVersionString: "3.0.2-0ubuntu1.15", PackageManager: "dpkg",
		SourcePackage: "openssl",
		Relationships: []evidence.Relationship{{
			Confidence: "direct", EvidenceSource: "dpkg:Source",
			TargetEntityID: "srcpkg:dpkg:openssl", Type: "package_built_from_source_package",
		}},
	}))
	if p.SourcePackage != "openssl" {
		t.Errorf("source=%q", p.SourcePackage)
	}
	if p.Source.Confidence != "direct" || p.Source.EvidenceSource != "dpkg:Source" {
		t.Errorf("relationship=%+v", p.Source)
	}
}

// Task 3: source field with embedded version "openssh (1:8.9p1-3ubuntu0.16)".
func TestSourceFieldWithVersion(t *testing.T) {
	p, _ := FromHostRecord(rec(evidence.PackageValue{
		Name: "openssh-client", RawVersionString: "1:8.9p1-3ubuntu0.16", PackageManager: "dpkg",
		SourcePackage: "openssh (1:8.9p1-3ubuntu0.16)",
	}))
	if p.SourcePackage != "openssh" {
		t.Errorf("source=%q, want openssh", p.SourcePackage)
	}
	if p.Source.SourceVersion != "1:8.9p1-3ubuntu0.16" {
		t.Errorf("source version=%q", p.Source.SourceVersion)
	}
	if p.Source.Confidence != "direct" {
		t.Errorf("confidence=%q, want direct", p.Source.Confidence)
	}
}

// Task 3: missing source metadata falls back to the binary name, marked inferred.
func TestSourceFallbackIsInferred(t *testing.T) {
	p, _ := FromHostRecord(rec(evidence.PackageValue{
		Name: "accountsservice", RawVersionString: "22.07.5-2ubuntu1.5", PackageManager: "dpkg",
	}))
	if p.SourcePackage != "accountsservice" {
		t.Errorf("source=%q", p.SourcePackage)
	}
	if p.Source.Confidence != "inferred" || p.Source.EvidenceSource != "binary_name_fallback" {
		t.Errorf("fallback must be visible as inferred: %+v", p.Source)
	}
}

// Kernel binaries: unusual source packages must pass through unchanged.
func TestKernelSourcePackage(t *testing.T) {
	p, _ := FromHostRecord(rec(evidence.PackageValue{
		Name: "linux-image-6.8.0-106-generic", RawVersionString: "6.8.0-106.108", PackageManager: "dpkg",
		SourcePackage: "linux-signed",
	}))
	if p.SourcePackage != "linux-signed" || p.Source.Confidence != "direct" {
		t.Errorf("got %+v", p.Source)
	}
}

func TestMultiarchIndexing(t *testing.T) {
	p1, _ := FromHostRecord(rec(evidence.PackageValue{Name: "libc6", RawVersionString: "2.35-0ubuntu3.8", PackageManager: "dpkg", Architecture: "arm64", SourcePackage: "glibc"}))
	p2, _ := FromHostRecord(rec(evidence.PackageValue{Name: "libc6", RawVersionString: "2.35-0ubuntu3.8", PackageManager: "dpkg", Architecture: "armhf", SourcePackage: "glibc"}))
	idx := NewIndex([]InstalledPackage{p1, p2})
	if got := len(idx.BySourcePackage[HostScopeKey()]["glibc"]); got != 2 {
		t.Errorf("expected 2 multiarch entries, got %d", got)
	}
	if idx.Duplicates != 0 {
		t.Errorf("no duplicates expected, got %d", idx.Duplicates)
	}
	// The same package twice must be counted as duplicate.
	idx2 := NewIndex([]InstalledPackage{p1, p1})
	if idx2.Duplicates != 1 {
		t.Errorf("expected 1 duplicate, got %d", idx2.Duplicates)
	}
}

func TestMissingVersionRejected(t *testing.T) {
	if _, err := FromHostRecord(rec(evidence.PackageValue{Name: "x", PackageManager: "dpkg"})); err == nil {
		t.Error("expected error for missing raw_version_string")
	}
}

func TestProvenanceClassification(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		status string
		want   string
	}{
		{"ubuntu archive", "Ubuntu", "matched_apt_lists", ProvenanceVendor},
		{"esm archive", "UbuntuESMApps", "matched_apt_lists", ProvenanceVendor},
		{"third party", "Docker", "matched_apt_lists", ProvenanceThirdParty},
		{"not in apt lists is unknown, never local", "", "not_in_apt_lists", ProvenanceUnknown},
		{"origin present but unmatched", "Ubuntu", "not_in_apt_lists", ProvenanceUnknown},
		{"no repo evidence collected", "", "", ""},
	}
	for _, c := range cases {
		p := InstalledPackage{RepositoryOrigin: c.origin, RepositoryMetadataStatus: c.status}
		if got := p.Provenance("ubuntu"); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// Debian origin on an Ubuntu asset is third-party: never silently apply
	// cross-distro trust.
	p := InstalledPackage{RepositoryOrigin: "Debian", RepositoryMetadataStatus: "matched_apt_lists"}
	if got := p.Provenance("ubuntu"); got != ProvenanceThirdParty {
		t.Errorf("debian origin on ubuntu asset: %q", got)
	}
}
