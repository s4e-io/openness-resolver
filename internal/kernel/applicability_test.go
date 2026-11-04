package kernel

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

func TestSourceFamilyExplicitMapping(t *testing.T) {
	tests := []struct {
		src  string
		want string
		ok   bool
	}{
		{"linux-signed-hwe-6.8", "linux-hwe-6.8", true},
		{"linux-hwe-6.8", "linux-hwe-6.8", true},
		{"linux-signed-aws-6.8", "linux-aws-6.8", true},
		{"linux-signed", "linux", true},
		{"linux-custom-unknown", "", false},
	}
	for _, tc := range tests {
		got, ok := SourceFamily(tc.src)
		if got != tc.want || ok != tc.ok {
			t.Errorf("SourceFamily(%q) = (%q, %v), want (%q, %v)", tc.src, got, ok, tc.want, tc.ok)
		}
	}
}

func TestVersionTrack(t *testing.T) {
	if got := VersionTrack("6.8.0-106.106~22.04.1"); got != "6.8.0" {
		t.Fatalf("got %q", got)
	}
	if got := VersionTrack("6.5.0-41.41~22.04.2"); got != "6.5.0" {
		t.Fatalf("got %q", got)
	}
	if VersionTrack("bad") != "" {
		t.Fatal("expected empty for bad version")
	}
}

func TestRuleApplicableExactSourceAndTrack(t *testing.T) {
	kctx := &Context{
		SourceFamily:   "linux-hwe-6.8",
		PackageVersion: "6.8.0-106.106~22.04.1",
		VersionABI:     "6.8.0-106",
		Flavour:        "generic",
	}
	okRule := &rules.PackageVulnerabilityRule{
		IsKernel:      true,
		SourcePackage: "linux-hwe-6.8",
		FixedVersion:  "6.8.0-136.136~22.04.1",
		Status:        rules.StatusReleased,
	}
	if !RuleApplicable(kctx, okRule) {
		t.Fatal("expected applicable")
	}
	awsRule := &rules.PackageVulnerabilityRule{
		IsKernel:      true,
		SourcePackage: "linux-aws-6.8",
		FixedVersion:  "6.8.0-1030.32",
		Status:        rules.StatusReleased,
	}
	if RuleApplicable(kctx, awsRule) {
		t.Fatal("linux-aws-6.8 must not apply to linux-hwe-6.8 host")
	}
	wrongTrack := &rules.PackageVulnerabilityRule{
		IsKernel:      true,
		SourcePackage: "linux-hwe-6.8",
		FixedVersion:  "6.5.0-44.44~22.04.1",
		Status:        rules.StatusReleased,
	}
	if RuleApplicable(kctx, wrongTrack) {
		t.Fatal("6.5 track rule must not apply to 6.8 running kernel")
	}
}

func TestRuleApplicableUnknownContext(t *testing.T) {
	rule := &rules.PackageVulnerabilityRule{IsKernel: true, SourcePackage: "linux-hwe-6.8"}
	if RuleApplicable(&Context{}, rule) {
		t.Fatal("empty context must not match")
	}
}
