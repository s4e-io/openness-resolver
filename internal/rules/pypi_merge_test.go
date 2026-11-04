package rules

import "testing"

func TestMergePyPIKeepsPackagesFromTheFirstAsset(t *testing.T) {
	existing := []PackageVulnerabilityRule{
		{RuleID: "a", PackageName: "pkg-a"},
		{RuleID: "b-old", PackageName: "pkg-b"},
	}
	fresh := []PackageVulnerabilityRule{
		{RuleID: "b-new", PackageName: "pkg-b"},
	}
	merged, names := MergePyPI(existing, []string{"pkg-a", "pkg-b"}, fresh, []string{"pkg-b", "pkg-c"})
	if len(merged) != 2 || merged[0].RuleID != "a" || merged[1].RuleID != "b-new" {
		t.Fatalf("merged=%+v", merged)
	}
	if len(names) != 3 || names[0] != "pkg-a" || names[1] != "pkg-b" || names[2] != "pkg-c" {
		t.Fatalf("names=%v", names)
	}
}

func TestMergePyPIDropsRefreshedPackageThatHasNoVulnerabilities(t *testing.T) {
	existing := []PackageVulnerabilityRule{{RuleID: "old", PackageName: "pkg-a"}}
	merged, names := MergePyPI(existing, []string{"pkg-a"}, nil, []string{"pkg-a"})
	if len(merged) != 0 {
		t.Fatalf("stale rules kept: %+v", merged)
	}
	if len(names) != 1 || names[0] != "pkg-a" {
		t.Fatalf("names=%v", names)
	}
}
