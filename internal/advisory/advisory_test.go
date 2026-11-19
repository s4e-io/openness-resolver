package advisory

import "testing"

func TestBuiltinLoadsAndHasRules(t *testing.T) {
	s := Builtin()
	if len(s.Advisories) == 0 || s.Version == "" {
		t.Fatalf("empty advisory set %+v", s)
	}
	got := s.ForSourcePackage("dpkg", "ubuntu", "noble", "openjdk-17")
	if len(got) != 1 || got[0].FixedVersion != "17.0.21.1+2-1~24.04.1" || got[0].CVEID != "CVE-2026-114938" ||
		got[0].AdvisoryIDs[0] != "USN-9155-1" || got[0].PackageName != "" || got[0].Comparator != "dpkg" {
		t.Fatalf("noble openjdk-17 rule: %+v", got)
	}
	// Ubuntu 20.04's fix is in the Ubuntu Pro pocket only.
	if f := s.ForSourcePackage("dpkg", "ubuntu", "focal", "openjdk-17"); len(f) != 1 || f[0].SupportTier != "esm-apps" {
		t.Fatalf("focal rule: %+v", f)
	}
	if s.ForSourcePackage("dpkg", "ubuntu", "noble", "openjdk-11") != nil {
		t.Fatal("a package the advisory does not name got a rule")
	}
	// A rule ID sorts after the feeds' own, so on equal fixed versions the feed's advisory wins.
	if got[0].RuleID < "ubuntu:" {
		t.Fatalf("rule id %q sorts before the feed's", got[0].RuleID)
	}
}

func TestEvaluateInstance(t *testing.T) {
	a := Builtin().Advisories[0]
	for _, tc := range []struct {
		version, verdict, fixed string
	}{
		{"1.8.0_391", NotAffected, ""},
		{"8.0.392", NotAffected, ""},
		{"11.0.20", NotAffected, ""},
		{"17.0.5", NotAffected, ""},
		{"17.0.6", Affected, "17.0.21.1"},
		{"17.0.21", Affected, "17.0.21.1"},
		{"17.0.21.1", Fixed, "17.0.21.1"},
		{"17.0.22", Fixed, "17.0.21.1"},
		{"21.0.13", Affected, "21.0.13.1"},
		{"21.0.13.1", Fixed, "21.0.13.1"},
		{"25.0.5+8", Affected, "25.0.5.1"},
		{"27.0.1.1", Fixed, "27.0.1.1"},
		{"19.0.2", Affected, ""}, // end-of-life line: affected, no fix on the line
		{"26", Affected, ""},
		{"", Unknown, ""},
		{"garbage", Unknown, ""},
	} {
		v, f := a.EvaluateInstance(tc.version)
		if v != tc.verdict || f != tc.fixed {
			t.Errorf("%q: got %s %q, want %s %q", tc.version, v, f, tc.verdict, tc.fixed)
		}
	}
}

func TestAffectsArchitecture(t *testing.T) {
	a := Builtin().Advisories[0]
	for arch, want := range map[string]bool{
		"x86_64": true, "amd64": true, "X64": true, "arm64": false, "aarch64": false, "": true, "riscv64": false,
	} {
		if got := a.AffectsArchitecture(arch); got != want {
			t.Errorf("%q: got %v want %v", arch, got, want)
		}
	}
	if !(Advisory{}).AffectsArchitecture("arm64") {
		t.Error("an advisory without architectures affects every architecture")
	}
}

func TestParseRejectsIncomplete(t *testing.T) {
	for _, raw := range []string{
		`{"advisories":[{"id":"x"}]}`,
		`{"advisories":[{"id":"x","cve":"CVE-1","packages":[{"ecosystem":"dpkg"}]}]}`,
		`not json`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
