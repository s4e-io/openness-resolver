package winbuild

import (
	"errors"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/version"
)

func TestCompare(t *testing.T) {
	c := Comparator{}
	cases := []struct {
		installed, fixed string
		want             int
		mismatch         bool
	}{
		{"20348.5000", "20348.5761", -1, false},
		{"20348.5761", "20348.5761", 0, false},
		{"20348.6000", "10.0.20348.5761", 1, false},
		{"10.0.26100.33650", "10.0.26100.33650", 0, false},
		{"26100.33650", "26100.9711", 1, false},     // Server 2025 vs Win11 24H2 stream: same build, UBR compares
		{"26200.100", "26100.9711", -1, false},      // 25H2 enablement package on 24H2: one UBR stream
		{"19044.3570", "10.0.19041.3570", 0, false}, // Oct 2023 CVRF lists 21H2 fixes as 19041
		{"22631.2861", "22621.2861", 0, false},
		{"20348.100", "25398.50", 0, true}, // Server 2022 and Server 23H2 are separate branches
		{"22000.100", "22621.50", 0, true},
		{"28000.100", "26100.50", 0, true},
		{"6.3.9600.22748", "6.3.9600.22800", -1, false},
	}
	for _, tc := range cases {
		got, err := c.Compare(tc.installed, tc.fixed)
		if tc.mismatch {
			if !errors.Is(err, ErrBuildMismatch) {
				t.Errorf("%s vs %s: want ErrBuildMismatch, got %v", tc.installed, tc.fixed, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s vs %s: got %d err=%v want %d", tc.installed, tc.fixed, got, err, tc.want)
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "26100", "x.y", "26100.-1", "0.5"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%q must not parse", s)
		}
	}
}

func TestRegistered(t *testing.T) {
	if _, err := version.ForEcosystem(Ecosystem); err != nil {
		t.Fatal(err)
	}
}

func TestOnBuild(t *testing.T) {
	cases := []struct {
		v     string
		build int
		want  string
	}{
		{"19041.3570", 19044, "19044.3570"},
		{"10.0.26100.9106", 26200, "26200.9106"},
		{"20348.5761", 20348, "20348.5761"},
		{"25398.50", 20348, "25398.50"},
		{"bad", 20348, "bad"},
	}
	for _, tc := range cases {
		if got := OnBuild(tc.v, tc.build); got != tc.want {
			t.Errorf("OnBuild(%s, %d) = %s, want %s", tc.v, tc.build, got, tc.want)
		}
	}
}
