package rpm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/version"
)

// TestRpmvercmpCorpus replays rpm's own rpmvercmp test vectors.
func TestRpmvercmpCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/rpm/rpmvercmp.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			t.Fatalf("bad corpus line %q", line)
		}
		want, _ := strconv.Atoi(parts[2])
		if got := Vercmp(parts[0], parts[1]); got != want {
			t.Errorf("Vercmp(%q,%q)=%d, want %d", parts[0], parts[1], got, want)
		}
		n++
	}
	if n < 80 {
		t.Fatalf("corpus too small: %d", n)
	}
}

func TestCompareEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Epoch dominates everything.
		{"1:1.0-1", "2.0-1", 1},
		{"2.0-1", "1:1.0-1", -1},
		{"1:1.1.1k-4.el8", "1:1.1.1k-12.el8_9", -1},
		{"2:1.0-1", "1:99.0-99", 1},
		// Missing epoch == epoch 0.
		{"0:1.0-1", "1.0-1", 0},
		{"1.0-1", "0:1.0-1", 0},
		{"00:1.0-1", "0:1.0-1", 0},
		// Release comparison.
		{"3.0.7-16.el9_2", "3.0.7-6.el9_2", 1},
		{"3.0.7-6.el9_2", "3.0.7-16.el9_2", -1},
		{"1.1.1k-16.el8_6", "1.1.1k-14.el8_10", 1},
		{"1.1.1k-14.el8_6", "1.1.1k-14.el8_10", -1},
		{"5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4", 0},
		{"5.14.0-427.13.1.el9_4", "5.14.0-503.11.1.el9_5", -1},
		// Version before release.
		{"1.2-100", "1.10-1", -1},
		// Rebuild suffixes.
		{"3.5.8-1.el10_2", "3.5.8-1.el10_2.alma.1", -1},
		{"1.0-1.el9", "1.0-1.el9.1", -1},
		// Tilde and caret in versions and releases.
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0-1~beta", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0^git1-1", "1.0.1-1", -1},
		// SUSE style release numbers.
		{"3.1.4-150600.5.7.1", "3.1.4-150600.5.10.1", -1},
		{"3.1.4-150600.5.15.1", "3.1.4-150600.5.7.1", 1},
		// Release missing on one side is not compared.
		{"1.0", "1.0-5", 0},
		{"1.0-5", "1.0", 0},
		// Large numbers never overflow.
		{"1.99999999999999999999999-1", "1.100000000000000000000000-1", -1},
	}
	for _, c := range cases {
		got, err := Compare(c.a, c.b)
		if err != nil {
			t.Fatalf("Compare(%q,%q): %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	e, err := Parse("1:3.0.7-16.el9_2")
	if err != nil {
		t.Fatal(err)
	}
	if e.Epoch != "1" || e.Version != "3.0.7" || e.Release != "16.el9_2" {
		t.Fatalf("parsed %+v", e)
	}
	e, err = Parse("2.5.5-105.module+el8.1.0+3656+f80bfa1d")
	if err != nil {
		t.Fatal(err)
	}
	if e.Epoch != "0" || e.Version != "2.5.5" || e.Release != "105.module+el8.1.0+3656+f80bfa1d" {
		t.Fatalf("parsed %+v", e)
	}
}

func TestParseErrors(t *testing.T) {
	for _, v := range []string{"", "  ", ":1.0-1", "a:1.0-1", "1.0-", "-1", "1:-1", "1.0 2-1"} {
		if _, err := Compare(v, "1.0-1"); err == nil {
			t.Errorf("Compare(%q) must fail", v)
		}
	}
}

func TestRegistered(t *testing.T) {
	c, err := version.ForEcosystem("rpm")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Compare("1:1.0-1", "1.0-1"); got != 1 {
		t.Errorf("registered comparator returned %d", got)
	}
}

func TestIsModular(t *testing.T) {
	if !IsModular("0:2.5.5-105.module+el8.1.0+3656+f80bfa1d") || !IsModular("1:18.19.0-1.module_el8.9.0+3710+44ad0b4a") {
		t.Error("modular releases not detected")
	}
	if IsModular("1:1.1.1k-4.el8") {
		t.Error("plain release reported modular")
	}
}
