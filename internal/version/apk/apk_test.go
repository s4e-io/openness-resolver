package apk

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

func mustCompare(t *testing.T, a, b string) int {
	t.Helper()
	c, err := Compare(a, b)
	if err != nil {
		t.Fatalf("Compare(%q,%q): %v", a, b, err)
	}
	return c
}

func TestSemantics(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Revision ordering.
		{"1.2.13-r0", "1.2.13-r1", -1},
		{"1.36.1-r5", "1.36.1-r15", -1},
		{"1.0", "1.0-r0", -1}, // no revision < -r0 in apk semantics
		// Pre-release suffixes sort before release.
		{"1.0_alpha", "1.0", -1},
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_beta", "1.0_pre", -1},
		{"1.0_pre", "1.0_rc1", -1},
		{"1.0_rc1", "1.0_rc2", -1},
		{"0.8.1_rc1-r1", "0.8.1-r0", -1},
		// Post-release suffixes sort after release.
		{"1.0_p1", "1.0", 1},
		{"1.0_git20230101", "1.0", 1},
		// Numeric ordering.
		{"1.9.4-r0", "1.10.0-r0", -1},
		{"0.9", "0.10", -1},
		{"1.1.1l-r0", "1.1.1n-r0", -1},
		// Letters after digits.
		{"1.0a", "1.0b", -1},
		{"1.0", "1.0a", -1},
		// Component count.
		{"1.0", "1.0.1", -1},
		{"2.38-r0", "2.38.1-r0", -1},
		// Equality.
		{"3.4.3-r1", "3.4.3-r1", 0},
	}
	for _, c := range cases {
		if got := mustCompare(t, c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
		if got := mustCompare(t, c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestInvalid(t *testing.T) {
	for _, v := range []string{"", " "} {
		if _, err := Compare(v, "1.0"); err == nil {
			t.Errorf("expected error for %q", v)
		}
	}
}

// TestNativeCorpus validates against fixtures labeled by native
// `apk version -t` (testdata/apk/corpus.txt).
func TestNativeCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/apk/corpus.txt")
	if err != nil {
		t.Skipf("apk corpus not available: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n, failures := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			t.Fatalf("bad corpus line: %q", line)
		}
		want := map[string]int{"<": -1, "=": 0, ">": 1}[parts[2]]
		got, err := Compare(parts[0], parts[1])
		if err != nil {
			t.Errorf("corpus %q: %v", line, err)
			failures++
			continue
		}
		if got != want {
			t.Errorf("corpus mismatch: Compare(%q,%q)=%d, native=%d", parts[0], parts[1], got, want)
			failures++
		}
		n++
	}
	if n < 300 {
		t.Errorf("corpus has only %d comparisons; at least 300 required", n)
	}
	fmt.Printf("apk corpus: %d comparisons, %d failures\n", n, failures)
}
