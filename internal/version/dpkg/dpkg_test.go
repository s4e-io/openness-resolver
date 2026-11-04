package dpkg

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

// Required regression pairs from the task specification.
func TestRequiredRegressionPairs(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:8.9p1-3ubuntu0.15", "1:8.9p1-3ubuntu0.16", -1},
		{"1.2.3~rc1-0ubuntu1", "1.2.3-0ubuntu1", -1},
		{"2:1.0-1", "1:99.0-99", 1},
		{"1.0-1ubuntu1", "1.0-1ubuntu2", -1},
		{"1.0", "1.0-0", 0},
	}
	for _, c := range cases {
		if got := mustCompare(t, c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSemantics(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Epoch dominates.
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		// Tilde sorts before everything, including empty.
		{"1.0~", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		// Numeric vs non-numeric segments.
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0b", -1},
		{"1.10", "1.9", 1},
		{"1.01", "1.1", 0},
		// Letters sort before non-letters.
		{"1.0a1", "1.0+1", -1},
		// Long numeric segments (no integer overflow).
		{"1.999999999999999999999999998", "1.999999999999999999999999999", -1},
		{"1.123456789012345678901234567890", "1.123456789012345678901234567890", 0},
		// Missing revision equivalent to -0.
		{"1.0", "1.0-1", -1},
		// Ubuntu revision suffixes.
		{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.16", -1},
		{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.15", 0},
		{"1.13.1+dfsg-1ubuntu0.1~esm1", "1.13.1+dfsg-1ubuntu0.1", -1},
		// Plus and dot ordering.
		{"1.0+b1", "1.0.1", -1}, // '+' (order 299) > end but '.'... validated against dpkg in corpus
	}
	for _, c := range cases {
		if got := mustCompare(t, c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry.
		if got := mustCompare(t, c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestInvalidVersions(t *testing.T) {
	invalid := []string{"", "abc:1.0", "1.0:", ":1.0", "1.0-", "  "}
	for _, v := range invalid {
		if _, err := Compare(v, "1.0"); err == nil {
			t.Errorf("expected error for %q", v)
		}
	}
}

// TestNativeCorpus validates the Go implementation against fixtures generated
// with native `dpkg --compare-versions` (testdata/dpkg/corpus.txt, format:
// "a b <|=|>" per line).
func TestNativeCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/dpkg/corpus.txt")
	if err != nil {
		t.Skipf("dpkg corpus not available: %v", err)
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
	if n < 500 {
		t.Errorf("corpus has only %d comparisons; at least 500 required", n)
	}
	fmt.Printf("dpkg corpus: %d comparisons, %d failures\n", n, failures)
}
