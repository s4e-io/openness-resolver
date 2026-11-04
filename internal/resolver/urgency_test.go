package resolver

import "testing"

func TestNormalizeUrgency(t *testing.T) {
	for in, want := range map[string]string{"Medium": "medium", " high ": "high", "None": "", "": "", "not yet assigned": "", "important": "important"} {
		if got := normalizeUrgency(in); got != want {
			t.Errorf("normalizeUrgency(%q) = %q, want %q", in, got, want)
		}
	}
}
