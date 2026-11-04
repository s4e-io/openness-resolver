package rules

import "testing"

func TestFormatIDFollowsParsers(t *testing.T) {
	a := Format(map[string]string{"ubuntu-oval": "1.1.0", "msrc-cvrf": "1.0.0"})
	b := Format(map[string]string{"msrc-cvrf": "1.0.0", "ubuntu-oval": "1.1.0"})
	c := Format(map[string]string{"msrc-cvrf": "1.0.0", "ubuntu-oval": "1.2.0"})
	if a.ID != b.ID || len(a.ID) != 12 {
		t.Fatalf("same parsers, different ids: %s %s", a.ID, b.ID)
	}
	if a.ID == c.ID {
		t.Fatal("a parser version change must change the id")
	}
	if a.Format != RulesFormat {
		t.Fatalf("format %q", a.Format)
	}
}
