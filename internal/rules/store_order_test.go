package rules

import (
	"os"
	"path/filepath"
	"testing"
)

// The same rules in any order are written as the same bytes, so a data mirror that ships
// rules.json sees a change only when the rules changed.
func TestSaveRulesWritesAStableOrder(t *testing.T) {
	rs := []PackageVulnerabilityRule{
		{RuleID: "b", CVEID: "CVE-2"}, {RuleID: "a", CVEID: "CVE-1"}, {RuleID: "a", CVEID: "CVE-0"},
	}
	rev := []PackageVulnerabilityRule{rs[2], rs[0], rs[1]}
	meta := FeedSourceMetadata{SourceName: "x", PackageNames: []string{"z", "a"}}
	read := func(list []PackageVulnerabilityRule, m FeedSourceMetadata) (string, string) {
		dir := t.TempDir()
		if err := NewStore(dir).SaveRules("v", "r", list, m); err != nil {
			t.Fatal(err)
		}
		a, _ := os.ReadFile(filepath.Join(dir, "normalized", "v", "r", "rules.json"))
		b, _ := os.ReadFile(filepath.Join(dir, "normalized", "v", "r", "metadata.json"))
		return string(a), string(b)
	}
	r1, m1 := read(rs, meta)
	meta.PackageNames = []string{"a", "z"}
	r2, m2 := read(rev, meta)
	if r1 != r2 || m1 != m2 {
		t.Fatalf("order leaked into the files:\n%s\n%s", r1, r2)
	}
	if rs[0].RuleID != "b" {
		t.Fatal("SaveRules reordered the caller's slice")
	}
}
