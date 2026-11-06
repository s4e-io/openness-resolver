package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A damaged rules.json must name the file, so the user knows what to repair.
func TestLoadNamesCorruptRulesFile(t *testing.T) {
	cases := map[string]string{
		"truncated":  `[{"rule_id":"r1","distribution":"ubuntu"`,
		"garbage":    "\xf5\x00\x01not json",
		"empty":      "",
		"wrong type": `{"rule_id":"r1"}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "normalized", "ubuntu", "jammy")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "rules.json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := NewStore(root).LoadFiltered(nil)
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("error %v does not name %s", err, path)
			}
		})
	}
}
