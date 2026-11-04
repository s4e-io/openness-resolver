package backlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildStatusReport(t *testing.T) {
	b := &Backlog{Items: []ResolverBacklogItem{
		{TaskID: "T01-a", RowNumber: 1, Difficulty: 1},
		{TaskID: "T02-b", RowNumber: 2, Difficulty: 3},
	}}
	statuses := map[string]StatusEntry{
		"T01-a":    {Status: StatusTested},
		"T99-gone": {Status: StatusDeferred},
	}
	rep := b.BuildStatusReport(statuses, "x.json")
	if rep.Counts[StatusTested] != 1 || rep.Counts[StatusNotStarted] != 1 {
		t.Errorf("counts=%v", rep.Counts)
	}
	if len(rep.UnknownTaskIDs) != 1 || rep.UnknownTaskIDs[0] != "T99-gone" {
		t.Errorf("stale statuses must be reported: %v", rep.UnknownTaskIDs)
	}
}

func TestLoadStatusFile(t *testing.T) {
	dir := t.TempDir()
	// Missing file: every task defaults to not_started.
	m, err := LoadStatusFile(filepath.Join(dir, "missing.json"))
	if err != nil || len(m) != 0 {
		t.Errorf("missing file must yield empty map: %v %v", m, err)
	}
	// Invalid status value must be rejected.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"T01":{"status":"done"}}`), 0o644)
	if _, err := LoadStatusFile(bad); err == nil {
		t.Error("invalid status must fail")
	}
	good := filepath.Join(dir, "good.json")
	os.WriteFile(good, []byte(`{"T01":{"status":"tested","notes":"x"}}`), 0o644)
	m, err = LoadStatusFile(good)
	if err != nil || m["T01"].Status != StatusTested {
		t.Errorf("good file: %v %v", m, err)
	}
}
