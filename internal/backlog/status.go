package backlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Task lifecycle states. A task may only be marked StatusTested when unit
// tests, integration tests, real .openness evidence processing, vendor
// ground-truth checks, CSV edge-case coverage, and regression tests all
// exist.
const (
	StatusNotStarted = "not_started"
	StatusInProgress = "in_progress"
	StatusImplement  = "implemented"
	StatusTested     = "tested"
	StatusBlocked    = "blocked"
	StatusDeferred   = "deferred"
)

var validStatuses = map[string]bool{
	StatusNotStarted: true,
	StatusInProgress: true,
	StatusImplement:  true,
	StatusTested:     true,
	StatusBlocked:    true,
	StatusDeferred:   true,
}

// StatusEntry is the curated, human-maintained status for one CSV task.
type StatusEntry struct {
	Status    string   `json:"status"`
	Notes     string   `json:"notes,omitempty"`
	Modules   []string `json:"modules,omitempty"`    // Go packages implementing the task
	TestRefs  []string `json:"test_refs,omitempty"`  // test functions/files covering it
	BlockedOn []string `json:"blocked_on,omitempty"` // task IDs this depends on
	UpdatedAt string   `json:"updated_at,omitempty"`
}

// TaskStatus is one row of the generated backlog-status report: the CSV task
// joined with its curated status.
type TaskStatus struct {
	TaskID               string   `json:"task_id"`
	RowNumber            int      `json:"row_number"`
	CollectedInformation string   `json:"collected_information"`
	VulnerabilityType    string   `json:"vulnerability_type"`
	Difficulty           int      `json:"difficulty"`
	Status               string   `json:"status"`
	Notes                string   `json:"notes,omitempty"`
	Modules              []string `json:"modules,omitempty"`
	TestRefs             []string `json:"test_refs,omitempty"`
	BlockedOn            []string `json:"blocked_on,omitempty"`
	UpdatedAt            string   `json:"updated_at,omitempty"`
}

// StatusReport is the full generated build/backlog-status.json document.
type StatusReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	SourceCSV   string         `json:"source_csv"`
	StatusFile  string         `json:"status_file"`
	Counts      map[string]int `json:"counts"`
	Tasks       []TaskStatus   `json:"tasks"`
	// UnknownTaskIDs lists status entries that do not match any CSV task,
	// so stale statuses are reported instead of silently dropped.
	UnknownTaskIDs []string `json:"unknown_task_ids,omitempty"`
}

// LoadStatusFile reads the curated status map (task ID -> StatusEntry).
// A missing file is not an error: every task is then not_started.
func LoadStatusFile(path string) (map[string]StatusEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]StatusEntry{}, nil
		}
		return nil, fmt.Errorf("read status file: %w", err)
	}
	var m map[string]StatusEntry
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse status file %s: %w", path, err)
	}
	for id, e := range m {
		if !validStatuses[e.Status] {
			return nil, fmt.Errorf("status file %s: task %s has invalid status %q", path, id, e.Status)
		}
	}
	return m, nil
}

// BuildStatusReport joins the parsed backlog with the curated statuses.
func (b *Backlog) BuildStatusReport(statuses map[string]StatusEntry, statusFile string) *StatusReport {
	rep := &StatusReport{
		GeneratedAt: time.Now().UTC(),
		SourceCSV:   b.SourceFile,
		StatusFile:  statusFile,
		Counts:      map[string]int{},
	}
	seen := map[string]bool{}
	for _, it := range b.Items {
		e, ok := statuses[it.TaskID]
		if !ok {
			e = StatusEntry{Status: StatusNotStarted}
		}
		seen[it.TaskID] = true
		rep.Counts[e.Status]++
		rep.Tasks = append(rep.Tasks, TaskStatus{
			TaskID:               it.TaskID,
			RowNumber:            it.RowNumber,
			CollectedInformation: it.CollectedInformation,
			VulnerabilityType:    it.VulnerabilityType,
			Difficulty:           it.Difficulty,
			Status:               e.Status,
			Notes:                e.Notes,
			Modules:              e.Modules,
			TestRefs:             e.TestRefs,
			BlockedOn:            e.BlockedOn,
			UpdatedAt:            e.UpdatedAt,
		})
	}
	for id := range statuses {
		if !seen[id] {
			rep.UnknownTaskIDs = append(rep.UnknownTaskIDs, id)
		}
	}
	return rep
}

// WriteStatusReport writes the report as JSON, creating parent directories.
func (r *StatusReport) Write(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
