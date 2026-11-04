package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// PreflightExpectations are mandatory checks before resolver validation runs.
type PreflightExpectations struct {
	Filename         string
	SHA256           string
	CollectorVersion string
	SchemaVersion    string
	CollectionID     string
}

// PreflightResult captures verified evidence metadata.
type PreflightResult struct {
	Path             string
	SHA256           string
	CollectorVersion string
	SchemaVersion    string
	CollectionID     string
	Fallback         bool
}

// RunPreflight verifies the evidence file path and document metadata.
func RunPreflight(path string, exp PreflightExpectations) (*Document, *PreflightResult, error) {
	if path == "" {
		return nil, nil, fmt.Errorf("evidence path is required")
	}
	if exp.Filename != "" && !endsWithBase(path, exp.Filename) {
		return nil, nil, fmt.Errorf("evidence file must be %q (got %q)", exp.Filename, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	dec := json.NewDecoder(io.TeeReader(f, h))
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("decode evidence: %w", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	res := &PreflightResult{
		Path:             path,
		SHA256:           sum,
		CollectorVersion: doc.Collector.Version,
		SchemaVersion:    doc.SchemaVersion,
		CollectionID:     doc.Collection.CollectionID,
		Fallback:         false,
	}
	if exp.SHA256 != "" && sum != exp.SHA256 {
		return nil, nil, fmt.Errorf("sha256 mismatch: expected %s got %s", exp.SHA256, sum)
	}
	if exp.CollectorVersion != "" && doc.Collector.Version != exp.CollectorVersion {
		return nil, nil, fmt.Errorf("collector version mismatch: expected %s got %s", exp.CollectorVersion, doc.Collector.Version)
	}
	if exp.SchemaVersion != "" && doc.SchemaVersion != exp.SchemaVersion {
		return nil, nil, fmt.Errorf("schema version mismatch: expected %s got %s", exp.SchemaVersion, doc.SchemaVersion)
	}
	if exp.CollectionID != "" && doc.Collection.CollectionID != exp.CollectionID {
		return nil, nil, fmt.Errorf("collection id mismatch: expected %s got %s", exp.CollectionID, doc.Collection.CollectionID)
	}
	return &doc, res, nil
}

func endsWithBase(path, name string) bool {
	i := len(path) - len(name)
	if i < 0 {
		return false
	}
	if i > 0 && path[i-1] != '/' && path[i-1] != '\\' {
		return false
	}
	return path[i:] == name
}
