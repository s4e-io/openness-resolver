package evidence

import (
	"io"
	"strings"
	"testing"
)

func TestParseMinimalDocument(t *testing.T) {
	doc := `{"schema_version":"1.3.2","asset":{"asset_id":"a"},"operating_system":{"distribution_id":"ubuntu"}}`
	lr, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	// Missing categories yield empty slices, never a failure.
	if len(lr.PackageRecords()) != 0 || len(lr.ContainerRecords()) != 0 {
		t.Error("missing categories must be empty")
	}
	if len(lr.RecordErrors) != 0 {
		t.Errorf("no record errors expected: %v", lr.RecordErrors)
	}
}

func TestParseRejectsMissingSchemaVersion(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"asset":{}}`)); err == nil {
		t.Error("expected error for missing schema_version")
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	base := `{"schema_version":"1.3.2"}`
	for _, suffix := range []string{`{"schema_version":"1.3.2"}`, "garbage"} {
		if _, err := Parse(strings.NewReader(base + suffix)); err == nil {
			t.Fatalf("accepted trailing %q", suffix)
		}
	}
	if _, err := Parse(strings.NewReader(base + " \n\t")); err != nil {
		t.Fatalf("rejected whitespace: %v", err)
	}
}

func TestParseRejectsOversizeEvidence(t *testing.T) {
	base := `{"schema_version":"1.3.2"}`
	spaces := io.LimitReader(spaceReader{}, MaxEvidenceBytes)
	if _, err := Parse(io.MultiReader(strings.NewReader(base), spaces)); err == nil {
		t.Fatal("accepted evidence over the size limit")
	}
}

// spaceReader yields endless spaces without holding them in memory.
type spaceReader struct{}

func (spaceReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestMalformedRecordIsCollectedNotFatal(t *testing.T) {
	doc := `{"schema_version":"1.3.2",
		"packages":[
			{"evidence_id":"good","value":{"name":"x","raw_version_string":"1.0","package_manager":"dpkg"}},
			{"evidence_id":"bad","value":{"name":123}}
		]}`
	lr, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	recs := lr.PackageRecords()
	if len(recs) != 1 || recs[0].EvidenceID != "good" {
		t.Errorf("expected 1 good record, got %d", len(recs))
	}
	if len(lr.RecordErrors) != 1 || lr.RecordErrors[0].EvidenceID != "bad" {
		t.Errorf("bad record must be reported: %v", lr.RecordErrors)
	}
}

func TestParseRejectsOtherSchemaMajor(t *testing.T) {
	for _, v := range []string{"2.0.0", "9", "0.9.0", "x.1"} {
		if _, err := Parse(strings.NewReader(`{"schema_version":"` + v + `"}`)); err == nil {
			t.Errorf("schema_version %q must be refused", v)
		}
	}
	if _, err := Parse(strings.NewReader(`{"schema_version":"1.5.0"}`)); err != nil {
		t.Fatalf("1.x must load: %v", err)
	}
}
