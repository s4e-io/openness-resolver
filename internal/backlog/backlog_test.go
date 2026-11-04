package backlog

import (
	"strings"
	"testing"
)

const header = "Collected Information,Vulnerability Type,Vulnerable Decision Rule,Implementation Approach,Difficulty,Critical Edge Cases,Primary Data Sources"

func TestParseDifficulty(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"1/5", 1, false},
		{"2/5", 2, false},
		{"3/5", 3, false},
		{"4/5", 4, false},
		{"5/5", 5, false},
		{" 3/5 ", 3, false},
		{"6/5", 0, true},
		{"0/5", 0, true},
		{"3", 0, true},
		{"", 0, true},
		{"three/5", 0, true},
	}
	for _, c := range cases {
		got, err := ParseDifficulty(c.in)
		if c.wantErr != (err != nil) {
			t.Errorf("ParseDifficulty(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
		}
		if got != c.want {
			t.Errorf("ParseDifficulty(%q)=%d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseValidRow(t *testing.T) {
	csv := header + "\n" +
		`"Binary package + exact version",OS package CVEs,Installed version lower than fixed,Collect with dpkg-query,2/5,"Epoch, tilde; never SemVer",Ubuntu OVAL/USN; Alpine secdb` + "\n"
	b, err := Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(b.Items))
	}
	it := b.Items[0]
	if it.Difficulty != 2 {
		t.Errorf("difficulty=%d, want 2", it.Difficulty)
	}
	if len(it.EdgeCases) != 2 {
		t.Errorf("edge cases=%v, want 2 entries", it.EdgeCases)
	}
	if len(it.PrimaryDataSources) != 2 {
		t.Errorf("sources=%v, want 2 entries", it.PrimaryDataSources)
	}
	if !strings.HasPrefix(it.TaskID, "T01-binary-package") {
		t.Errorf("unexpected task id %q", it.TaskID)
	}
	if len(b.Errors()) != 0 {
		t.Errorf("unexpected validation errors: %v", b.Errors())
	}
}

func TestMissingRequiredColumn(t *testing.T) {
	csv := "Collected Information,Vulnerability Type\nfoo,bar\n"
	if _, err := Parse(strings.NewReader(csv)); err == nil {
		t.Fatal("expected error for missing columns")
	}
}

func TestUnknownColumnDoesNotBreak(t *testing.T) {
	csv := header + ",Extra Column\n" + "info,type,rule,impl,1/5,edge,src,extra-value\n"
	b, err := Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.UnknownColumn) != 1 || b.UnknownColumn[0] != "Extra Column" {
		t.Errorf("unknown columns=%v", b.UnknownColumn)
	}
	if len(b.Items) != 1 {
		t.Fatalf("expected 1 item")
	}
}

func TestValidationErrors(t *testing.T) {
	csv := header + "\n" +
		"info,type,,impl,9/5,edge,\n" // empty rule, bad difficulty, no sources
	b, err := Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	errs := b.Errors()
	if len(errs) != 3 {
		t.Fatalf("expected 3 errors, got %d: %v", len(errs), errs)
	}
}

func TestDuplicateDetection(t *testing.T) {
	csv := header + "\n" +
		"info,type,rule,impl,1/5,edge,src\n" +
		"info,type,rule2,impl2,2/5,edge2,src2\n"
	b, err := Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range b.Issues {
		if is.Severity == "warning" && strings.Contains(is.Message, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate warning, issues=%v", b.Issues)
	}
}
