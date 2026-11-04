package alpine

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

const sampleSecdb = `{
  "distroversion": "v3.18",
  "reponame": "main",
  "packages": [
    {"pkg": {"name": "busybox", "secfixes": {
      "1.36.1-r7": ["CVE-2023-42363", "CVE-2023-42364"],
      "1.36.1-r2": ["CVE-2022-48174"],
      "0": ["CVE-2022-30065"]
    }}},
    {"pkg": {"name": "openssl", "secfixes": {
      "3.1.4-r0": ["CVE-2023-5678 (openssl advisory)"]
    }}},
    {"pkg": {"name": "", "secfixes": {"1.0-r0": ["CVE-0000-0000"]}}}
  ]
}`

func TestParseSecdb(t *testing.T) {
	meta := rules.FeedSourceMetadata{RawObjectID: "test", SourceURL: "https://example.invalid/secdb"}
	res, err := Parse(strings.NewReader(sampleSecdb), meta)
	if err != nil {
		t.Fatal(err)
	}
	if res.Branch != "v3.18" {
		t.Errorf("branch=%q", res.Branch)
	}
	if len(res.Rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(res.Rules))
	}
	byCVE := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range res.Rules {
		byCVE[r.CVEID] = r
	}
	r := byCVE["CVE-2023-42363"]
	if r.PackageName != "busybox" || r.FixedVersion != "1.36.1-r7" || r.Status != rules.StatusReleased {
		t.Errorf("busybox rule wrong: %+v", r)
	}
	if r.Comparator != "apk" || r.Release != "v3.18" || r.SourcePriority != 1 {
		t.Errorf("rule metadata wrong: %+v", r)
	}
	// "0" means never affected -> not_affected, no fixed version claimed.
	na := byCVE["CVE-2022-30065"]
	if na.Status != rules.StatusNotAffected || na.FixedVersion != "" {
		t.Errorf("version-0 semantics wrong: %+v", na)
	}
	// Annotated CVE ids are split; the annotation is preserved as notes.
	ann := byCVE["CVE-2023-5678"]
	if ann.PackageName != "openssl" {
		t.Errorf("annotated cve entry wrong: %+v", ann)
	}
	if !strings.Contains(ann.VendorNotes, "openssl advisory") {
		t.Errorf("annotation lost: %q", ann.VendorNotes)
	}
	// Nameless package rejected with a reason.
	if res.Metrics.RejectionReasons["package_without_name"] != 1 {
		t.Errorf("rejections=%v", res.Metrics.RejectionReasons)
	}
	if res.Metrics.PackagesSeen != 2 {
		t.Errorf("packages seen=%d", res.Metrics.PackagesSeen)
	}
}

func TestParseSecdbInvalid(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"reponame":"main"}`), rules.FeedSourceMetadata{}); err == nil {
		t.Error("expected error for missing distroversion")
	}
	if _, err := Parse(strings.NewReader(`not json`), rules.FeedSourceMetadata{}); err == nil {
		t.Error("expected error for malformed json")
	}
}
