package resolver

import (
	"testing"

	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

func packagesModule(status string, truncated bool, codes ...string) []any {
	var errs []any
	for _, c := range codes {
		errs = append(errs, map[string]any{"code": c, "module_id": "packages", "message": c})
	}
	m := map[string]any{"module_id": "packages", "status": status, "errors": errs}
	if truncated {
		m["truncated"] = true
	}
	return []any{m}
}

// Every case must keep findings.json honest: a host with nothing usable is
// missing coverage (exit 1), a damaged but usable inventory is partial.
func TestInventoryGaps(t *testing.T) {
	jammy := tf.UbuntuRule("CVE-2024-0001", "jammy", "bash", "bash", "released", "5.0")
	cases := []struct {
		name      string
		doc       *tf.Doc
		state     string
		gaps      []string // kinds, in order
		count     int      // invalid_package_records count
		unknownPR int      // package_record unknowns
		wantError bool
	}{
		{name: "empty packages list", doc: tf.NewUbuntuJammyARM64().Set("packages", []any{}),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "packages key missing", doc: tf.NewUbuntuJammyARM64(),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "packages null", doc: tf.NewUbuntuJammyARM64().Set("packages", nil),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "module unavailable no_packages", doc: tf.NewUbuntuJammyARM64().Set("modules", packagesModule("unavailable", false, "no_packages")),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "module empty with stray records", doc: tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").Set("modules", packagesModule("empty", false)),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "no_packages error code with stray records", doc: tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").Set("modules", packagesModule("error", false, "no_packages")),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "packages module failed without records", doc: tf.NewUbuntuJammyARM64().Set("modules", packagesModule("error", false, "timeout")),
			state: CoverageMissing, gaps: []string{GapNoPackages}, wantError: true},
		{name: "only wrong-type records",
			doc:   tf.NewUbuntuJammyARM64().AddRawRecord("packages", "bash").AddRawRecord("packages", 42),
			state: CoverageMissing, gaps: []string{GapInvalidPackageRecords, GapNoPackages}, count: 2, unknownPR: 2, wantError: true},
		{name: "only empty versions",
			doc:   tf.NewUbuntuJammyARM64().AddPackage("bash", "").AddPackage("zlib1g", ""),
			state: CoverageMissing, gaps: []string{GapInvalidPackageRecords, GapNoPackages}, count: 2, unknownPR: 2, wantError: true},
		{name: "some malformed records",
			doc:   tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").AddRawRecord("packages", []any{1}).AddRawRecord("packages", map[string]any{"version": "1"}),
			state: CoveragePartial, gaps: []string{GapInvalidPackageRecords}, count: 2, unknownPR: 2},
		{name: "host list truncated (module flag)",
			doc:   tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").Set("modules", packagesModule("partial", true, "package_limit_truncated")),
			state: CoveragePartial, gaps: []string{GapPackagesTruncated}},
		{name: "packages module timed out with records",
			doc:   tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").Set("modules", packagesModule("error", false, "timeout")),
			state: CoveragePartial, gaps: []string{GapPackagesTruncated}},
		{name: "container truncation in top-level errors",
			doc:   tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").Set("errors", []any{map[string]any{"code": "package_limit_truncated", "module_id": "containers"}}),
			state: CoveragePartial, gaps: []string{GapPackagesTruncated}},
		{name: "container record flag",
			doc: tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1").
				AddRawRecord("containers", map[string]any{"container_id": "c1", "packages_truncated": true, "package_limit": 500}),
			state: CoveragePartial, gaps: []string{GapPackagesTruncated}},
		{name: "unknown distribution",
			doc:   tf.NewUbuntuJammyARM64().SetOS(map[string]any{"distribution_id": "fooos", "version_id": "1.0"}).AddPackage("bash", "5.1"),
			state: CoverageMissing, gaps: []string{GapUnknownDistribution}, wantError: true},
		{name: "distribution_id missing",
			doc:   tf.NewUbuntuJammyARM64().SetOS(map[string]any{"distribution_id": ""}).AddPackage("bash", "5.1"),
			state: CoverageMissing, gaps: []string{GapUnknownDistribution}, wantError: true},
		{name: "busybox: no operating_system, no packages",
			doc:   tf.NewUbuntuJammyARM64().Delete("operating_system").Set("modules", packagesModule("unavailable", false, "no_packages")),
			state: CoverageMissing, gaps: []string{GapNoPackages, GapUnknownDistribution}, wantError: true},
		{name: "healthy host", doc: tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1"),
			state: CoverageCovered},
		{name: "windows host without packages is not no_packages", doc: tf.NewWindowsServer2022("1000"),
			state: CoverageMissing, gaps: []string{GapMissingRules}, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := resolve(t, tc.doc, jammy)
			cov := res.RuleCoverage
			if cov.State != tc.state {
				t.Fatalf("state %q, want %q (gaps %+v)", cov.State, tc.state, cov.Gaps)
			}
			var kinds []string
			for _, g := range cov.Gaps {
				kinds = append(kinds, g.Kind)
				if g.Kind == GapInvalidPackageRecords && g.Count != tc.count {
					t.Fatalf("invalid count %d, want %d", g.Count, tc.count)
				}
			}
			if len(kinds) != len(tc.gaps) {
				t.Fatalf("gaps %v, want %v", kinds, tc.gaps)
			}
			for i := range kinds {
				if kinds[i] != tc.gaps[i] {
					t.Fatalf("gaps %v, want %v", kinds, tc.gaps)
				}
			}
			pr := 0
			for _, u := range res.Unknowns {
				if u.Kind == "package_record" {
					pr++
				}
			}
			if pr != tc.unknownPR {
				t.Fatalf("package_record unknowns %d, want %d: %+v", pr, tc.unknownPR, res.Unknowns)
			}
			for _, g := range cov.Gaps {
				found := false
				for _, u := range res.Unknowns {
					if u.Kind == "rule_coverage" && u.Reason == g.Kind {
						found = true
					}
				}
				if !found {
					t.Fatalf("gap %s has no unknowns entry", g.Kind)
				}
			}
			if err := cov.EvaluationError("host.openness"); (err != nil) != tc.wantError {
				t.Fatalf("EvaluationError %v, want error %v", err, tc.wantError)
			}
		})
	}
}
