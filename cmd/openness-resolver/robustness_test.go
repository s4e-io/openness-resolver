package main

// Hostile evidence and data: a host the resolver could not evaluate must never
// read as clean. findings.json is always written; exit 1 when the asset was not
// evaluated (the NO RULE COVERAGE path), exit 0 for a partial inventory.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// signEvidence sets integrity.payload_hash the way the collector computes it.
func signEvidence(doc map[string]any) {
	doc["integrity"] = map[string]any{"algorithm": "", "payload_hash": "", "signature": "", "signing_key_id": ""}
	raw, _ := json.Marshal(doc)
	sum := sha256.Sum256(raw)
	doc["integrity"] = map[string]any{"algorithm": "SHA-256", "payload_hash": hex.EncodeToString(sum[:]), "signature": "", "signing_key_id": ""}
}

type coverageOut struct {
	Asset struct {
		EvidenceIntegrity string `json:"evidence_integrity"`
	} `json:"asset"`
	RuleCoverage struct {
		State string `json:"state"`
		Gaps  []struct {
			Kind  string `json:"kind"`
			Count int    `json:"count"`
		} `json:"gaps"`
	} `json:"rule_coverage"`
	Unknowns []struct {
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	} `json:"unknowns"`
}

func readRunCoverage(t *testing.T, path string) coverageOut {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("findings.json not written: %v", err)
	}
	var out coverageOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantCoverage checks state and gap kinds (with counts as "kind=N").
func wantCoverage(state string, gaps ...string) func(t *testing.T, tmp string, _ cliResult) {
	return func(t *testing.T, tmp string, _ cliResult) {
		t.Helper()
		out := readRunCoverage(t, filepath.Join(tmp, "out.json"))
		var got []string
		for _, g := range out.RuleCoverage.Gaps {
			k := g.Kind
			if g.Count > 0 {
				k += "=" + strconv.Itoa(g.Count)
			}
			got = append(got, k)
		}
		if out.RuleCoverage.State != state || strings.Join(got, ",") != strings.Join(gaps, ",") {
			t.Fatalf("rule_coverage state=%s gaps=%v, want %s %v", out.RuleCoverage.State, got, state, gaps)
		}
	}
}

func TestResolveHostileEvidence(t *testing.T) {
	sh := shared(t)
	in := filepath.Join("{tmp}", "host.openness")
	out := filepath.Join("{tmp}", "out.json")
	ubuntu := func(edit func(doc map[string]any)) func(t *testing.T, tmp string) {
		return func(t *testing.T, tmp string) {
			writeEvidence(t, filepath.Join(tmp, "host.openness"), "ubuntu-22.04-jammy", edit)
		}
	}
	resolveArgs := []string{"resolve", "--input", in, "--data-dir", sh.data, "--output", out}
	preflightArgs := append(append([]string{}, resolveArgs...), "--preflight")
	noPackages := func(doc map[string]any) { doc["packages"] = []any{} }
	malformed := func(doc map[string]any) {
		doc["packages"] = []any{
			map[string]any{"evidence_id": "p1", "value": "bash"},
			map[string]any{"evidence_id": "p2", "value": map[string]any{"name": "zlib1g", "raw_version_string": ""}},
		}
	}
	unknownDistro := func(doc map[string]any) {
		os := doc["operating_system"].(map[string]any)
		os["distribution_id"], os["version_id"], os["version_codename"] = "fooos", "99", "zzz"
	}
	runFlagCases(t, []flagCase{
		{name: "zero packages", args: resolveArgs, setup: ubuntu(noPackages), code: 1,
			stdout: []string{"NO RULE COVERAGE", "no_packages"}, stderr: []string{"no packages to evaluate"},
			check: wantCoverage("missing", "no_packages")},
		{name: "zero packages preflight", args: preflightArgs, setup: ubuntu(noPackages), code: 1,
			stdout: []string{"NO RULE COVERAGE"}, check: wantCoverage("missing", "no_packages")},
		{name: "packages key missing", args: resolveArgs, setup: ubuntu(func(doc map[string]any) { delete(doc, "packages") }), code: 1,
			check: wantCoverage("missing", "no_packages")},
		{name: "only malformed package records", args: resolveArgs, setup: ubuntu(malformed), code: 1,
			check: wantCoverage("missing", "invalid_package_records=2", "no_packages")},
		{name: "only malformed package records preflight", args: preflightArgs, setup: ubuntu(malformed), code: 1,
			check: wantCoverage("missing", "invalid_package_records=2", "no_packages")},
		{name: "one malformed record among good ones", args: resolveArgs, code: 0,
			setup: ubuntu(func(doc map[string]any) {
				doc["packages"] = append(doc["packages"].([]any), map[string]any{"evidence_id": "bad", "value": 42})
			}),
			stdout: []string{"rule coverage: partial"},
			check: func(t *testing.T, tmp string, r cliResult) {
				wantCoverage("partial", "invalid_package_records=1")(t, tmp, r)
				found := false
				for _, u := range readRunCoverage(t, filepath.Join(tmp, "out.json")).Unknowns {
					found = found || u.Kind == "package_record"
				}
				if !found {
					t.Fatal("no package_record unknown")
				}
			}},
		{name: "collector truncated the package list", args: resolveArgs, code: 0,
			setup: ubuntu(func(doc map[string]any) {
				doc["modules"] = []any{map[string]any{"module_id": "packages", "status": "partial", "truncated": true,
					"errors": []any{map[string]any{"code": "package_limit_truncated", "message": "cut"}}}}
			}),
			check: wantCoverage("partial", "packages_truncated")},
		{name: "unknown distribution", args: resolveArgs, setup: ubuntu(unknownDistro), code: 1,
			stdout: []string{"NO RULE COVERAGE"}, check: wantCoverage("missing", "unknown_distribution")},
		{name: "distribution_id missing", args: resolveArgs, code: 1,
			setup: ubuntu(func(doc map[string]any) { doc["operating_system"].(map[string]any)["distribution_id"] = nil }),
			check: wantCoverage("missing", "unknown_distribution")},
		{name: "busybox: no os, packages module unavailable", args: resolveArgs, code: 1,
			setup: ubuntu(func(doc map[string]any) {
				delete(doc, "operating_system")
				delete(doc, "packages")
				doc["modules"] = []any{map[string]any{"module_id": "packages", "status": "unavailable",
					"errors": []any{map[string]any{"code": "no_packages", "message": "no supported package manager found"}}}}
			}),
			check: wantCoverage("missing", "no_packages", "unknown_distribution")},
		{name: "payload hash verified", args: resolveArgs, setup: ubuntu(signEvidence),
			check: func(t *testing.T, tmp string, _ cliResult) {
				if got := readRunCoverage(t, filepath.Join(tmp, "out.json")).Asset.EvidenceIntegrity; got != "verified" {
					t.Fatalf("evidence_integrity=%q", got)
				}
			}},
		{name: "payload hash absent is accepted with a note", args: resolveArgs, setup: ubuntu(func(map[string]any) {}),
			stdout: []string{"no integrity.payload_hash"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if got := readRunCoverage(t, filepath.Join(tmp, "out.json")).Asset.EvidenceIntegrity; got != "not_present" {
					t.Fatalf("evidence_integrity=%q", got)
				}
			}},
		{name: "payload hash mismatch", args: resolveArgs, code: 1,
			setup: ubuntu(func(doc map[string]any) {
				signEvidence(doc)
				doc["asset"].(map[string]any)["hostname"] = "changed-after-collection"
			}),
			stderr: []string{"evidence integrity check failed", "host.openness"}},
		{name: "payload hash mismatch preflight", args: preflightArgs, code: 1,
			setup: ubuntu(func(doc map[string]any) {
				signEvidence(doc)
				doc["packages"] = doc["packages"].([]any)[1:]
			}),
			stderr: []string{"evidence integrity check failed"}},
	})
}

func TestResolveCorruptRulesFileNamesIt(t *testing.T) {
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data")
	dir := filepath.Join(data, "normalized", "ubuntu", "jammy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rulesFile := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesFile, []byte(`[{"rule_id":`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run(t, "resolve", "--input", evidencePath("ubuntu-22.04-jammy"), "--data-dir", data, "--output", filepath.Join(tmp, "out.json"))
	if r.Code != 1 || !strings.Contains(r.Stderr, rulesFile) {
		t.Fatalf("exit %d, stderr does not name %s:\n%s", r.Code, rulesFile, r.Stderr)
	}
}
