package resolver

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"

	_ "github.com/s4e-io/openness-resolver/internal/version/apk"
	_ "github.com/s4e-io/openness-resolver/internal/version/dpkg"
	_ "github.com/s4e-io/openness-resolver/internal/version/pep440"
)

func TestUbuntuPythonDPKGCorrelatesToCanonicalFinding(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("python3-urllib3", "1.26.5-1~exp1ubuntu0.3", tf.WithSource("python-urllib3")).
		AddPythonDistribution(map[string]any{
			"entity_id":           "py-dist:urllib3:host",
			"evidence_id":         "ev-py-urllib3",
			"environment_id":      "python:env:system",
			"name_normalized":     "urllib3",
			"name_raw":            "urllib3",
			"version":             "1.26.5",
			"raw_version_string":  "1.26.5",
			"resolver_ecosystem":  "ubuntu_dpkg",
			"runtime_load_status": "installed_not_proven_loaded",
			"os_binary_package":   "python3-urllib3",
			"os_source_package":   "python-urllib3",
			"os_package_version":  "1.26.5-1~exp1ubuntu0.3",
		})

	res := resolve(t, doc, tf.UbuntuRule(
		"CVE-2023-TEST", "jammy", "python-urllib3", "python3-urllib3",
		rules.StatusReleased, "1.26.5-1~exp1ubuntu0.4",
	))

	host := mustFinding(t, res, "python3-urllib3", "CVE-2023-TEST")
	if len(host.PythonDistributionEntityIDs) != 1 || host.PythonDistributionEntityIDs[0] != "py-dist:urllib3:host" {
		t.Fatalf("expected python correlation on canonical finding, got %+v", host.PythonDistributionEntityIDs)
	}
	if len(res.DeduplicatedFindings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(res.DeduplicatedFindings))
	}
	if res.DeduplicatedFindings[0].CanonicalFindingID != host.FindingID {
		t.Fatalf("deduplicated finding must reference canonical id")
	}
	for _, f := range res.Findings {
		if f.ResolverEcosystem == "ubuntu_dpkg" {
			t.Fatalf("ubuntu_dpkg must not emit separate python-scoped finding: %+v", f)
		}
	}
	if !res.Reconciliation.Balanced {
		t.Fatalf("reconciliation not balanced: %+v metrics=%+v", res.Reconciliation, res.Metrics)
	}
}

func TestPyPIEnvironmentFindingsAreDistinct(t *testing.T) {
	vulnEnv := "python:env:vulnerable"
	fixedEnv := "python:env:fixed"
	doc := tf.NewUbuntuJammyARM64().
		AddPythonDistribution(map[string]any{
			"entity_id":             "py-dist:demo:vuln",
			"evidence_id":           "ev-py-vuln",
			"environment_id":        vulnEnv,
			"name_normalized":       "demo-pkg",
			"name_raw":              "demo_pkg",
			"version":               "1.0.0",
			"raw_version_string":    "1.0.0",
			"resolver_ecosystem":    "pypi",
			"runtime_load_status":   "confirmed_loaded",
			"loaded_by_process_ids": []any{4242},
		}).
		AddPythonDistribution(map[string]any{
			"entity_id":           "py-dist:demo:fixed",
			"evidence_id":         "ev-py-fixed",
			"environment_id":      fixedEnv,
			"name_normalized":     "demo-pkg",
			"name_raw":            "demo_pkg",
			"version":             "2.0.0",
			"raw_version_string":  "2.0.0",
			"resolver_ecosystem":  "pypi",
			"runtime_load_status": "installed_not_proven_loaded",
		})

	res := resolve(t, doc, tf.PyPIRule("CVE-2024-DEMO", "demo-pkg", "GHSA-demo", rules.StatusReleased, "1.5.0"))

	var vulnF, fixedF *findings.Finding
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Scope != ScopePythonEnvironment {
			continue
		}
		switch f.EnvironmentID {
		case vulnEnv:
			vulnF = f
		case fixedEnv:
			fixedF = f
		}
	}
	if vulnF == nil || fixedF == nil {
		t.Fatalf("expected two python_environment findings, got %d py findings", res.Reconciliation.PythonEnvironmentFindings)
	}
	if vulnF.FindingID == fixedF.FindingID {
		t.Fatal("vulnerable and fixed environments must have distinct finding ids")
	}
	if vulnF.State != findings.StateVulnerable {
		t.Fatalf("vulnerable env state=%s", vulnF.State)
	}
	if fixedF.State != findings.StateFixed {
		t.Fatalf("fixed env state=%s", fixedF.State)
	}
	if vulnF.Comparison == nil || vulnF.Comparison.Comparator != "pep440" {
		t.Fatalf("missing pep440 comparison on vulnerable finding")
	}
	if vulnF.RuntimeLoadStatus != "confirmed_loaded" {
		t.Fatalf("runtime_load_status=%q", vulnF.RuntimeLoadStatus)
	}
	if fixedF.RuntimeLoadStatus != "installed_not_proven_loaded" {
		t.Fatalf("runtime_load_status=%q", fixedF.RuntimeLoadStatus)
	}
	if res.Reconciliation.PythonEnvironmentFindings != 2 {
		t.Fatalf("expected 2 python environment findings, got %d", res.Reconciliation.PythonEnvironmentFindings)
	}
}

func TestAdvisoryOnlyFindingNeverUsesUSNAsCVEID(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("apport", "2.20.11-0ubuntu82.10", tf.WithSource("apport"))
	rule := tf.UbuntuRule("", "jammy", "apport", "apport", rules.StatusReleased, "2.20.11-0ubuntu82.8")
	rule.CVEID = "USN-7545-2"
	rule.AdvisoryIDs = []string{"USN-7545-2"}
	res := resolve(t, doc, rule)

	var adv *findings.Finding
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.BinaryPackage == "apport" && f.FindingType == findings.FindingTypeAdvisoryOnly {
			adv = f
			break
		}
	}
	if adv == nil {
		t.Fatal("expected advisory-only finding")
	}
	if adv.CVEID != "" {
		t.Fatalf("cve_id must be empty for advisory-only, got %q", adv.CVEID)
	}
	if len(adv.AdvisoryIDs) != 1 || adv.AdvisoryIDs[0] != "USN-7545-2" {
		t.Fatalf("advisory_ids=%v", adv.AdvisoryIDs)
	}
}
