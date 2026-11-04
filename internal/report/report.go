// Package report renders resolver run results for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/resolver"
)

// missingCoverageTitle names the holes, not the host release. A covered Ubuntu
// host with a missing Alpine image must not read as "no rules for ubuntu/jammy".
func missingCoverageTitle(cov resolver.RuleCoverage) string {
	if len(cov.Gaps) == 0 {
		if cov.AssetRelease != "" {
			return cov.AssetRelease
		}
		return "unspecified release"
	}
	parts := make([]string, len(cov.Gaps))
	for i, g := range cov.Gaps {
		parts[i] = g.Release
	}
	return strings.Join(parts, ", ")
}

// WriteJSON writes the full run result (findings + metrics) as JSON.
func WriteJSON(res *resolver.RunResult, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Summary prints a human-readable run summary.
// Note: counters are package-scope rule coverage, not "CVE coverage".
func Summary(res *resolver.RunResult, w io.Writer) {
	m := res.Metrics
	fmt.Fprintf(w, "asset: %s   platform: %s %s (%s) %s   support: %s\n",
		res.AssetID, res.Platform.DistributionID, res.Platform.DistributionVersion,
		res.Platform.Codename, res.Platform.Architecture, res.PlatformSupport)
	if res.SupportReason != "" {
		fmt.Fprintf(w, "support note: %s\n", res.SupportReason)
	}
	if res.PlatformSupport == "supported" && !res.PlatformTested {
		fmt.Fprintf(w, "platform note: supported but not tested on a real host (verified with mock data only)\n")
	}
	switch res.RuleCoverage.State {
	case resolver.CoverageCovered:
		fmt.Fprintf(w, "rule coverage: %d rules loaded for %s\n", res.RuleCoverage.RulesForAsset, res.RuleCoverage.AssetRelease)
	case resolver.CoverageMissing:
		loaded := "none"
		if len(res.RuleCoverage.LoadedReleases) > 0 {
			loaded = strings.Join(res.RuleCoverage.LoadedReleases, ", ")
		}
		fmt.Fprintf(w, "\nNO RULE COVERAGE FOR %s\n", missingCoverageTitle(res.RuleCoverage))
		fmt.Fprintf(w, "  loaded releases: %s\n", loaded)
		if res.RuleCoverage.Reason != "" {
			fmt.Fprintf(w, "  %s\n", res.RuleCoverage.Reason)
		} else {
			fmt.Fprintf(w, "  no package of this asset was evaluated; the finding counts below are not an all-clear\n")
		}
		missingRules := false
		for _, g := range res.RuleCoverage.Gaps {
			fmt.Fprintf(w, "  gap: %s (%s)\n", g.Release, g.Kind)
			if g.Kind == resolver.GapMissingRules {
				missingRules = true
			}
		}
		if missingRules {
			fmt.Fprintf(w, "  fix: openness-resolver feed sync --for <evidence.openness>\n")
		}
	}
	fmt.Fprintf(w, "\npackages:\n")
	fmt.Fprintf(w, "  asset packages:              %d\n", m.AssetPackages)
	fmt.Fprintf(w, "  host packages:               %d\n", m.HostPackages)
	fmt.Fprintf(w, "  container packages:          %d\n", m.ContainerPackages)
	fmt.Fprintf(w, "  with source package:         %d\n", m.PackagesWithSourcePackage)
	fmt.Fprintf(w, "  with vendor rules:           %d\n", m.PackagesWithVendorRules)
	fmt.Fprintf(w, "  without vendor rules:        %d\n", m.PackagesWithoutVendorRules)
	fmt.Fprintf(w, "\nrules:\n")
	fmt.Fprintf(w, "  considered:                  %d\n", m.RulesConsidered)
	fmt.Fprintf(w, "  applicable:                  %d\n", m.RulesApplicable)
	fmt.Fprintf(w, "  rejected (not applicable):   %d\n", m.RulesRejected)
	fmt.Fprintf(w, "  comparator errors:           %d\n", m.ComparatorErrors)
	fmt.Fprintf(w, "\nfindings:\n")
	fmt.Fprintf(w, "  vulnerable:                  %d\n", m.FindingsVulnerable)
	fmt.Fprintf(w, "  fixed:                       %d\n", m.FindingsFixed)
	fmt.Fprintf(w, "  not applicable:              %d\n", m.FindingsNotApplicable)
	fmt.Fprintf(w, "  potentially vulnerable:      %d\n", m.FindingsPotentially)
	fmt.Fprintf(w, "  unknown:                     %d\n", m.FindingsUnknown)
	fmt.Fprintf(w, "  conflicting evidence:        %d\n", m.FindingsConflicting)
	fmt.Fprintf(w, "  vulnerable runtime:          %d\n", m.FindingsVulnerableRuntime)
	fmt.Fprintf(w, "\nsoftware inventory:          %d instances (no product feed yet; see software_inventory[])\n", len(res.SoftwareInventory))
	fmt.Fprintf(w, "unknowns:                    %d (see unknowns[])\n", len(res.Unknowns))
	fmt.Fprintf(w, "\nremediation groups:          %d (closes %d)\n",
		res.Reconciliation.RemediationGroups, res.Reconciliation.RemediationCloses)
	fmt.Fprintf(w, "output schema:               %s\n", res.OutputSchemaVersion)
	fmt.Fprintf(w, "\nresolver duration: %d ms\n", m.ResolverDurationMS)
	if len(res.Notes) > 0 {
		fmt.Fprintf(w, "\nnotes (%d):\n", len(res.Notes))
		max := len(res.Notes)
		if max > 20 {
			max = 20
		}
		for _, n := range res.Notes[:max] {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		if len(res.Notes) > 20 {
			fmt.Fprintf(w, "  ... and %d more (see JSON output)\n", len(res.Notes)-20)
		}
	}
}
