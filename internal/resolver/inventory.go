package resolver

import (
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/platform"
)

// Inventory gap kinds. no_packages and unknown_distribution make the run
// missing (exit 1); invalid_package_records and packages_truncated leave the
// rest evaluated and make it partial (exit 0).
const (
	// GapNoPackages: the evidence holds no usable host package (the packages
	// module was unavailable, empty, failed, or every record was malformed).
	GapNoPackages = "no_packages"
	// GapInvalidPackageRecords: package records were skipped as malformed
	// (wrong type, no name, no version). CoverageGap.Count says how many.
	GapInvalidPackageRecords = "invalid_package_records"
	// GapPackagesTruncated: the collector cut the package list (limit, timeout
	// or output size), so packages may be missing from the evaluation.
	GapPackagesTruncated = "packages_truncated"
	// GapUnknownDistribution: the host distribution is missing from the
	// evidence or is not one the resolver knows.
	GapUnknownDistribution = "unknown_distribution"
)

// inventoryHealth is what the evidence says about the host package list.
type inventoryHealth struct {
	// Usable is the number of installed host packages the resolver evaluates.
	Usable int
	// Invalid lists the package records skipped as malformed.
	Invalid []Unknown
	// ModuleStatus is the packages module status ("" when absent).
	ModuleStatus string
	// Truncated is true when the collector said it cut a package list.
	Truncated bool
	// NoPackages is true when the collector said the host has no package
	// list (module status unavailable or empty, or error code no_packages).
	NoPackages bool
}

// packageModuleSignals reads the collector's packages module status and its
// truncation signals (top-level errors, module errors, module
// truncated flag, container packages_truncated).
func packageModuleSignals(doc *evidence.Document, ctrs []evidence.TypedRecord[evidence.ContainerValue], h *inventoryHealth) {
	for _, m := range doc.Modules {
		pkgModule := m.ModuleID == "packages"
		if pkgModule {
			h.ModuleStatus = m.Status
			if m.Truncated {
				h.Truncated = true
			}
			if m.Status == "unavailable" || m.Status == "empty" {
				h.NoPackages = true
			}
		}
		for _, e := range m.Errors {
			switch errorCode(e) {
			case "no_packages":
				h.NoPackages = h.NoPackages || pkgModule
			case "package_limit_truncated":
				h.Truncated = true
			case "timeout", "output_size_limit":
				h.Truncated = h.Truncated || pkgModule
			}
		}
	}
	for _, e := range doc.Errors {
		if errorCode(e) == "package_limit_truncated" {
			h.Truncated = true
		}
	}
	for _, c := range ctrs {
		if c.Value.PackagesTruncated {
			h.Truncated = true
		}
	}
}

// errorCode returns the code of a collector error entry ({"code": ...}).
func errorCode(e any) string {
	m, ok := e.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m["code"].(string)
	return s
}

// inventoryGaps reports the holes in the host package inventory. Windows hosts
// are evaluated by build number, not packages, and are left out.
func inventoryGaps(plat platform.PlatformContext, support platform.SupportState, reason string, assetPlatform string, h inventoryHealth) []CoverageGap {
	if plat.DistributionID == "windows" || strings.EqualFold(assetPlatform, "windows") {
		return nil
	}
	label := hostLabel(plat)
	var gaps []CoverageGap
	if support == platform.UnknownState ||
		support == platform.NotSupported && !platform.Known(plat.DistributionID) {
		gaps = append(gaps, CoverageGap{Release: label, Kind: GapUnknownDistribution, Detail: reason})
	}
	switch {
	case h.Usable == 0 || h.NoPackages:
		detail := "the evidence has no usable host package"
		if h.ModuleStatus != "" && h.ModuleStatus != "ok" {
			detail += "; packages module status " + h.ModuleStatus
		}
		gaps = append(gaps, CoverageGap{Release: label, Kind: GapNoPackages, Detail: detail})
	case h.Truncated:
		gaps = append(gaps, CoverageGap{Release: label, Kind: GapPackagesTruncated, Detail: "the collector cut the package list; some packages were not evaluated"})
	}
	if n := len(h.Invalid); n > 0 {
		gaps = append(gaps, CoverageGap{Release: label, Kind: GapInvalidPackageRecords, Count: n, Detail: "malformed package records were skipped"})
	}
	return gaps
}

// hostLabel names the host release for a gap: "ubuntu/jammy", "rocky/9",
// "fooos/1.0", or "unknown" without a distribution.
func hostLabel(plat platform.PlatformContext) string {
	if plat.DistributionID == "" {
		return "unknown"
	}
	rel := plat.RuleRelease()
	if rel == "" {
		rel = plat.DistributionVersion
	}
	if rel == "" {
		return plat.DistributionID
	}
	return plat.DistributionID + "/" + rel
}
