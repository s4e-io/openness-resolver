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
	// GapOSBuildUnknown: a Windows host whose build number or UBR could not
	// be read, so its MSRC rules cannot be compared (missing, exit 1).
	GapOSBuildUnknown = "os_build_unknown"
	// GapApplicationsIncomplete: the Windows applications module failed, timed
	// out or was cut, so installed applications may be missing (partial).
	GapApplicationsIncomplete = "applications_incomplete"
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
	// ContainersCut names why the containers module may have dropped
	// container records (timeout, output size cut, failure); "" when not.
	ContainersCut string
	// ApplicationsCut names why the Windows applications module may have
	// dropped applications; "" when it succeeded or is absent.
	ApplicationsCut string
}

// packageModuleSignals reads the collector's packages module status and its
// truncation signals (top-level errors, module errors, module
// truncated flag, container packages_truncated), and whether the containers
// and Windows applications modules may have dropped records.
func packageModuleSignals(doc *evidence.Document, ctrs []evidence.TypedRecord[evidence.ContainerValue], h *inventoryHealth) {
	for _, m := range doc.Modules {
		switch m.ModuleID {
		case "containers":
			h.ContainersCut = moduleCut(m, false)
		case "applications":
			h.ApplicationsCut = moduleCut(m, true)
		}
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
			case "timeout", "output_size_truncated", "output_size_limit":
				// output_size_truncated is the collector's code; output_size_limit
				// is kept for older evidence.
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

// moduleCut says why a module's records may be incomplete: a timeout or an
// output size or record limit cut (error codes), the truncated flag, or, when failedCounts,
// any status other than success. "" when the module is complete. The
// containers module reports unreadable package databases per container
// (packages_error) and is partial for them; that is not a cut.
func moduleCut(m evidence.ModuleRun, failedCounts bool) string {
	packageLimit := false
	for _, e := range m.Errors {
		switch c := errorCode(e); c {
		case "timeout", "output_size_truncated", "output_size_limit", "record_limit":
			return c
		case "package_limit_truncated":
			packageLimit = true
		}
	}
	// A package cap alone sets the truncated flag too; it is reported as
	// packages_truncated, not as dropped records.
	if m.Truncated && !packageLimit {
		return "truncated"
	}
	if m.Status == "error" {
		return "module error"
	}
	if failedCounts && m.Status != "" && m.Status != "success" {
		return "module status " + m.Status
	}
	return ""
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

// inventoryGaps reports the holes in the host inventory. Windows hosts are
// evaluated by build number and installed applications, not packages: they
// get os_build_unknown and applications_incomplete instead of package gaps.
// A containers module that may have dropped container records is a
// container_not_covered gap on every platform.
func inventoryGaps(plat platform.PlatformContext, support platform.SupportState, reason string, assetPlatform string, h inventoryHealth) []CoverageGap {
	var gaps []CoverageGap
	if h.ContainersCut != "" {
		gaps = append(gaps, CoverageGap{Release: "containers", Kind: GapContainerNotCovered,
			Detail: "the collector's containers module did not finish (" + h.ContainersCut + "); containers may be missing from the evaluation"})
	}
	if plat.DistributionID == "windows" || strings.EqualFold(assetPlatform, "windows") {
		label := hostLabel(plat)
		if plat.DistributionID != "windows" || plat.WindowsBuild == "" {
			if reason == "" {
				reason = "windows identity missing from evidence"
			}
			gaps = append(gaps, CoverageGap{Release: label, Kind: GapOSBuildUnknown, Detail: reason})
		}
		if h.ApplicationsCut != "" {
			gaps = append(gaps, CoverageGap{Release: label, Kind: GapApplicationsIncomplete,
				Detail: "the collector's applications module did not finish (" + h.ApplicationsCut + "); installed applications may be missing"})
		}
		return gaps
	}
	label := hostLabel(plat)
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
