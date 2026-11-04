package resolver

import (
	"fmt"
	"sort"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/python"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

const (
	MethodUbuntuPythonDPKG = "ubuntu_python_distribution_dpkg_fixed_version"
	MethodPyPIOSV          = "pypi_distribution_osv_fixed_version"

	ScopePythonEnvironment = "python_environment"
)

// resolvePython evaluates language_deps Python distributions (T25).
func (e *Engine) resolvePython(
	res *RunResult,
	inv *python.Inventory,
	pkgIndex *pkgs.Index,
	plat platform.PlatformContext,
	esmActive bool,
	findingIndex map[string]int,
) {
	if inv == nil || len(inv.Distributions) == 0 {
		return
	}
	res.Notes = append(res.Notes, inv.Notes...)
	for i := range inv.Distributions {
		d := &inv.Distributions[i]
		switch d.ResolverEcosystem {
		case python.EcosystemUbuntuDPKG:
			e.correlateUbuntuPythonDPKG(res, d, pkgIndex, plat, esmActive, findingIndex)
		case python.EcosystemPyPI:
			fs := e.resolvePyPIDistribution(res, d, plat)
			for _, f := range fs {
				res.Findings = append(res.Findings, f)
				findingIndex[f.FindingID] = len(res.Findings) - 1
			}
		default:
			res.Notes = append(res.Notes, fmt.Sprintf("python distribution %s skipped: unsupported resolver_ecosystem %q", d.NameNormalized, d.ResolverEcosystem))
		}
	}
}

func (e *Engine) correlateUbuntuPythonDPKG(
	res *RunResult,
	d *python.Distribution,
	pkgIndex *pkgs.Index,
	plat platform.PlatformContext,
	esmActive bool,
	findingIndex map[string]int,
) {
	if d.OSBinaryPackage == "" || d.OSPackageVersion == "" {
		res.Notes = append(res.Notes, fmt.Sprintf("ubuntu_dpkg python distribution %s missing OS package identity", d.NameNormalized))
		return
	}
	src := d.OSSourcePackage
	arch := plat.Architecture
	if host := pkgIndex.LookupHost(d.OSBinaryPackage); host != nil {
		if src == "" {
			src = host.SourcePackage
		}
		if host.Architecture != "" {
			arch = host.Architecture
		}
	}
	p := pkgs.InstalledPackage{
		Scope:         pkgs.ScopeHost,
		Ecosystem:     "dpkg",
		Name:          d.OSBinaryPackage,
		SourcePackage: src,
		RawVersion:    d.OSPackageVersion,
		Architecture:  arch,
		EvidenceID:    d.EvidenceID,
		EntityID:      d.EntityID,
	}
	candidates := map[string]*rules.PackageVulnerabilityRule{}
	for _, r := range e.Rules.ForBinaryPackage("dpkg", "ubuntu", plat.Codename, p.Name) {
		if !r.IsKernel {
			candidates[r.RuleID] = r
		}
	}
	for _, r := range e.Rules.ForSourcePackage("dpkg", "ubuntu", plat.Codename, p.SourcePackage) {
		if !r.IsKernel && ruleAppliesToInstalledBinary(p, r) {
			candidates[r.RuleID] = r
		}
	}
	if len(candidates) == 0 {
		return
	}
	evaluated := e.decidePackage(res, p, candidates, plat, MethodUbuntuPythonDPKG)
	for i := range evaluated {
		f := evaluated[i]
		if esmActive && f.FixAvailability == findings.FixRequiresESM {
			f.FixAvailability = findings.FixAvailable
		}
		groupKey := f.CVEID
		if groupKey == "" && len(f.AdvisoryIDs) > 0 {
			groupKey = "advisory:" + f.AdvisoryIDs[0]
		}
		canonicalID := findingID(res.AssetID, pkgs.ScopeHost, groupKey, d.OSBinaryPackage, d.OSPackageVersion)
		idx, ok := findingIndex[canonicalID]
		if !ok {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"python ubuntu_dpkg distribution %s/%s has no canonical host finding for %s; evaluation state=%s",
				d.NameNormalized, d.RawVersion, groupKey, f.State,
			))
			continue
		}
		mergePythonCorrelation(&res.Findings[idx], d)
		res.DeduplicatedFindings = append(res.DeduplicatedFindings, findings.DeduplicatedFinding{
			CanonicalFindingID:         canonicalID,
			ResolverEcosystem:          python.EcosystemUbuntuDPKG,
			PythonDistributionEntityID: d.EntityID,
			EnvironmentID:              d.EnvironmentID,
			NormalizedPackageName:      d.NameNormalized,
			CVEID:                      f.CVEID,
			AdvisoryIDs:                append([]string(nil), f.AdvisoryIDs...),
			FindingType:                f.FindingType,
			State:                      f.State,
			Reason:                     "Python distribution evaluation merged into canonical Ubuntu package finding",
		})
	}
}

func (e *Engine) resolvePyPIDistribution(res *RunResult, d *python.Distribution, plat platform.PlatformContext) []findings.Finding {
	candidates := map[string]*rules.PackageVulnerabilityRule{}
	for _, r := range e.Rules.ForBinaryPackage("pypi", "pypi", "", d.NameNormalized) {
		candidates[r.RuleID] = r
	}
	if len(candidates) == 0 {
		return nil
	}
	p := pkgs.InstalledPackage{
		Scope:         ScopePythonEnvironment,
		ScopeID:       d.EnvironmentID,
		Ecosystem:     "pypi",
		Name:          d.NameNormalized,
		SourcePackage: d.NameNormalized,
		RawVersion:    d.RawVersion,
		Architecture:  plat.Architecture,
		EvidenceID:    d.EvidenceID,
		EntityID:      d.EntityID,
	}
	pypiPlat := platform.PlatformContext{DistributionID: "pypi", Codename: "", Architecture: plat.Architecture}
	base := e.decidePackage(res, p, candidates, pypiPlat, MethodPyPIOSV)
	out := make([]findings.Finding, 0, len(base))
	for i := range base {
		f := base[i]
		applyPyPIFindingFields(&f, d)
		out = append(out, f)
	}
	return out
}

func mergePythonCorrelation(f *findings.Finding, d *python.Distribution) {
	appendUnique := func(list *[]string, vals ...string) {
		seen := map[string]bool{}
		for _, v := range *list {
			seen[v] = true
		}
		for _, v := range vals {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			*list = append(*list, v)
		}
	}
	appendUnique(&f.PythonDistributionEntityIDs, d.EntityID)
	appendUnique(&f.PythonEnvironmentIDs, d.EnvironmentID)
	appendUnique(&f.PythonRuntimeLoadStatus, d.RuntimeLoadStatus)
	for _, pid := range d.ProcessIDs {
		appendUnique(&f.PythonRuntimeProcessIDs, fmt.Sprintf("%d", pid))
	}
	appendUnique(&f.PythonRuntimeEvidenceIDs, d.RuntimeEvidenceIDs...)
	if d.EvidenceID != "" {
		appendUnique(&f.EvidenceIDs, d.EvidenceID)
	}
	sort.Strings(f.EvidenceIDs)
}

func applyPyPIFindingFields(f *findings.Finding, d *python.Distribution) {
	f.Scope = ScopePythonEnvironment
	if f.CVEID != "" {
		f.FindingType = findings.FindingTypeCVE
	} else if len(f.AdvisoryIDs) > 0 {
		f.FindingType = findings.FindingTypeAdvisoryOnly
	}
	f.EnvironmentID = d.EnvironmentID
	f.ResolverEcosystem = python.EcosystemPyPI
	f.NormalizedPackageName = d.NameNormalized
	f.RawPackageName = d.NameRaw
	f.RuntimeLoadStatus = d.RuntimeLoadStatus
	f.LoadedModulePaths = append([]string(nil), d.LoadedModulePaths...)
	f.BinaryPackage = d.NameNormalized
	f.SourcePackage = d.NameNormalized
	f.InstalledVersion = d.RawVersion
	groupKey := f.CVEID
	if groupKey == "" && len(f.AdvisoryIDs) > 0 {
		groupKey = "advisory:" + f.AdvisoryIDs[0]
	}
	f.FindingID = findingID(f.AssetID, ScopePythonEnvironment+":"+d.EnvironmentID, groupKey, d.NameNormalized, d.RawVersion)
	if d.EvidenceID != "" {
		f.EvidenceIDs = uniqueStrings(append(f.EvidenceIDs, d.EvidenceID))
	}
	switch d.RuntimeLoadStatus {
	case "confirmed_loaded":
		f.RuntimeState = findings.RuntimeRunning
		for _, pid := range d.ProcessIDs {
			f.RuntimeProcessIDs = append(f.RuntimeProcessIDs, fmt.Sprintf("%d", pid))
		}
		f.RuntimeProcessIDs = uniqueStrings(f.RuntimeProcessIDs)
	case "installed_not_proven_loaded":
		f.RuntimeState = findings.RuntimeNotObserved
	}
}
