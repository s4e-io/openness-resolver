// Package resolver implements the deterministic decision engine (Task 7 and
// Task 9 decision rules). All final vulnerability decisions are made here by
// Go code from normalized evidence + vendor rules + native version
// comparison + explicit applicability logic. No AI is involved at runtime.
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
	"github.com/s4e-io/openness-resolver/internal/containers"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/kernel"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/python"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/runtime"
	"github.com/s4e-io/openness-resolver/internal/version"
)

// Detection methods.
const (
	MethodUbuntuSourcePackage = "ubuntu_source_package_fixed_version"
	MethodAlpineBranchPackage = "alpine_branch_package_fixed_version"
	MethodUbuntuRunningKernel = "ubuntu_running_kernel_fixed_version"
	MethodDebianSourcePackage = "debian_source_package_fixed_version"
	MethodRPMPackage          = "rpm_package_fixed_version"
)

// hostEvaluator is the generic host package evaluator of one distribution:
// the package ecosystem its rules use and the detection method reported.
// Ubuntu keeps its own path (running kernel, ESM, Python correlation).
// Alpine hosts use the same secdb rules and apk comparator as Alpine
// container images, keyed by the branch derived from VERSION_ID.
type hostEvaluator struct {
	ecosystem string
	method    string
}

var hostEvaluators = map[string]hostEvaluator{
	"debian":    {ecosystem: "dpkg", method: MethodDebianSourcePackage},
	"rocky":     {ecosystem: "rpm", method: MethodRPMPackage},
	"almalinux": {ecosystem: "rpm", method: MethodRPMPackage},
	"rhel":      {ecosystem: "rpm", method: MethodRPMPackage},
	"opensuse":  {ecosystem: "rpm", method: MethodRPMPackage},
	"amazon":    {ecosystem: "rpm", method: MethodRPMPackage},
	"alpine":    {ecosystem: "apk", method: MethodAlpineBranchPackage},
}

// RunMetrics is reported after every resolver run.
type RunMetrics struct {
	AssetPackages              int   `json:"asset_packages"`
	HostPackages               int   `json:"host_packages"`
	ContainerPackages          int   `json:"container_packages"`
	PackagesWithSourcePackage  int   `json:"packages_with_source_package"`
	PackagesWithVendorRules    int   `json:"packages_with_vendor_rules"`
	PackagesWithoutVendorRules int   `json:"packages_without_vendor_rules"`
	RulesConsidered            int   `json:"rules_considered"`
	RulesApplicable            int   `json:"rules_applicable"`
	RulesRejected              int   `json:"rules_rejected"`
	FindingsVulnerable         int   `json:"findings_vulnerable"`
	FindingsFixed              int   `json:"findings_fixed"`
	FindingsNotApplicable      int   `json:"findings_not_applicable"`
	FindingsUnknown            int   `json:"findings_unknown"`
	FindingsConflicting        int   `json:"findings_conflicting"`
	FindingsVulnerableRuntime  int   `json:"findings_vulnerable_runtime"`
	FindingsPotentially        int   `json:"findings_potentially_vulnerable"`
	ComparatorErrors           int   `json:"comparator_errors"`
	ResolverDurationMS         int64 `json:"resolver_duration_ms"`
}

const (
	CoverageCovered       = "covered"
	CoverageMissing       = "missing"
	CoverageNotApplicable = "not_applicable"
	// CoverageNotSupported: a network device no device catalog entry matched.
	CoverageNotSupported = "not_supported"
	// CoverageUnknown: a device entry matched, but the device version could not be read.
	CoverageUnknown = "unknown"
	// CoveragePartial: everything was evaluated except what the partial gaps name:
	// PyPI packages whose data is not synced (GapNotSynced), malformed package
	// records (GapInvalidPackageRecords), a cut package list
	// (GapPackagesTruncated) or container images that were not evaluated
	// (GapContainerNotCovered). resolve exits 0.
	CoveragePartial = "partial"

	// GapMissingRules means the release is evaluated by an existing path but
	// the store has no rules for it. feed sync can fill that gap.
	GapMissingRules = "missing_rules"
	// GapNoEvaluator means the platform is recognized and the evidence has
	// packages, but this build has no comparator for that host. feed sync
	// does not fix it.
	GapNoEvaluator = "no_evaluator"
	// GapNotSynced means the osv-pypi data is not in the store (release "pypi"), or older
	// per-package data does not name this package (release "pypi/<name>"). Python package
	// findings are missing; the rest of the asset is evaluated.
	GapNotSynced = "not_synced"
)

// CoverageGap is one release or host that was not evaluated.
type CoverageGap struct {
	Release string `json:"release"`
	Kind    string `json:"kind"`
	// Count is the number of records behind the gap (invalid_package_records).
	Count int `json:"count,omitempty"`
	// Detail explains the gap in words.
	Detail string `json:"detail,omitempty"`
}

// RuleCoverage separates "nothing was found" from "nothing was evaluated".
// AssetRelease is the host release only. Extra holes are listed in Gaps and
// do not rewrite AssetRelease or RulesForAsset.
type RuleCoverage struct {
	AssetRelease   string        `json:"asset_release"`
	RulesForAsset  int           `json:"rules_for_asset"`
	LoadedReleases []string      `json:"loaded_releases"`
	Gaps           []CoverageGap `json:"gaps,omitempty"`
	State          string        `json:"state"`
	Reason         string        `json:"reason,omitempty"`
	// Sources names the data behind the loaded rules: for each rule directory,
	// the publisher file it was built from, its sha256 and when it was
	// downloaded, how old that is and whether it counts as old (stale), so a
	// stale feed is visible even when State is covered.
	Sources []CoverageSource `json:"sources"`
}

// CoverageSource is one loaded rule directory and the feed snapshot it came from.
type CoverageSource struct {
	Release         string     `json:"release"`
	Source          string     `json:"source"`
	URL             string     `json:"url"`
	SHA256          string     `json:"sha256"`
	DownloadedAt    *time.Time `json:"downloaded_at,omitempty"`
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`
	Parser          string     `json:"parser"`
	// Version is the data version, for the application mapper.
	Version string `json:"version,omitempty"`
	// AgeDays is how many whole days ago the data was downloaded, and Stale whether that
	// is older than the source allows (MarkStale); both only with DownloadedAt.
	AgeDays *int  `json:"age_days,omitempty"`
	Stale   *bool `json:"stale,omitempty"`
}

// coverageSources lists the snapshots of the loaded rule directories, in a
// stable order.
func coverageSources(rs *rules.RuleSet) []CoverageSource {
	out := []CoverageSource{}
	if rs == nil {
		return out
	}
	for _, s := range rs.Snapshots {
		c := CoverageSource{Release: s.Vendor + "/" + s.Release, Source: s.SourceName, URL: s.SourceURL,
			SHA256: s.SHA256, SourceUpdatedAt: s.SourceUpdatedAt, Parser: s.ParserVersion}
		if !s.DownloadedAt.IsZero() {
			t := s.DownloadedAt
			c.DownloadedAt = &t
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Release != out[j].Release {
			return out[i].Release < out[j].Release
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// RunResult is the full output of one resolver run.
type RunResult struct {
	OutputSchemaVersion string                   `json:"output_schema_version"`
	AssetID             string                   `json:"asset_id"`
	Asset               AssetSummary             `json:"asset"`
	Platform            platform.PlatformContext `json:"platform"`
	PlatformSupport     string                   `json:"platform_support"`
	// PlatformTested is true only when the host platform is supported AND
	// was verified against a real host (platform.testedReleases). A
	// supported platform covered by mock data only reports false.
	PlatformTested       bool                           `json:"platform_tested"`
	SupportReason        string                         `json:"support_reason,omitempty"`
	RuleCoverage         RuleCoverage                   `json:"rule_coverage"`
	Findings             []findings.Finding             `json:"findings"`
	DeduplicatedFindings []findings.DeduplicatedFinding `json:"deduplicated_findings,omitempty"`
	RemediationGroups    []findings.RemediationGroup    `json:"remediation_groups"`
	Reconciliation       findings.OutputReconciliation  `json:"reconciliation"`
	// SoftwareInventory passes collector catalog detections through with the
	// resolver's stance (no product feed yet). Empty list, never null.
	SoftwareInventory []SoftwareInstanceResult `json:"software_inventory"`
	// Unknowns lists what was seen but not judged. Empty list, never null.
	Unknowns []Unknown `json:"unknowns"`
	// Applications lists a Windows host's installed applications with what the application
	// mapper made of each (matched, guessed, unmatched, ...); absent on other hosts.
	Applications []appvuln.Application `json:"applications,omitempty"`
	// ApplicationMapper is the version of the application mapper data used.
	ApplicationMapper string                 `json:"application_mapper,omitempty"`
	Metrics           RunMetrics             `json:"metrics"`
	Notes             []string               `json:"notes"`
	EvidenceErrors    []evidence.RecordError `json:"evidence_errors"`
	GeneratedAt       time.Time              `json:"generated_at"`

	// invalidPackages are the skipped package records, added to Unknowns.
	invalidPackages []Unknown
}

// AssetSummary is the header a consumer shows: where the evidence came from.
type AssetSummary struct {
	Hostname         string `json:"hostname"`
	FQDN             string `json:"fqdn,omitempty"`
	MachineID        string `json:"machine_id,omitempty"`
	Platform         string `json:"platform"`
	Architecture     string `json:"architecture"`
	CollectorVersion string `json:"collector_version"`
	SchemaVersion    string `json:"schema_version"`
	CollectionID     string `json:"collection_id"`
	CollectedAt      string `json:"collected_at"`
	CollectionStatus string `json:"collection_status"`
	PrivilegeLevel   string `json:"privilege_level"`
	// EvidenceIntegrity is "verified" (payload hash matched) or "not_present"
	// (no hash in the evidence); empty when the evidence was not loaded from a file.
	EvidenceIntegrity string `json:"evidence_integrity,omitempty"`
}

// Engine evaluates evidence against a rule set.
type Engine struct {
	Rules *rules.RuleSet
	Now   func() time.Time
	// Apps is the application mapper for third-party Windows applications and network
	// devices; nil skips them. AppSource, when set, is listed in rule_coverage.sources of
	// a run that used the mapper.
	Apps       *appvuln.Data
	AppOptions appvuln.Options
	AppSource  *CoverageSource
}

// NewEngine creates an Engine over a loaded rule set.
func NewEngine(rs *rules.RuleSet) *Engine {
	return &Engine{Rules: rs, Now: time.Now}
}

// Resolve runs the full pipeline over one .openness document.
func (e *Engine) Resolve(lr *evidence.LoadResult) (*RunResult, error) {
	start := e.Now()
	doc := lr.Doc
	res := &RunResult{
		OutputSchemaVersion: findings.OutputSchemaVersion,
		AssetID:             doc.Asset.AssetID,
		GeneratedAt:         start.UTC(),
		Findings:            []findings.Finding{},
		RemediationGroups:   []findings.RemediationGroup{},
		SoftwareInventory:   []SoftwareInstanceResult{},
		Unknowns:            []Unknown{},
		Notes:               []string{},
		EvidenceErrors:      []evidence.RecordError{},
	}
	res.Asset = AssetSummary{
		Hostname:         doc.Asset.Hostname,
		FQDN:             doc.Asset.FQDN,
		MachineID:        doc.Asset.MachineID,
		Platform:         doc.Asset.Platform,
		Architecture:     doc.Asset.Architecture,
		CollectorVersion: doc.Collector.Version,
		SchemaVersion:    doc.SchemaVersion,
		CollectionID:     doc.Collection.CollectionID,
		CollectedAt:      doc.Collection.CompletedAt,
		CollectionStatus: doc.Collection.Status,
		PrivilegeLevel:   doc.Collection.PrivilegeLevel,

		EvidenceIntegrity: lr.Integrity,
	}
	if lr.Integrity == evidence.IntegrityAbsent {
		res.Notes = append(res.Notes, evidence.IntegrityAbsentNote)
	}

	// Platform applicability (Task 1).
	res.Platform = platform.FromOS(doc.OperatingSystem, doc.Kernel)
	support, reason := res.Platform.Support()
	res.PlatformSupport = string(support)
	res.SupportReason = reason
	res.PlatformTested = res.Platform.Tested()

	// Host package inventory (Tasks 2-3).
	var hostPackages []pkgs.InstalledPackage
	decodeErrs := len(lr.RecordErrors)
	pkgRecords := lr.PackageRecords()
	var health inventoryHealth
	for _, re := range lr.RecordErrors[decodeErrs:] {
		health.Invalid = append(health.Invalid, Unknown{Kind: "package_record", Subject: re.EvidenceID, Reason: "invalid_package_record: " + re.Message})
	}
	for _, rec := range pkgRecords {
		p, err := pkgs.FromHostRecord(rec)
		if err != nil {
			res.Notes = append(res.Notes, "package record rejected: "+err.Error())
			health.Invalid = append(health.Invalid, Unknown{Kind: "package_record", Subject: rec.EvidenceID, Reason: "invalid_package_record: " + err.Error()})
			continue
		}
		if !p.Installed() {
			continue
		}
		hostPackages = append(hostPackages, p)
	}
	pkgIndex := pkgs.NewIndex(hostPackages)
	if pkgIndex.Duplicates > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d duplicate package identities ignored", pkgIndex.Duplicates))
	}
	res.Metrics.HostPackages = len(pkgIndex.All)

	// Runtime correlation (Task 10).
	runtimeIdx := runtime.Build(lr.ProcessRecords(), lr.ServiceRecords(), lr.EvidenceChainRecords(), lr.LoadedLibraryRecords(), pkgIndex)
	res.Notes = append(res.Notes, runtimeIdx.Notes...)

	// Container inventory (Task 8).
	ctrRecords := lr.ContainerRecords()
	markUnreadContainerPackages(doc.Modules, ctrRecords)
	inventory := containers.BuildInventory(ctrRecords)
	for _, msg := range inventory.PackageErrors {
		res.Notes = append(res.Notes, "container package rejected: "+msg)
	}
	for _, c := range inventory.MissingDigest {
		res.Notes = append(res.Notes, fmt.Sprintf("container %s (%s) has no usable image digest; its packages were not resolved at image level", c.ContainerID, c.Name))
	}

	// Host findings.
	pyInv := python.BuildInventory(lr.LanguageDepRecords())
	if support == platform.Supported && res.Platform.DistributionID == "ubuntu" {
		if res.Platform.Codename == "" {
			res.Notes = append(res.Notes, "ubuntu codename could not be determined; host package rules cannot be selected")
		} else {
			e.resolveHostUbuntu(res, pkgIndex, runtimeIdx)
			e.resolveKernelUbuntu(res, doc.Kernel, pkgIndex)
			esmActive := hostESMEntitlement(pkgIndex)
			findingIndex := indexFindings(res.Findings)
			e.resolvePython(res, pyInv, pkgIndex, res.Platform, esmActive, findingIndex)
		}
	} else if support == platform.Supported && res.Platform.DistributionID == "windows" {
		e.resolveWindowsOS(res)
	} else if ev, ok := hostEvaluators[res.Platform.DistributionID]; ok && support == platform.Supported {
		if res.Platform.RuleRelease() == "" {
			res.Notes = append(res.Notes, res.Platform.DistributionID+" release could not be determined; host package rules cannot be selected")
		} else {
			e.resolveHostVendor(res, pkgIndex, runtimeIdx, ev)
		}
	} else if support != platform.Supported {
		res.Notes = append(res.Notes, fmt.Sprintf("host platform not resolved: %s", reason))
	}

	// Container findings (Task 9).
	for _, group := range inventory.Groups {
		e.resolveContainerGroup(res, group)
	}
	health.Usable = res.Metrics.HostPackages
	packageModuleSignals(doc, ctrRecords, &health)
	res.invalidPackages = health.Invalid
	res.RuleCoverage = e.ruleCoverage(res.Platform, support, pkgIndex, inventory.Groups, pyInv)
	addCoverageGaps(&res.RuleCoverage, inventoryGaps(res.Platform, support, reason, doc.Asset.Platform, health))
	for _, g := range res.RuleCoverage.Gaps {
		if g.Kind == GapNotSynced {
			res.Notes = append(res.Notes, PyPINotSyncedNote)
			break
		}
	}

	res.Metrics.AssetPackages = res.Metrics.HostPackages + res.Metrics.ContainerPackages
	if lr.RecordErrors != nil {
		res.EvidenceErrors = lr.RecordErrors
	}
	sortFindings(res.Findings)
	e.attachRemediation(res, pkgIndex, runtimeIdx, doc.Kernel.RebootRequired)
	if res.Platform.DistributionID == "windows" {
		// after the package cards: an application card is its own, never merged into those
		e.resolveApplications(res, doc.Applications)
		sortFindings(res.Findings)
		sortRemediationGroups(res.RemediationGroups)
	}
	res.SoftwareInventory = buildSoftwareInventory(lr.SoftwareInventoryRecords())
	res.Unknowns = append(buildUnknowns(res), res.invalidPackages...)
	reconcileOutput(res)
	res.Metrics.ResolverDurationMS = time.Since(start).Milliseconds()
	return res, nil
}

// ruleCoverage counts loaded rules for every release this run actually needed.
// An Alpine image is part of the asset: a branch with packages and zero rules
// is missing even when the Ubuntu host itself is covered.
func (e *Engine) ruleCoverage(plat platform.PlatformContext, support platform.SupportState, pkgIndex *pkgs.Index, groups []*containers.ImageGroup, pyInv *python.Inventory) RuleCoverage {
	cov := RuleCoverage{State: CoverageNotApplicable, Sources: coverageSources(e.Rules)}
	counts := map[string]int{}
	if e.Rules != nil {
		for i := range e.Rules.Rules {
			r := &e.Rules.Rules[i]
			if r.Distribution == "" || r.Release == "" {
				continue
			}
			counts[r.Distribution+"/"+r.Release]++
		}
	}
	for k := range counts {
		cov.LoadedReleases = append(cov.LoadedReleases, k)
	}
	sort.Strings(cov.LoadedReleases)

	var gaps []CoverageGap
	hostPackages := 0
	if pkgIndex != nil {
		for _, p := range pkgIndex.All {
			if p.Scope == pkgs.ScopeHost {
				hostPackages++
			}
		}
	}
	if support == platform.Supported && plat.DistributionID == "ubuntu" && hostPackages > 0 {
		release := plat.DistributionID + "/(codename unknown)"
		if plat.Codename != "" {
			release = plat.DistributionID + "/" + plat.Codename
		}
		cov.AssetRelease = release
		cov.RulesForAsset = counts[release]
		if cov.RulesForAsset == 0 {
			gaps = append(gaps, CoverageGap{Release: release, Kind: GapMissingRules})
		}
	}
	if _, ok := hostEvaluators[plat.DistributionID]; ok && support == platform.Supported && hostPackages > 0 {
		release := plat.DistributionID + "/(release unknown)"
		if rr := plat.RuleRelease(); rr != "" {
			release = plat.DistributionID + "/" + rr
		}
		cov.AssetRelease = release
		cov.RulesForAsset = counts[release]
		if cov.RulesForAsset == 0 {
			gaps = append(gaps, CoverageGap{Release: release, Kind: GapMissingRules})
		}
	}
	if support == platform.Supported && plat.DistributionID == "windows" && plat.Codename != "" {
		release := "windows/" + plat.Codename
		cov.AssetRelease = release
		cov.RulesForAsset = counts[release]
		if cov.RulesForAsset == 0 {
			gaps = append(gaps, CoverageGap{Release: release, Kind: GapMissingRules})
		}
	}
	seenImage := map[string]bool{}
	for _, g := range groups {
		if g == nil || g.Distro != "alpine" || g.Branch == "" || len(g.Packages) == 0 {
			continue
		}
		release := "alpine/" + g.Branch
		if seenImage[release] {
			continue
		}
		seenImage[release] = true
		if counts[release] == 0 {
			gaps = append(gaps, CoverageGap{Release: release, Kind: GapMissingRules})
		} else if cov.AssetRelease == "" {
			cov.AssetRelease = release
			cov.RulesForAsset = counts[release]
		}
	}
	imageReleases, imageGaps := e.containerCoverage(groups, plat.RawArchitecture)
	gaps = append(gaps, imageGaps...)
	for _, release := range imageReleases {
		if cov.AssetRelease == "" {
			cov.AssetRelease = release
			cov.RulesForAsset = counts[release]
		}
	}
	if support == platform.Supported && plat.DistributionID == "ubuntu" && plat.Codename != "" {
		gaps = append(gaps, pypiCoverageGaps(e.Rules, pyInv)...)
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Release != gaps[j].Release {
			return gaps[i].Release < gaps[j].Release
		}
		return gaps[i].Kind < gaps[j].Kind
	})
	if len(gaps) == 0 {
		if cov.AssetRelease != "" {
			cov.State = CoverageCovered
		}
		return cov
	}
	cov.Gaps = gaps
	cov.State = CoverageMissing
	cov.State, cov.Reason = gapState(gaps), coverageReason(gaps)
	return cov
}

// addCoverageGaps merges extra gaps into cov and recomputes its state and reason.
func addCoverageGaps(cov *RuleCoverage, extra []CoverageGap) {
	if len(extra) == 0 {
		return
	}
	cov.Gaps = append(cov.Gaps, extra...)
	sort.SliceStable(cov.Gaps, func(i, j int) bool {
		if cov.Gaps[i].Release != cov.Gaps[j].Release {
			return cov.Gaps[i].Release < cov.Gaps[j].Release
		}
		return cov.Gaps[i].Kind < cov.Gaps[j].Kind
	})
	cov.State, cov.Reason = gapState(cov.Gaps), coverageReason(cov.Gaps)
}

// gapState is partial when every gap leaves the rest of the asset evaluated,
// else missing.
func gapState(gaps []CoverageGap) string {
	for _, g := range gaps {
		switch g.Kind {
		case GapNotSynced, GapInvalidPackageRecords, GapPackagesTruncated, GapContainerNotCovered:
		default:
			return CoverageMissing
		}
	}
	return CoveragePartial
}

// PyPINotSyncedNote is the note of a run without PyPI data.
const PyPINotSyncedNote = "PyPI data (osv-pypi) is not synced: Python package findings are missing; run feed sync --for this evidence"

// pypiCoverageGaps reports the PyPI data the asset's Python packages lack. The osv-pypi
// archive covers every package (its snapshot names none). Older per-package data covers
// the names in its rule file and package list. Without either, the one gap is "pypi".
func pypiCoverageGaps(rs *rules.RuleSet, inv *python.Inventory) []CoverageGap {
	if inv == nil {
		return nil
	}
	names := python.PyPINames(inv)
	if len(names) == 0 {
		return nil
	}
	synced := map[string]bool{}
	if rs != nil {
		for _, snap := range rs.Snapshots {
			if snap.SourceName != "osv-pypi" {
				continue
			}
			if len(snap.PackageNames) == 0 {
				return nil // the full archive
			}
			for _, n := range snap.PackageNames {
				if n != "" {
					synced[n] = true
				}
			}
		}
		for i := range rs.Rules {
			r := &rs.Rules[i]
			if r.Distribution == "pypi" && r.PackageName != "" {
				synced[r.PackageName] = true
			}
		}
	}
	if len(synced) == 0 {
		return []CoverageGap{{Release: "pypi", Kind: GapNotSynced}}
	}
	var gaps []CoverageGap
	for _, n := range names {
		if !synced[n] {
			gaps = append(gaps, CoverageGap{Release: "pypi/" + n, Kind: GapNotSynced})
		}
	}
	return gaps
}

func coverageReason(gaps []CoverageGap) string {
	parts := make([]string, 0, len(gaps))
	for _, g := range gaps {
		switch g.Kind {
		case GapNotSynced:
			parts = append(parts, "PyPI data not synced for "+g.Release)
		case GapNoEvaluator:
			parts = append(parts, g.Release+" host has no package evaluator")
		case GapNoPackages:
			parts = append(parts, "no packages to evaluate for "+g.Release+" ("+g.Detail+")")
		case GapUnknownDistribution:
			parts = append(parts, "unknown distribution "+g.Release+" ("+g.Detail+")")
		case GapInvalidPackageRecords:
			parts = append(parts, fmt.Sprintf("%d malformed package records skipped for %s", g.Count, g.Release))
		case GapPackagesTruncated:
			parts = append(parts, "package list cut by the collector for "+g.Release)
		case GapContainerNotCovered:
			parts = append(parts, fmt.Sprintf("container image %s (%d containers) not evaluated: %s", strings.TrimPrefix(g.Release, "container:"), g.Count, g.Detail))
		default:
			parts = append(parts, "no rules loaded for "+g.Release)
		}
	}
	return "finding counts are not an all-clear: " + strings.Join(parts, "; ")
}

// EvaluationError is what resolve returns when the run must not look clean.
// A missing-rules gap names feed sync. A host with no evaluator does not,
// because downloading rules would not score those packages.
func (c RuleCoverage) EvaluationError(evidencePath string) error {
	if c.State != CoverageMissing {
		return nil
	}
	var rules []string
	for _, g := range c.Gaps {
		if g.Kind == GapMissingRules {
			rules = append(rules, g.Release)
		}
	}
	msg := c.Reason
	if msg == "" {
		msg = "the asset was not fully evaluated"
	}
	if len(rules) > 0 {
		msg += fmt.Sprintf(" (run `openness-resolver feed sync --for %s`)", evidencePath)
	}
	return fmt.Errorf("%s", msg)
}

// resolveHostUbuntu evaluates every installed host package against Ubuntu
// vendor rules for the asset's release.
func (e *Engine) resolveHostUbuntu(res *RunResult, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex) {
	codename := res.Platform.Codename
	esmActive := hostESMEntitlement(pkgIndex)
	if esmActive {
		res.Notes = append(res.Notes, "Ubuntu Pro/ESM archives observed active on this asset (packages installed from esm.ubuntu.com)")
	}
	for _, p := range pkgIndex.All {
		if p.Ecosystem != "dpkg" {
			continue
		}
		if p.SourcePackage != "" {
			res.Metrics.PackagesWithSourcePackage++
		}
		// Candidate rules: indexed by binary name and by source package.
		candidates := map[string]*rules.PackageVulnerabilityRule{}
		for _, r := range e.Rules.ForBinaryPackage("dpkg", "ubuntu", codename, p.Name) {
			if r.IsKernel {
				continue // kernel rules apply to the running kernel only
			}
			candidates[r.RuleID] = r
		}
		for _, r := range e.Rules.ForSourcePackage("dpkg", "ubuntu", codename, p.SourcePackage) {
			if r.IsKernel {
				continue
			}
			if !ruleAppliesToInstalledBinary(*p, r) {
				continue
			}
			candidates[r.RuleID] = r
		}
		if len(candidates) == 0 {
			res.Metrics.PackagesWithoutVendorRules++
			continue
		}
		res.Metrics.PackagesWithVendorRules++
		fs := e.decidePackage(res, *p, candidates, res.Platform, MethodUbuntuSourcePackage)
		for i := range fs {
			e.enrichRuntime(&fs[i], *p, runtimeIdx)
			applyESMEntitlement(&fs[i], esmActive)
		}
		res.Findings = append(res.Findings, fs...)
	}
}

// resolveKernelUbuntu implements T06/T07: kernel advisories are evaluated
// against the running kernel's package version, never against installed
// kernel packages generically (old kernel images on disk are not the
// running attack surface; the meta-package is not the running image).
func (e *Engine) resolveKernelUbuntu(res *RunResult, k evidence.Kernel, pkgIndex *pkgs.Index) {
	kctx := kernel.Build(&k, pkgIndex)
	res.Notes = append(res.Notes, kctx.Notes...)
	if kctx.RunningKernel == "" {
		return
	}
	if kctx.SourceFamily == "" || kctx.PackageVersion == "" {
		// Manually built or unmapped kernel: kernel CVEs are undecidable.
		res.Notes = append(res.Notes, fmt.Sprintf("kernel advisories skipped: running kernel %s could not be mapped to a vendor kernel package", kctx.RunningKernel))
		return
	}

	var kernelRules map[string]*rules.PackageVulnerabilityRule
	for _, r := range e.Rules.ForSourcePackage("dpkg", "ubuntu", res.Platform.Codename, kctx.SourceFamily) {
		if !r.IsKernel {
			continue
		}
		if !kernel.RuleApplicable(kctx, r) {
			res.Metrics.RulesRejected++
			continue
		}
		if kernelRules == nil {
			kernelRules = map[string]*rules.PackageVulnerabilityRule{}
		}
		kernelRules[r.RuleID] = r
	}
	if len(kernelRules) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("no kernel advisories found for source family %q in %s", kctx.SourceFamily, res.Platform.Codename))
		return
	}

	// The running kernel is modeled as a synthetic package: the image
	// package name with the running kernel's dpkg-comparable version.
	runningName := "linux-image-" + kctx.VersionABI + "-" + kctx.Flavour
	p := pkgs.InstalledPackage{
		Scope:         pkgs.ScopeHost,
		Ecosystem:     "dpkg",
		Name:          runningName,
		SourcePackage: kctx.SourceFamily,
		RawVersion:    kctx.PackageVersion,
		Architecture:  res.Platform.Architecture,
	}
	if len(kctx.EvidenceIDs) > 0 {
		p.EvidenceID = kctx.EvidenceIDs[0]
	}
	fs := e.decidePackage(res, p, kernelRules, res.Platform, MethodUbuntuRunningKernel)

	dpkgCmp := func(a, b string) (int, error) {
		cmp, err := version.ForEcosystem("dpkg")
		if err != nil {
			return 0, err
		}
		return cmp.Compare(a, b)
	}
	for i := range fs {
		f := &fs[i]
		if f.State != findings.StateVulnerable {
			continue
		}
		// The kernel is running by definition.
		f.RuntimeState = findings.RuntimeRunning
		// T07: a fixed kernel image already on disk means only a reboot is
		// missing — recorded explicitly, never converted to fixed.
		if img := kctx.NewerInstalledImage(f.FixedVersion, dpkgCmp); img != nil {
			f.FixedImageInstalled = true
			f.Reasons = append(f.Reasons, fmt.Sprintf("fixed kernel image %s (%s) is installed but not running; reboot into it to remediate", img.PackageName, img.RawVersion))
			if kctx.RebootRequired {
				f.Reasons = append(f.Reasons, "reboot-required marker is present on the asset")
			}
		}
	}
	res.Findings = append(res.Findings, fs...)
}

// hostESMEntitlement reports whether Ubuntu Pro/ESM archives are actually in
// use on the asset. Only packages installed from esm.ubuntu.com (or carrying
// an ESM origin) prove entitlement; a merely-configured repository does not.
func hostESMEntitlement(pkgIndex *pkgs.Index) bool {
	for _, p := range pkgIndex.All {
		if strings.Contains(p.RepositoryURL, "esm.ubuntu.com") ||
			strings.HasPrefix(p.RepositoryOrigin, "UbuntuESM") {
			return true
		}
	}
	return false
}

// applyESMEntitlement resolves T05 fix availability: a fix published in an
// ESM pocket is only available to assets with observed ESM entitlement.
func applyESMEntitlement(f *findings.Finding, esmActive bool) {
	if f.FixAvailability != findings.FixRequiresESM {
		return
	}
	if esmActive {
		f.FixAvailability = findings.FixAvailable
		f.Reasons = append(f.Reasons, "ESM entitlement observed on this asset; the ESM-pocket fix is installable")
	} else {
		f.Reasons = append(f.Reasons, "no evidence of Ubuntu Pro/ESM entitlement on this asset; the fix is not installable without it")
	}
}

// resolveContainerGroup evaluates the packages of one image digest group.
func (e *Engine) resolveContainerGroup(res *RunResult, group *containers.ImageGroup) {
	res.Metrics.ContainerPackages += len(group.Packages)
	if len(group.Packages) == 0 {
		if group.PackagesError != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("image %s (%s): package database could not be read (%s); packages unknown", group.ImageDigest, imageLabel(group), group.PackagesError))
			return
		}
		// Distroless/scratch image or package DB unavailable: this is a
		// visible gap, not a clean result.
		res.Notes = append(res.Notes, fmt.Sprintf("image %s has no package database (distroless/scratch or collection gap); packages unknown", group.ImageDigest))
		return
	}
	if group.Distro != "alpine" {
		e.resolveContainerVendor(res, group)
		return
	}
	if group.Branch == "" {
		res.Notes = append(res.Notes, fmt.Sprintf("image %s: alpine branch could not be inferred; findings for its packages are unknown", group.ImageDigest))
		// Branch unknown => evidence insufficient: unknown finding per
		// package would be noise; a single unknown marker finding is emitted.
		f := findings.Finding{
			FindingID:       findingID(res.AssetID, group.ImageDigest, "branch-unknown", "", ""),
			AssetID:         res.AssetID,
			Scope:           pkgs.ScopeContainer,
			ImageDigest:     group.ImageDigest,
			ContainerIDs:    group.ContainerIDs(),
			State:           findings.StateUnknown,
			Confidence:      "low",
			DetectionMethod: MethodAlpineBranchPackage,
			Distribution:    "alpine",
			Reasons:         []string{"alpine release branch could not be inferred from anchor packages"},
			MissingEvidence: []string{"container os-release / alpine branch"},
		}
		res.Findings = append(res.Findings, f)
		res.Metrics.PackagesWithoutVendorRules += len(group.Packages)
		return
	}

	platformCtx := platform.PlatformContext{
		DistributionID:      "alpine",
		DistributionVersion: strings.TrimPrefix(group.Branch, "v"),
		Codename:            group.Branch,
	}
	for i := range group.Packages {
		p := group.Packages[i]
		candidates := map[string]*rules.PackageVulnerabilityRule{}
		for _, r := range e.Rules.ForBinaryPackage("apk", "alpine", group.Branch, p.Name) {
			candidates[r.RuleID] = r
		}
		// APK origin (source) package lookups: container evidence carries
		// only binary names, so secdb origin-name rules are matched via the
		// source index too.
		for _, r := range e.Rules.ForSourcePackage("apk", "alpine", group.Branch, p.SourcePackage) {
			candidates[r.RuleID] = r
		}
		if len(candidates) == 0 {
			res.Metrics.PackagesWithoutVendorRules++
			continue
		}
		res.Metrics.PackagesWithVendorRules++
		fs := e.decidePackage(res, p, candidates, platformCtx, MethodAlpineBranchPackage)
		for i := range fs {
			fs[i].ImageDigest = group.ImageDigest
			fs[i].ContainerIDs = group.ContainerIDs()
			// Alpine branch inference lowers confidence: the branch is not
			// vendor-asserted evidence.
			if group.BranchConfidence == "inferred" && fs[i].Confidence == "high" {
				fs[i].Confidence = "medium"
				fs[i].Reasons = append(fs[i].Reasons, "alpine branch inferred from anchor package versions, not from os-release")
			}
		}
		res.Findings = append(res.Findings, fs...)
	}
}

// decidePackage groups candidate rules by vulnerability id and produces findings.
func (e *Engine) decidePackage(res *RunResult, p pkgs.InstalledPackage, candidates map[string]*rules.PackageVulnerabilityRule, plat platform.PlatformContext, method string) []findings.Finding {
	byVuln := map[string][]*rules.PackageVulnerabilityRule{}
	for _, r := range candidates {
		res.Metrics.RulesConsidered++
		key := vulnerabilityKey(r)
		byVuln[key] = append(byVuln[key], r)
	}
	keys := make([]string, 0, len(byVuln))
	for key := range byVuln {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var out []findings.Finding
	for _, key := range keys {
		if f := e.decideCVE(res, p, key, byVuln[key], plat, method); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// ruleEvaluation is the outcome of applying one rule to one package.
type ruleEvaluation struct {
	rule         *rules.PackageVulnerabilityRule
	applicable   bool
	rejectReason string
	state        string
	comparison   *findings.Comparison
	fixAvail     string
	reasons      []string
}

// EvaluateRule applies the full Task 7 decision table for one rule against
// one installed package. Exported for tests and `explain`.
func EvaluateRule(p pkgs.InstalledPackage, plat platform.PlatformContext, r *rules.PackageVulnerabilityRule) ruleEvaluation {
	ev := ruleEvaluation{rule: r}

	// Applicability gates -> not_applicable (never silently skipped).
	if !ruleAppliesToInstalledBinary(p, r) {
		ev.state = findings.StateNotApplicable
		ev.rejectReason = fmt.Sprintf("binary package mismatch: rule=%s installed=%s", r.PackageName, p.Name)
		return ev
	}
	if r.Ecosystem != "pypi" {
		if r.Distribution != plat.DistributionID {
			ev.state = findings.StateNotApplicable
			ev.rejectReason = fmt.Sprintf("distribution mismatch: rule=%s asset=%s", r.Distribution, plat.DistributionID)
			return ev
		}
		ruleRelease := r.Release
		// Codename for ubuntu/debian, branch for alpine, major version for
		// the RPM family, Leap version for openSUSE.
		assetRelease := plat.RuleRelease()
		if ruleRelease != assetRelease {
			ev.state = findings.StateNotApplicable
			ev.rejectReason = fmt.Sprintf("release mismatch: rule=%s asset=%s", ruleRelease, assetRelease)
			return ev
		}
	}
	if r.Ecosystem != "pypi" && r.SourcePackage != "" && r.SourcePackage != p.SourcePackage && r.PackageName != p.Name {
		ev.state = findings.StateNotApplicable
		ev.rejectReason = fmt.Sprintf("package mismatch: rule source=%s/binary=%s, installed source=%s/binary=%s", r.SourcePackage, r.PackageName, p.SourcePackage, p.Name)
		return ev
	}
	if r.Comparator == "rpm" {
		if reason := rpmStreamMismatch(p.RawVersion, r.FixedVersion); reason != "" {
			ev.state = findings.StateNotApplicable
			ev.rejectReason = reason
			return ev
		}
	}
	installed, viaSource := comparableInstalledVersion(p, r)
	if r.IntroducedVersion != "" {
		if cmp, err := version.ForEcosystem(r.Comparator); err == nil {
			if c, err := cmp.Compare(installed, r.IntroducedVersion); err == nil && c < 0 {
				ev.state = findings.StateNotApplicable
				ev.rejectReason = fmt.Sprintf("installed %s is older than the first affected version %s", installed, r.IntroducedVersion)
				return ev
			}
		}
	}
	if r.Ecosystem != "pypi" && !platform.ArchitectureCompatible(p.Architecture, r.Architecture) {
		// Architecture is not pre-filtered by the rule indexes, so this gate
		// produces a visible not_applicable outcome instead of a silent drop.
		ev.applicable = true
		ev.state = findings.StateNotApplicable
		ev.reasons = append(ev.reasons, fmt.Sprintf("architecture mismatch: rule applies to %s, package is %s", r.Architecture, p.Architecture))
		return ev
	}

	ev.applicable = true
	switch r.Status {
	case rules.StatusNotAffected:
		ev.state = findings.StateNotApplicable
		ev.reasons = append(ev.reasons, "vendor status: not_affected")
	case rules.StatusDoesNotExist:
		ev.state = findings.StateNotApplicable
		ev.reasons = append(ev.reasons, "vendor status: does_not_exist")
	case rules.StatusReleased:
		if r.FixedVersion == "" {
			ev.state = findings.StateUnknown
			ev.reasons = append(ev.reasons, "vendor status released but no fixed version in rule; refusing to claim fixed without vendor fixed-version evidence")
			return ev
		}
		cmp, err := version.ForEcosystem(r.Comparator)
		if err != nil {
			ev.state = findings.StateUnknown
			ev.reasons = append(ev.reasons, err.Error())
			return ev
		}
		c, err := cmp.Compare(installed, r.FixedVersion)
		comparison := &findings.Comparison{
			Comparator: r.Comparator,
			Installed:  installed,
			Fixed:      r.FixedVersion,
			Expression: "installed < fixed",
		}
		if err != nil {
			comparison.Error = err.Error()
			ev.comparison = comparison
			ev.state = findings.StateUnknown
			ev.reasons = append(ev.reasons, "version comparison failed: "+err.Error())
			return ev
		}
		comparison.Result = c < 0
		ev.comparison = comparison
		if viaSource {
			ev.reasons = append(ev.reasons, fmt.Sprintf("compared source package version %s (binary %s %s); the vendor fixed version is a source version", installed, p.Name, p.RawVersion))
		}
		if c < 0 {
			ev.state = findings.StateVulnerable
			ev.fixAvail = findings.FixAvailable
			if strings.HasPrefix(r.SupportTier, "esm") {
				ev.fixAvail = findings.FixRequiresESM
				ev.reasons = append(ev.reasons, fmt.Sprintf("fix is published in the %s pocket (Ubuntu Pro required)", r.SupportTier))
			}
			ev.reasons = append(ev.reasons, fmt.Sprintf("installed %s < fixed %s (vendor status released)", installed, r.FixedVersion))
		} else {
			ev.state = findings.StateFixed
			ev.reasons = append(ev.reasons, fmt.Sprintf("installed %s >= fixed %s", installed, r.FixedVersion))
		}
	case rules.StatusNeeded:
		ev.state = findings.StateVulnerable
		ev.fixAvail = findings.FixUnavailable
		ev.reasons = append(ev.reasons, "vendor status: needed (affected, fix not yet available)")
	case rules.StatusDeferred:
		ev.state = findings.StateVulnerable
		ev.fixAvail = findings.FixDeferred
		ev.reasons = append(ev.reasons, "vendor status: deferred")
	case rules.StatusIgnored:
		ev.state = findings.StatePotentiallyVulnerable
		ev.reasons = append(ev.reasons, "vendor status: ignored ("+r.RawStatus+")")
	default:
		ev.state = findings.StateUnknown
		ev.reasons = append(ev.reasons, "vendor status unknown: "+r.RawStatus)
	}
	return ev
}

// comparableInstalledVersion returns the installed version a rule's fixed
// version is compared with. Debian Security Tracker fixed versions are
// source package versions, while a binary package can carry its own epoch
// (bsdutils 1:2.38.1-5+b1 from util-linux 2.38.1-5) or a binNMU suffix.
// Comparing the binary version there would read an unfixed epoch binary as
// fixed, so the source version from the dpkg Source field is used when the
// collector reported one. The bool is true when the source version was used.
func comparableInstalledVersion(p pkgs.InstalledPackage, r *rules.PackageVulnerabilityRule) (string, bool) {
	if r.Distribution == "debian" && r.Comparator == "dpkg" && r.PackageName == "" && p.Source.SourceVersion != "" {
		return p.Source.SourceVersion, p.Source.SourceVersion != p.RawVersion
	}
	return p.RawVersion, false
}

// preferCompatibleArch drops rules for another architecture when at least
// one rule matches the package architecture. collapseSiblingRules ignores
// architecture, so without this step a per-architecture rule pair (same
// package, CVE and fixed version) could collapse onto the wrong-arch rule
// and read as not_applicable. When no rule matches, all are kept so the
// mismatch stays visible.
func preferCompatibleArch(p pkgs.InstalledPackage, ruleList []*rules.PackageVulnerabilityRule) []*rules.PackageVulnerabilityRule {
	var compatible []*rules.PackageVulnerabilityRule
	for _, r := range ruleList {
		if r.Ecosystem == "pypi" || platform.ArchitectureCompatible(p.Architecture, r.Architecture) {
			compatible = append(compatible, r)
		}
	}
	if len(compatible) == 0 || len(compatible) == len(ruleList) {
		return ruleList
	}
	return compatible
}

// collapseSiblingRules deduplicates rules that describe the same vendor
// decision (same status + fixed version + source + binary package). The
// representative rule prefers the installed binary name so explanations
// point at the right rule.
func collapseSiblingRules(p pkgs.InstalledPackage, ruleList []*rules.PackageVulnerabilityRule) []*rules.PackageVulnerabilityRule {
	byOutcome := map[string]*rules.PackageVulnerabilityRule{}
	var order []string
	for _, r := range ruleList {
		bin := r.PackageName
		if bin == "" {
			bin = p.Name
		}
		key := strings.Join([]string{r.Vendor, r.Release, r.SourcePackage, bin, r.Status, r.FixedVersion, r.SupportTier}, "|")
		cur, ok := byOutcome[key]
		if !ok {
			byOutcome[key] = r
			order = append(order, key)
			continue
		}
		if cur.PackageName != p.Name && r.PackageName == p.Name {
			byOutcome[key] = r
		}
	}
	out := make([]*rules.PackageVulnerabilityRule, 0, len(order))
	for _, k := range order {
		out = append(out, byOutcome[k])
	}
	return out
}

// decideCVE merges all rule evaluations for one vulnerability into a single finding.
func (e *Engine) decideCVE(res *RunResult, p pkgs.InstalledPackage, vulnKey string, ruleList []*rules.PackageVulnerabilityRule, plat platform.PlatformContext, method string) *findings.Finding {
	// Candidates arrive in map order. Two advisories can fix one CVE at the
	// same version (Rocky and AlmaLinux re-issue errata), and the stable
	// sorts below keep input order on such ties, so the chosen rule (its
	// advisory id, rule id and source URL) must not depend on map order.
	ruleList = append([]*rules.PackageVulnerabilityRule(nil), ruleList...)
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].RuleID < ruleList[j].RuleID })
	ruleList = collapseSiblingRules(p, preferCompatibleArch(p, ruleList))
	var evals []ruleEvaluation
	for _, r := range ruleList {
		ev := EvaluateRule(p, plat, r)
		if !ev.applicable {
			res.Metrics.RulesRejected++
			continue
		}
		res.Metrics.RulesApplicable++
		if ev.comparison != nil && ev.comparison.Error != "" {
			res.Metrics.ComparatorErrors++
		}
		evals = append(evals, ev)
	}
	if len(evals) == 0 {
		return nil
	}

	// Supersede logic: for several released rules (multiple USNs fixing the
	// same CVE), the highest fixed version is authoritative.
	var released []ruleEvaluation
	var others []ruleEvaluation
	for _, ev := range evals {
		if ev.rule.Status == rules.StatusReleased {
			released = append(released, ev)
		} else {
			others = append(others, ev)
		}
	}
	// Supersede only among rules for the same binary package identity.
	released = filterEvaluationsForBinary(released, p)
	others = filterEvaluationsForBinary(others, p)
	var chosen ruleEvaluation
	var superseded []string
	switch {
	case len(released) > 0:
		sort.SliceStable(released, func(i, j int) bool {
			cmp, err := version.ForEcosystem(released[i].rule.Comparator)
			if err != nil {
				return false
			}
			c, err := cmp.Compare(released[i].rule.FixedVersion, released[j].rule.FixedVersion)
			if err != nil {
				return false
			}
			return c > 0 // highest fixed version first
		})
		chosen = released[0]
		for _, ev := range released[1:] {
			superseded = append(superseded, ev.rule.RuleID)
		}
	case len(others) > 0:
		// No released rule: prefer the most severe deterministic outcome.
		rank := map[string]int{
			findings.StateVulnerable:            0,
			findings.StatePotentiallyVulnerable: 1,
			findings.StateUnknown:               2,
			findings.StateNotApplicable:         3,
		}
		sort.SliceStable(others, func(i, j int) bool { return rank[others[i].state] < rank[others[j].state] })
		chosen = others[0]
	default:
		return nil
	}

	// Conflict detection: an applicable not_affected rule combined with a
	// vulnerable outcome from another equally-authoritative rule.
	var conflicts []string
	for _, ev := range evals {
		if ev.rule.RuleID == chosen.rule.RuleID {
			continue
		}
		bothVendor := ev.rule.SourcePriority == chosen.rule.SourcePriority
		disagree := (ev.state == findings.StateNotApplicable && chosen.state == findings.StateVulnerable && ev.rule.Status == rules.StatusNotAffected) ||
			(chosen.state == findings.StateNotApplicable && ev.state == findings.StateVulnerable && chosen.rule.Status == rules.StatusNotAffected)
		if bothVendor && disagree {
			conflicts = append(conflicts, fmt.Sprintf("rule %s (%s) disagrees with rule %s (%s)", ev.rule.RuleID, ev.state, chosen.rule.RuleID, chosen.state))
		} else if !bothVendor && disagree {
			// Lower-priority source disagreeing with the vendor: vendor wins,
			// informational conflict recorded.
			conflicts = append(conflicts, fmt.Sprintf("informational: lower-priority source rule %s (%s) disagrees with vendor decision", ev.rule.RuleID, ev.state))
		}
	}
	state := chosen.state
	if len(conflicts) > 0 && strings.Contains(strings.Join(conflicts, " "), "disagrees with rule") {
		state = findings.StateConflictingEvidence
	}

	confidence := "high"
	if p.Source.Confidence == "inferred" && chosen.rule.SourcePackage != p.Name {
		// The rule matched via an inferred source mapping.
		confidence = "medium"
	}

	// T04 provenance: vendor rules describe the vendor's own builds. Only
	// affirmative third-party evidence lowers confidence. "unknown" (the
	// installed version is no longer present in apt indexes — expected for
	// superseded, i.e. outdated, vendor packages) is labeled but never
	// treated as local and never downgraded on absence of evidence alone.
	provenance := ""
	var provenanceReason string
	if p.Scope == pkgs.ScopeHost && p.Ecosystem == "dpkg" {
		provenance = p.Provenance(plat.DistributionID)
		switch provenance {
		case pkgs.ProvenanceThirdParty:
			if confidence == "high" {
				confidence = "medium"
			}
			provenanceReason = fmt.Sprintf("package originates from a third-party repository (origin %q); the vendor advisory may not describe this build", p.RepositoryOrigin)
		case pkgs.ProvenanceUnknown:
			provenanceReason = "installed version not present in current apt indexes (superseded or local); provenance unverified, not treated as local"
		}
	}

	cveID, findingType := splitVulnerabilityKey(vulnKey, ruleList)
	groupKey := vulnKey
	if cveID != "" {
		groupKey = cveID
	}

	f := &findings.Finding{
		FindingID:           findingID(res.AssetID, p.Scope+p.ScopeID, groupKey, p.Name, p.RawVersion),
		AssetID:             res.AssetID,
		Scope:               p.Scope,
		FindingType:         findingType,
		CVEID:               cveID,
		State:               state,
		Confidence:          confidence,
		DetectionMethod:     method,
		BinaryPackage:       p.Name,
		SourcePackage:       p.SourcePackage,
		SourceConfidence:    p.Source.Confidence,
		InstalledVersion:    p.RawVersion,
		FixedVersion:        chosen.rule.FixedVersion,
		Distribution:        chosen.rule.Distribution,
		Release:             chosen.rule.Release,
		Architecture:        p.Architecture,
		VendorStatus:        chosen.rule.Status,
		FixAvailability:     chosen.fixAvail,
		Urgency:             normalizeUrgency(chosen.rule.Urgency),
		Provenance:          provenance,
		RepositorySuite:     p.RepositorySuite,
		RepositoryComponent: p.RepositoryComponent,
		AdvisoryIDs:         chosen.rule.AdvisoryIDs,
		RuleIDs:             sortedRuleIDs(evals),
		EvidenceIDs:         []string{p.EvidenceID},
		Reasons:             chosen.reasons,
		Conflicts:           conflicts,
		Comparison:          chosen.comparison,
		SupersededRules:     superseded,
		Rule: &findings.RuleRef{
			RuleID:         chosen.rule.RuleID,
			Source:         chosen.rule.Vendor,
			SourceURL:      chosen.rule.SourceURL,
			SourceSnapshot: chosen.rule.SourceSnapshotID,
			Release:        chosen.rule.Release,
			FixedVersion:   chosen.rule.FixedVersion,
			Comparator:     chosen.rule.Comparator,
			VendorStatus:   chosen.rule.Status,
			RawStatus:      chosen.rule.RawStatus,
			SupportTier:    chosen.rule.SupportTier,
		},
	}
	if p.Source.Confidence == "inferred" {
		f.Reasons = append(f.Reasons, "source package mapping is inferred from the binary name (no native source metadata)")
	}
	if provenanceReason != "" {
		f.Reasons = append(f.Reasons, provenanceReason)
	}
	if f.FindingType == "" {
		switch {
		case f.CVEID != "":
			f.FindingType = findings.FindingTypeCVE
		case len(f.AdvisoryIDs) > 0:
			f.FindingType = findings.FindingTypeAdvisoryOnly
		}
	}
	assertBinaryFixedVersionInvariant(res, f, chosen.rule, p)
	return f
}

// ruleAppliesToInstalledBinary enforces release+source+binary+CVE rule identity.
// Source-package indexes may return sibling binaries; fixed versions must not
// be shared across them.
func ruleAppliesToInstalledBinary(p pkgs.InstalledPackage, r *rules.PackageVulnerabilityRule) bool {
	if r.Ecosystem == "pypi" {
		return true
	}
	if r.Ecosystem == "apk" {
		// secdb keys are origin packages and every subpackage of an origin
		// carries the origin's version (libcrypto3 and libssl3 are built
		// from openssl), so an origin rule applies to all of them.
		return r.PackageName == p.Name || (r.SourcePackage != "" && r.SourcePackage == p.SourcePackage)
	}
	if r.PackageName == "" {
		return r.SourcePackage == "" || r.SourcePackage == p.SourcePackage
	}
	return r.PackageName == p.Name
}

func filterEvaluationsForBinary(evals []ruleEvaluation, p pkgs.InstalledPackage) []ruleEvaluation {
	if len(evals) == 0 {
		return evals
	}
	out := make([]ruleEvaluation, 0, len(evals))
	for _, ev := range evals {
		if ruleAppliesToInstalledBinary(p, ev.rule) {
			out = append(out, ev)
		}
	}
	return out
}

func assertBinaryFixedVersionInvariant(res *RunResult, f *findings.Finding, rule *rules.PackageVulnerabilityRule, p pkgs.InstalledPackage) {
	if rule.PackageName != "" && rule.PackageName != f.BinaryPackage && rule.Ecosystem != "apk" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"invariant violation: finding %s/%s fixed version taken from rule binary %q",
			f.BinaryPackage, f.CVEID, rule.PackageName,
		))
	}
	if f.Comparison != nil && f.FixedVersion != "" && f.Comparison.Fixed != f.FixedVersion {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"invariant violation: finding %s/%s comparison fixed %q != finding fixed %q",
			f.BinaryPackage, f.CVEID, f.Comparison.Fixed, f.FixedVersion,
		))
	}
	if rule.RawStatus != "" && f.Rule != nil && f.Rule.RawStatus == "" {
		f.Rule.RawStatus = rule.RawStatus
	}
	_ = p
}

// enrichRuntime applies Task 10 runtime enrichment to a host finding.
// A vulnerable-but-not-running package stays vulnerable; a fixed package
// with a deleted vulnerable executable still running becomes
// vulnerable_runtime.
func (e *Engine) enrichRuntime(f *findings.Finding, p pkgs.InstalledPackage, idx *runtime.RuntimeIndex) {
	exp := idx.ExposureFor(p.Name, p.SourcePackage)
	if !exp.Running {
		if f.State == findings.StateVulnerable || f.State == findings.StatePotentiallyVulnerable {
			f.RuntimeState = findings.RuntimeNotObserved
			f.Reasons = append(f.Reasons, "package is installed but no matching process was observed running; state remains "+f.State)
		}
		return
	}
	f.RuntimeState = findings.RuntimeRunning
	f.RuntimeProcessIDs = uniqueStrings(exp.ProcessIDs)
	f.RuntimeBinaryPaths = uniqueStrings(exp.BinaryPaths)
	f.RuntimeServices = uniqueStrings(exp.Services)

	if exp.DeletedExecutable {
		switch f.State {
		case findings.StateFixed:
			// Fixed on disk, but the old (potentially vulnerable) binary is
			// still mapped in a running process.
			f.State = findings.StateVulnerableRuntime
			f.Reasons = append(f.Reasons, "package is fixed on disk but a process still runs a deleted (pre-update) executable or library; restart required")
		case findings.StateVulnerable:
			f.Reasons = append(f.Reasons, "a matching process runs a deleted executable; the on-disk package was updated after process start")
		}
	}
}

func findingID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "finding-" + hex.EncodeToString(h[:8])
}

func sortedRuleIDs(evals []ruleEvaluation) []string {
	var ids []string
	for _, ev := range evals {
		ids = append(ids, ev.rule.RuleID)
	}
	sort.Strings(ids)
	return ids
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Scope != fs[j].Scope {
			return fs[i].Scope < fs[j].Scope
		}
		if fs[i].BinaryPackage != fs[j].BinaryPackage {
			return fs[i].BinaryPackage < fs[j].BinaryPackage
		}
		keyI := fs[i].CVEID
		if keyI == "" && len(fs[i].AdvisoryIDs) > 0 {
			keyI = fs[i].AdvisoryIDs[0]
		}
		keyJ := fs[j].CVEID
		if keyJ == "" && len(fs[j].AdvisoryIDs) > 0 {
			keyJ = fs[j].AdvisoryIDs[0]
		}
		return keyI < keyJ
	})
}

func vulnerabilityKey(r *rules.PackageVulnerabilityRule) string {
	if cve := strings.ToUpper(strings.TrimSpace(r.CVEID)); strings.HasPrefix(cve, "CVE-") {
		return cve
	}
	if cve := strings.TrimSpace(r.CVEID); strings.HasPrefix(cve, "USN-") {
		return "advisory:" + cve
	}
	if len(r.AdvisoryIDs) > 0 {
		return "advisory:" + r.AdvisoryIDs[0]
	}
	return r.RuleID
}

func splitVulnerabilityKey(vulnKey string, ruleList []*rules.PackageVulnerabilityRule) (cveID, findingType string) {
	if strings.HasPrefix(vulnKey, "CVE-") {
		return vulnKey, findings.FindingTypeCVE
	}
	if strings.HasPrefix(vulnKey, "advisory:") {
		return "", findings.FindingTypeAdvisoryOnly
	}
	if strings.HasPrefix(vulnKey, "USN-") {
		return "", findings.FindingTypeAdvisoryOnly
	}
	for _, r := range ruleList {
		if cve := strings.ToUpper(strings.TrimSpace(r.CVEID)); strings.HasPrefix(cve, "CVE-") {
			return cve, findings.FindingTypeCVE
		}
	}
	if len(ruleList) > 0 && len(ruleList[0].AdvisoryIDs) > 0 {
		return "", findings.FindingTypeAdvisoryOnly
	}
	return vulnKey, findings.FindingTypeCVE
}

func indexFindings(fs []findings.Finding) map[string]int {
	idx := make(map[string]int, len(fs))
	for i := range fs {
		idx[fs[i].FindingID] = i
	}
	return idx
}

func reconcileOutput(res *RunResult) {
	var rec findings.OutputReconciliation
	for _, f := range res.Findings {
		switch f.State {
		case findings.StateVulnerable:
			rec.SerializedVulnerable++
			res.Metrics.FindingsVulnerable++
		case findings.StateFixed:
			rec.SerializedFixed++
			res.Metrics.FindingsFixed++
		case findings.StateNotApplicable:
			res.Metrics.FindingsNotApplicable++
		case findings.StateUnknown:
			res.Metrics.FindingsUnknown++
		case findings.StateConflictingEvidence:
			res.Metrics.FindingsConflicting++
		case findings.StateVulnerableRuntime:
			res.Metrics.FindingsVulnerableRuntime++
		case findings.StatePotentiallyVulnerable:
			res.Metrics.FindingsPotentially++
		}
		switch f.FindingType {
		case findings.FindingTypeCVE:
			rec.CVEFindings++
		case findings.FindingTypeAdvisoryOnly:
			rec.AdvisoryOnlyFindings++
		}
		if f.Scope == ScopePythonEnvironment {
			rec.PythonEnvironmentFindings++
		}
	}
	for _, d := range res.DeduplicatedFindings {
		switch d.State {
		case findings.StateVulnerable, findings.StateVulnerableRuntime:
			rec.DeduplicatedVulnerable++
			res.Metrics.FindingsVulnerable++
		case findings.StateFixed:
			rec.DeduplicatedFixed++
			res.Metrics.FindingsFixed++
		}
		if d.ResolverEcosystem == python.EcosystemUbuntuDPKG {
			rec.PythonCorrelatedUbuntu++
		}
	}
	rec.Balanced = (rec.SerializedVulnerable+rec.DeduplicatedVulnerable == res.Metrics.FindingsVulnerable) &&
		(rec.SerializedFixed+rec.DeduplicatedFixed == res.Metrics.FindingsFixed)
	rec.RemediationGroups, rec.RemediationCloses, rec.RemediationBalanced = remediationInvariant(res)
	res.Reconciliation = rec
}

// normalizeUrgency writes the vendor's priority in one form: lower case, and nothing for an
// unrated rule (feeds say "None", "", "unknown" or "not yet assigned" for it).
func normalizeUrgency(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	switch u {
	case "", "none", "unknown", "not yet assigned", "unassigned":
		return ""
	}
	return u
}
