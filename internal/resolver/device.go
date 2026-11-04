package resolver

import (
	"fmt"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/platform"
)

// ScopeNetworkDevice is the scope of a network device's findings.
const ScopeNetworkDevice = "network_device"

// ResolveDevice evaluates one network device (resolve --device) against the device entries
// of the application mapper. Nothing of the device but the first sysDescr line of a matched
// device (with addresses and dotted host names redacted) and the version the catalog reads
// is copied into the result.
func (e *Engine) ResolveDevice(dev appvuln.Device) *RunResult {
	start := e.Now()
	res := &RunResult{
		OutputSchemaVersion: findings.OutputSchemaVersion,
		GeneratedAt:         start.UTC(),
		Platform:            platform.PlatformContext{DistributionID: ScopeNetworkDevice},
		PlatformSupport:     string(platform.NotSupported),
		Findings:            []findings.Finding{},
		RemediationGroups:   []findings.RemediationGroup{},
		SoftwareInventory:   []SoftwareInstanceResult{},
		Unknowns:            []Unknown{},
		Notes:               []string{},
		EvidenceErrors:      []evidence.RecordError{},
		RuleCoverage:        RuleCoverage{LoadedReleases: []string{}, Sources: []CoverageSource{}},
	}
	if e.AppSource != nil {
		res.RuleCoverage.Sources = append(res.RuleCoverage.Sources, *e.AppSource)
	}
	if e.Apps == nil {
		res.RuleCoverage.State = CoverageNotSupported
		res.SupportReason = "no device catalog loaded"
		res.Notes = append(res.Notes, res.SupportReason)
		res.Unknowns = buildUnknowns(res)
		reconcileOutput(res)
		return res
	}
	res.ApplicationMapper = e.Apps.Version
	r := e.Apps.EvaluateDevice(dev, e.AppOptions)
	p := r.Product
	if p != nil {
		// Only a device a catalog entry recognised is labelled with its sysDescr: the
		// sysDescr of anything else (net-snmp on Linux: "Linux <hostname> ...") may name
		// the host.
		label := appvuln.FirstLine(dev.SysDescr)
		res.Asset.Platform, res.Platform.RawDistributionID = label, label
	}
	var unknown *Unknown
	switch {
	case p == nil:
		res.RuleCoverage.State = CoverageNotSupported
		res.SupportReason = "no device catalog entry matches this device"
		if r.Skipped != nil {
			res.SupportReason = fmt.Sprintf("only the unreviewed device entry %s matches this device; --app-unverified uses it", r.Skipped.ID)
		}
		res.RuleCoverage.Reason = res.SupportReason
		res.Notes = append(res.Notes, "network device not evaluated: "+res.SupportReason)
	case r.Version == "":
		res.PlatformSupport = string(platform.Supported)
		res.Platform.Codename, res.Platform.CodenameSource = p.ID, "device_catalog"
		res.RuleCoverage.AssetRelease = "device/" + p.ID
		res.RuleCoverage.RulesForAsset = r.Rules
		res.RuleCoverage.State = CoverageUnknown
		res.RuleCoverage.Reason = fmt.Sprintf("%s matched, but its version could not be read from %s", p.Name, p.Version.From)
		res.Notes = append(res.Notes, "network device version unknown: "+res.RuleCoverage.Reason+"; no CVE was checked")
		unknown = &Unknown{Kind: "rule_coverage", Subject: res.RuleCoverage.AssetRelease, Reason: "version_unreadable"}
	default:
		res.PlatformSupport = string(platform.Supported)
		res.Platform.Codename, res.Platform.CodenameSource = p.ID, "device_catalog"
		res.Platform.DistributionVersion = r.Version
		res.RuleCoverage.AssetRelease = "device/" + p.ID
		res.RuleCoverage.RulesForAsset = r.Rules
		res.RuleCoverage.LoadedReleases = []string{res.RuleCoverage.AssetRelease}
		res.RuleCoverage.State = CoverageCovered
		if r.Rules == 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("the vulnerability data holds no CVE for %s", p.Name))
		}
	}
	for _, f := range r.Findings {
		res.Findings = append(res.Findings, mapperFinding(f, "", ScopeNetworkDevice, "", ""))
	}
	for _, c := range r.Remediations {
		n := len(c.FindingIDs)
		res.RemediationGroups = append(res.RemediationGroups, findings.RemediationGroup{
			GroupID: remediationGroupID("", ScopeNetworkDevice, findings.ActionUpdateDevice, c.GroupID),
			Scope:   ScopeNetworkDevice,
			Action:  findings.ActionUpdateDevice,
			Targets: []findings.RemediationTarget{{
				Name: c.ProductName, InstalledVersion: c.InstalledVersion,
				TargetVersion: c.FixedVersion, Kind: findings.TargetKindDevice,
			}},
			SourcePackage:          c.SourcePackage,
			AdvisoryIDs:            []string{},
			Closes:                 closeSet(c.FindingIDs, c.CVEIDs, &n),
			RequiresServiceRestart: []string{},
			Availability:           findings.AvailabilityAvailable,
			CommandHint:            c.CommandHint,
		})
	}
	sortFindings(res.Findings)
	sortRemediationGroups(res.RemediationGroups)
	res.Unknowns = buildUnknowns(res)
	if unknown != nil {
		res.Unknowns = append(res.Unknowns, *unknown)
	}
	reconcileOutput(res)
	res.Metrics.ResolverDurationMS = e.Now().Sub(start).Milliseconds()
	return res
}
