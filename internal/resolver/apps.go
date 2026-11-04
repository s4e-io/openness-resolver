package resolver

import (
	"encoding/json"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// Detection methods of third-party Windows application findings.
const (
	// MethodNVDCPERange: a catalog entry tied the application to NVD CPEs and its version
	// is in an affected range of one of them.
	MethodNVDCPERange = "nvd_cpe_version_range"
	// MethodNVDCPEGuess: the application is not in the catalog; its name looked like an NVD
	// product. The finding is potentially_vulnerable.
	MethodNVDCPEGuess = "nvd_cpe_name_guess"
)

// resolveApplications matches the installed applications of a Windows host against the
// application mapper (the catalog and its NVD data) and adds their findings, one update
// card per application version, and the list of applications with their match status.
func (e *Engine) resolveApplications(res *RunResult, recs []evidence.Record) {
	if e.Apps == nil {
		return
	}
	res.ApplicationMapper = e.Apps.Version
	values := make([]json.RawMessage, len(recs))
	for i, rec := range recs {
		values[i] = rec.Value
	}
	r := e.Apps.EvaluateApps(values, e.AppOptions)
	res.Applications = r.Applications
	if res.Applications == nil {
		res.Applications = []appvuln.Application{}
	}
	arch := res.Platform.Architecture
	for _, f := range r.Findings {
		method, confidence := MethodNVDCPERange, "high"
		switch {
		case f.Guess:
			method, confidence = MethodNVDCPEGuess, "low"
		case !f.Verified:
			confidence = "medium"
		}
		out := findings.Finding{
			FindingID:        f.FindingID,
			AssetID:          res.AssetID,
			Scope:            pkgs.ScopeHost,
			FindingType:      findings.FindingTypeCVE,
			CVEID:            f.CVEID,
			State:            f.State,
			Confidence:       confidence,
			DetectionMethod:  method,
			BinaryPackage:    f.BinaryPackage,
			SourcePackage:    f.SourcePackage,
			InstalledVersion: f.InstalledVersion,
			FixedVersion:     f.FixedVersion,
			Distribution:     "windows",
			Architecture:     arch,
			VendorStatus:     "nvd",
			Severity:         f.Severity,
			CVSSScore:        f.CVSSScore,
			MatchStrength:    f.MatchStrength,
			RuleIDs:          []string{"nvd:" + f.CPE + ":" + f.CVEID},
			EvidenceIDs:      []string{},
			Reasons:          f.Reasons,
		}
		if f.FixedVersion != "" {
			out.FixAvailability = findings.FixAvailable
		}
		res.Findings = append(res.Findings, out)
	}
	for _, c := range r.Remediations {
		n := len(c.FindingIDs)
		res.RemediationGroups = append(res.RemediationGroups, findings.RemediationGroup{
			GroupID: remediationGroupID(res.AssetID, pkgs.ScopeHost, findings.ActionUpdateApplication, c.GroupID),
			Scope:   pkgs.ScopeHost,
			Action:  findings.ActionUpdateApplication,
			Targets: []findings.RemediationTarget{{
				Name: c.ProductName, Architecture: arch, InstalledVersion: c.InstalledVersion,
				TargetVersion: c.FixedVersion, Kind: findings.TargetKindApplication,
			}},
			SourcePackage:          c.SourcePackage,
			AdvisoryIDs:            []string{},
			Closes:                 closeSet(c.FindingIDs, c.CVEIDs, &n),
			RequiresServiceRestart: []string{},
			Availability:           findings.AvailabilityAvailable,
			CommandHint:            c.CommandHint,
		})
	}
}
