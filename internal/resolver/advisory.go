package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/advisory"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// MethodAdvisory: the finding comes from a shipped advisory (internal/advisory), not from a
// vendor feed: the install's version was compared with the versions the advisory names.
const MethodAdvisory = "advisory_version_range"

// advisoryRules adds the advisory rules of a source package to the candidate rules of an
// installed package. They join the feed's rules for the same CVE and merge into one finding.
func (e *Engine) advisoryRules(candidates map[string]*rules.PackageVulnerabilityRule, p pkgs.InstalledPackage, eco, distro, release string) {
	if e.Advisories == nil || p.SourcePackage == "" {
		return
	}
	for _, r := range e.Advisories.ForSourcePackage(eco, distro, release, p.SourcePackage) {
		if ruleAppliesToInstalledBinary(p, r) {
			candidates[r.RuleID] = r
		}
	}
}

// resolveAdvisoryInstances evaluates the software installs found on disk (Java runtimes)
// against the advisories, for hosts the vendor feeds do not cover for the CVE yet.
//
//   - An install whose files belong to a package of the distribution is judged by the
//     distribution: when a finding for the CVE exists for that package (any state, a fix
//     already installed included) nothing is added; when none exists the install is only
//     potentially vulnerable, because a distribution backports fixes without changing the
//     version the install reports.
//   - Any other install (an archive from the vendor, an installer, a package of a third
//     party) is vulnerable when its version is in the affected range and below the fixed one.
//   - A host whose CPU architecture the advisory excludes (ARM64 for Java4Shell) gets nothing.
func (e *Engine) resolveAdvisoryInstances(res *RunResult, recs []evidence.TypedRecord[evidence.SoftwareInstanceValue], idx *pkgs.Index) {
	if e.Advisories == nil || len(recs) == 0 {
		return
	}
	for _, a := range e.Advisories.Advisories {
		if a.Instances == nil {
			continue
		}
		if !a.AffectsArchitecture(res.Platform.Architecture) {
			n := 0
			for _, r := range recs {
				if r.Value.ProductKey == a.Instances.ProductKey {
					n++
				}
			}
			if n > 0 {
				res.Notes = append(res.Notes, fmt.Sprintf("%s (%s): not affected on %s, %d %s not listed", a.CVE, a.ID, res.Platform.Architecture, n, plural(n, "install", "installs")))
			}
			continue
		}
		for _, r := range recs {
			v := r.Value
			if v.ProductKey != a.Instances.ProductKey || v.Version == "" {
				continue
			}
			verdict, fixed := a.EvaluateInstance(v.Version)
			if verdict == advisory.Unknown {
				continue
			}
			if res.advisoryJudged == nil {
				res.advisoryJudged = map[string]string{}
			}
			res.advisoryJudged[v.EntityID] = fmt.Sprintf("%s (%s): %s", a.CVE, a.ID, strings.ReplaceAll(verdict, "_", " "))
			if verdict != advisory.Affected {
				continue
			}
			state, owner := findings.StateVulnerable, ""
			var reasons []string
			if v.OwnerPackageStatus == "owned" && v.OwnerPackage != nil && v.OwnerPackage.Name != "" {
				op := ownerPackage(idx, v.OwnerPackage)
				if op != nil && op.Provenance(res.Platform.DistributionID) != pkgs.ProvenanceThirdParty {
					if hasPackageFinding(res, a.CVE, op) {
						continue // the distribution decided this install already
					}
					state, owner = findings.StatePotentiallyVulnerable, op.Name
					reasons = append(reasons, fmt.Sprintf("the files belong to package %s of the distribution, which has not published a decision for %s in the data yet; the package version decides, not the version %s the install reports", op.Name, a.CVE, v.Version))
				}
			}
			res.Findings = append(res.Findings, advisoryFinding(res, a, r, state, fixed, owner, reasons))
			if fixed != "" {
				res.RemediationGroups = append(res.RemediationGroups, advisoryRemediation(res, a, r, fixed))
			}
		}
	}
}

// ownerPackage finds the installed package an instance's owner record names.
func ownerPackage(idx *pkgs.Index, o *evidence.OwnerPackage) *pkgs.InstalledPackage {
	if idx == nil {
		return nil
	}
	if o.EntityID != "" {
		if p := idx.ByEntityID[o.EntityID]; p != nil {
			return p
		}
	}
	return idx.LookupHost(o.Name)
}

// hasPackageFinding says whether a vendor decision exists for the CVE on the package or
// another binary of its source package.
func hasPackageFinding(res *RunResult, cve string, p *pkgs.InstalledPackage) bool {
	for _, f := range res.Findings {
		if f.CVEID != cve || f.Scope != pkgs.ScopeHost || f.DetectionMethod == MethodAdvisory {
			continue
		}
		if f.BinaryPackage == p.Name || (p.SourcePackage != "" && f.SourcePackage == p.SourcePackage) {
			return true
		}
	}
	return false
}

func advisoryFinding(res *RunResult, a advisory.Advisory, r evidence.TypedRecord[evidence.SoftwareInstanceValue], state, fixed, owner string, extra []string) findings.Finding {
	v := r.Value
	sum := sha256.Sum256([]byte(strings.Join([]string{res.AssetID, a.ID, v.EntityID}, "|")))
	reasons := []string{fmt.Sprintf("Java %s at %s is in the range %s affects; %s", v.Version, orDash(v.InstallPath), a.CVE, fixText(fixed))}
	reasons = append(reasons, extra...)
	if a.Condition != "" {
		reasons = append(reasons, a.Condition)
	}
	if a.SeverityNote != "" {
		reasons = append(reasons, a.SeverityNote)
	}
	if a.Mitigation != "" {
		reasons = append(reasons, "Mitigation: "+a.Mitigation)
	}
	f := findings.Finding{
		FindingID:        "advisory-" + hex.EncodeToString(sum[:8]),
		AssetID:          res.AssetID,
		Scope:            pkgs.ScopeHost,
		FindingType:      findings.FindingTypeCVE,
		CVEID:            a.CVE,
		State:            state,
		Confidence:       "medium",
		DetectionMethod:  MethodAdvisory,
		BinaryPackage:    "Java runtime (" + orDash(v.InstallPath) + ")",
		SourcePackage:    a.Instances.ProductKey,
		InstalledVersion: v.Version,
		FixedVersion:     fixed,
		Distribution:     res.Platform.DistributionID,
		Architecture:     res.Platform.Architecture,
		VendorStatus:     "advisory",
		AdvisoryIDs:      []string{a.ID},
		Severity:         a.Severity,
		RuleIDs:          []string{"advisory:" + a.ID},
		EvidenceIDs:      []string{r.EvidenceID},
		Reasons:          reasons,
	}
	if fixed != "" {
		f.FixAvailability = findings.FixAvailable
	} else {
		f.FixAvailability = findings.FixUnavailable
	}
	if owner != "" {
		f.RawPackageName = owner
	}
	return f
}

func advisoryRemediation(res *RunResult, a advisory.Advisory, r evidence.TypedRecord[evidence.SoftwareInstanceValue], fixed string) findings.RemediationGroup {
	v := r.Value
	sum := sha256.Sum256([]byte(strings.Join([]string{res.AssetID, a.ID, v.EntityID}, "|")))
	fid := "advisory-" + hex.EncodeToString(sum[:8])
	n := 1
	return findings.RemediationGroup{
		GroupID: remediationGroupID(res.AssetID, pkgs.ScopeHost, findings.ActionUpdateApplication, "advisory:"+a.ID+":"+v.EntityID),
		Scope:   pkgs.ScopeHost,
		Action:  findings.ActionUpdateApplication,
		Targets: []findings.RemediationTarget{{
			Name: "Java runtime (" + orDash(v.InstallPath) + ")", Architecture: res.Platform.Architecture,
			InstalledVersion: v.Version, TargetVersion: fixed, Kind: findings.TargetKindApplication,
		}},
		SourcePackage:          a.Instances.ProductKey,
		AdvisoryIDs:            []string{a.ID},
		Closes:                 closeSet([]string{fid}, []string{a.CVE}, &n),
		RequiresServiceRestart: []string{},
		Availability:           findings.AvailabilityAvailable,
		CommandHint:            fmt.Sprintf("Update this Java install to %s or newer, then restart what runs on it. Until then start the JVM with -XX:-UseBASE64Intrinsics.", fixed),
	}
}

func fixText(fixed string) string {
	if fixed == "" {
		return "its release line has no fix: move to a fixed line"
	}
	return "fixed in " + fixed
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
