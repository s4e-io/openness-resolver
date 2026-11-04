package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/version/winbuild"
)

// MethodMSRCFixedBuild marks findings decided by comparing the installed
// Windows build.UBR against the MSRC FixedBuild of a vendor fix.
const MethodMSRCFixedBuild = "msrc_fixed_build_ubr"

// resolveWindowsOS evaluates MSRC winbuild rules for the host's product key
// against the installed "<build>.<ubr>". The OS is modelled as one synthetic
// package named "windows" so the generic decision table and supersede logic
// apply unchanged. Rules for another build number are the same product on a
// different servicing branch; they are rejected, not compared. Builds that
// share one cumulative update (19041-19045, 22621/22631, 26100/26200) are one
// branch, see winbuild.SameBuild.
func (e *Engine) resolveWindowsOS(res *RunResult) {
	plat := res.Platform
	if plat.Codename == "" || plat.WindowsBuild == "" {
		res.Notes = append(res.Notes, "windows product or build missing; MSRC rules cannot be selected")
		return
	}
	if plat.Architecture == "" {
		res.Notes = append(res.Notes, "windows architecture missing from evidence; architecture specific MSRC rules (client editions) cannot apply")
	}
	candidates := map[string]*rules.PackageVulnerabilityRule{}
	for _, r := range e.Rules.ForBinaryPackage(winbuild.Ecosystem, "windows", plat.Codename, "windows") {
		if !winbuild.SameBuild(plat.WindowsBuild, r.FixedVersion) {
			res.Metrics.RulesRejected++
			continue
		}
		// MSRC client products come per architecture (x64, ARM64, 32-bit)
		// with identical fixed builds. Drop the other architectures here:
		// the generic sibling collapse does not key on architecture and
		// could otherwise keep only the 32-bit rule, which then reads as
		// not_applicable on an x64 host and silently hides the CVE.
		if plat.Architecture != "" && !platform.ArchitectureCompatible(plat.Architecture, r.Architecture) {
			res.Metrics.RulesRejected++
			continue
		}
		candidates[r.RuleID] = r
	}
	if len(candidates) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("no MSRC rules for %s on build %s", plat.Codename, plat.WindowsBuild))
		return
	}
	candidates = selectServicingStream(res, plat.WindowsBuild, candidates)
	p := pkgs.InstalledPackage{
		Scope:         pkgs.ScopeHost,
		Ecosystem:     winbuild.Ecosystem,
		Name:          "windows",
		SourcePackage: plat.Codename,
		RawVersion:    plat.WindowsBuild,
		Architecture:  plat.Architecture,
	}
	fs := e.decidePackage(res, p, candidates, plat, MethodMSRCFixedBuild)
	for i := range fs {
		if fs[i].State == findings.StateVulnerable {
			// The operating system is running by definition.
			fs[i].RuntimeState = findings.RuntimeRunning
		}
	}
	res.Metrics.HostPackages++
	res.Findings = append(res.Findings, fs...)
}

// isHotpatchRule reports MSRC hotpatch remediations ("Security Hotpatch
// Update", "SecurityHotpatchUpdate", "AzureHotpatch").
func isHotpatchRule(r *rules.PackageVulnerabilityRule) bool {
	return strings.Contains(strings.ToLower(r.RawStatus), "hotpatch")
}

// selectServicingStream keeps the MSRC rules that apply to the host's update
// stream. MSRC lists a hotpatch KB and a regular cumulative update as
// alternative fixes for the same CVE; the hotpatch build has the lower UBR.
// Hotpatch builds have their own UBR values, so a host whose UBR equals a
// hotpatch fixed build (and no regular one) is hotpatch enrolled: for every
// CVE that has a hotpatch fix, that fix decides. Any other host never runs a
// hotpatch build, so hotpatch rules are dropped and the regular cumulative
// update decides. Without this a fully patched hotpatch host is reported
// vulnerable to every CVE of the month.
func selectServicingStream(res *RunResult, installed string, candidates map[string]*rules.PackageVulnerabilityRule) map[string]*rules.PackageVulnerabilityRule {
	host, err := winbuild.Parse(installed)
	if err != nil {
		return candidates
	}
	onHotpatch, onRegular := false, false
	for _, r := range candidates {
		f, err := winbuild.Parse(r.FixedVersion)
		if err != nil || f.UBR != host.UBR {
			continue
		}
		if isHotpatchRule(r) {
			onHotpatch = true
		} else {
			onRegular = true
		}
	}
	hotpatchHost := onHotpatch && !onRegular
	hasHotpatch := map[string]bool{}
	for _, r := range candidates {
		if isHotpatchRule(r) {
			hasHotpatch[strings.ToUpper(r.CVEID)] = true
		}
	}
	out := make(map[string]*rules.PackageVulnerabilityRule, len(candidates))
	dropped := 0
	for id, r := range candidates {
		keep := !isHotpatchRule(r)
		if hotpatchHost && hasHotpatch[strings.ToUpper(r.CVEID)] {
			keep = isHotpatchRule(r)
		}
		if keep {
			out[id] = r
		} else {
			dropped++
		}
	}
	if hotpatchHost {
		res.Notes = append(res.Notes, fmt.Sprintf("windows build %s is a hotpatch build; hotpatch fixes decide the CVEs that have one (%d regular update rules set aside)", installed, dropped))
	} else if dropped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("windows build %s is not a hotpatch build; %d hotpatch rules set aside", installed, dropped))
	}
	return out
}

// windowsUpdateCard builds one action card for every vulnerable Windows OS
// finding: install the cumulative update with the highest fixed UBR. Because
// servicing is cumulative, that single KB closes every finding whose fixed
// UBR is lower or equal.
func (e *Engine) windowsUpdateCard(res *RunResult) *findings.RemediationGroup {
	var vulnerable []findings.Finding
	for _, f := range res.Findings {
		if f.Scope == pkgs.ScopeHost && f.BinaryPackage == "windows" && f.DetectionMethod == MethodMSRCFixedBuild && f.State == findings.StateVulnerable {
			vulnerable = append(vulnerable, f)
		}
	}
	if len(vulnerable) == 0 {
		return nil
	}
	cmp := winbuild.Comparator{}
	target := vulnerable[0]
	for _, f := range vulnerable[1:] {
		if c, err := cmp.Compare(f.FixedVersion, target.FixedVersion); err == nil && c > 0 {
			target = f
		}
	}
	var ids, cves []string
	reboot := false
	for _, f := range vulnerable {
		ids = append(ids, f.FindingID)
		if f.CVEID != "" {
			cves = append(cves, f.CVEID)
		}
		if f.Rule != nil {
			if r, ok := e.Rules.ByID(f.Rule.RuleID); ok && r.RestartRequired {
				reboot = true
			}
		}
	}
	sort.Strings(ids)
	cves = uniqueStrings(cves)
	sort.Strings(cves)
	count := len(ids)
	installed := target.InstalledVersion
	targetVersion := target.FixedVersion
	if b, err := winbuild.Parse(installed); err == nil {
		// MSRC may publish the fix on a sibling build of the same servicing
		// branch (19041.x for a 19044 host); show it on the host's build.
		targetVersion = winbuild.OnBuild(targetVersion, b.Build)
	}
	return &findings.RemediationGroup{
		GroupID: remediationGroupID(res.AssetID, pkgs.ScopeHost, findings.ActionInstallUpdate, target.Release),
		Scope:   pkgs.ScopeHost,
		Action:  findings.ActionInstallUpdate,
		Targets: []findings.RemediationTarget{{
			Name:             "windows",
			Architecture:     target.Architecture,
			InstalledVersion: installed,
			TargetVersion:    targetVersion,
			Kind:             findings.TargetKindOSBuild,
		}},
		SourcePackage:          target.Release,
		AdvisoryIDs:            nonNilStrings(target.AdvisoryIDs),
		Closes:                 closeSet(ids, cves, &count),
		RequiresReboot:         reboot,
		RequiresServiceRestart: []string{},
		Availability:           findings.AvailabilityUnknown,
		CommandHint:            "",
		Notes: []string{
			fmt.Sprintf("cumulative update: installing %s (build %s) or any later cumulative update closes all %d findings", joinOr(target.AdvisoryIDs), targetVersion, count),
		},
	}
}

func joinOr(ids []string) string {
	if len(ids) == 0 {
		return "the latest cumulative update"
	}
	return ids[0]
}
