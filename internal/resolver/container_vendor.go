package resolver

import (
	"fmt"

	"github.com/s4e-io/openness-resolver/internal/containers"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// GapContainerNotCovered: a container image with packages was not evaluated
// (no os-release and no other way to name its release, a distribution or
// release without a package evaluator, or no rules loaded for its release).
// One gap per image; Count is the number of containers running it and
// Detail names the image digest and the reason. The rest of the asset is
// evaluated, so the run is partial (exit 0).
const GapContainerNotCovered = "container_not_covered"

// containerEvaluator is the package evaluator for a non-Alpine image: the
// host evaluator of the same distribution, and for Ubuntu the Ubuntu
// source-package method. Images have no running kernel, so kernel rules
// are skipped; Ubuntu ESM entitlement is a host property and is not applied.
func containerEvaluator(distro string) (hostEvaluator, bool) {
	if distro == "ubuntu" {
		return hostEvaluator{ecosystem: "dpkg", method: MethodUbuntuSourcePackage}, true
	}
	if distro == "alpine" {
		return hostEvaluator{}, false // Alpine images keep their own path
	}
	ev, ok := hostEvaluators[distro]
	return ev, ok
}

// containerEvaluation decides whether a non-Alpine image can be evaluated.
// The platform comes from the image's os-release, mapped like the host
// platform, and must pass the same support matrix; the reason is empty when
// it can be evaluated.
func (e *Engine) containerEvaluation(group *containers.ImageGroup, plat platform.PlatformContext) (hostEvaluator, string) {
	if group.OSRelease == nil {
		family := group.Distro
		if family == "" {
			family = "unknown"
		}
		return hostEvaluator{}, fmt.Sprintf("no os-release in the image; package family %s does not name a distribution release", family)
	}
	ev, ok := containerEvaluator(plat.DistributionID)
	if !ok {
		return ev, fmt.Sprintf("distribution %q has no container package evaluator", plat.DistributionID)
	}
	if state, why := plat.Support(); state != platform.Supported {
		return ev, why
	}
	release := plat.RuleRelease()
	if release == "" {
		return ev, plat.DistributionID + " release could not be determined from os-release"
	}
	if !hasReleaseRules(e.Rules, plat.DistributionID, release) {
		return ev, fmt.Sprintf("no rules loaded for %s/%s (run feed sync --for this evidence)", plat.DistributionID, release)
	}
	return ev, ""
}

func hasReleaseRules(rs *rules.RuleSet, distro, release string) bool {
	if rs == nil {
		return false
	}
	for i := range rs.Rules {
		if rs.Rules[i].Distribution == distro && rs.Rules[i].Release == release {
			return true
		}
	}
	return false
}

// resolveContainerVendor evaluates a Debian, Ubuntu or RPM-family image
// with the host rules and comparators of its distribution and release.
// An image that cannot be evaluated becomes a container_not_covered gap.
func (e *Engine) resolveContainerVendor(res *RunResult, group *containers.ImageGroup) {
	plat := group.Platform(res.Platform.RawArchitecture)
	ev, reason := e.containerEvaluation(group, plat)
	if reason != "" {
		res.Notes = append(res.Notes, fmt.Sprintf("image %s (%s) not evaluated: %s", group.ImageDigest, imageLabel(group), reason))
		res.Metrics.PackagesWithoutVendorRules += len(group.Packages)
		return
	}
	distro, release := plat.DistributionID, plat.RuleRelease()
	for i := range group.Packages {
		p := group.Packages[i]
		if p.Ecosystem != ev.ecosystem {
			res.Metrics.PackagesWithoutVendorRules++
			continue
		}
		if p.Source.EvidenceSource != "binary_name_fallback" {
			res.Metrics.PackagesWithSourcePackage++
		}
		candidates := map[string]*rules.PackageVulnerabilityRule{}
		for _, r := range e.Rules.ForBinaryPackage(ev.ecosystem, distro, release, p.Name) {
			if !r.IsKernel {
				candidates[r.RuleID] = r
			}
		}
		for _, r := range e.Rules.ForSourcePackage(ev.ecosystem, distro, release, p.SourcePackage) {
			if !r.IsKernel && ruleAppliesToInstalledBinary(p, r) {
				candidates[r.RuleID] = r
			}
		}
		if len(candidates) == 0 {
			res.Metrics.PackagesWithoutVendorRules++
			continue
		}
		res.Metrics.PackagesWithVendorRules++
		fs := e.decidePackage(res, p, candidates, plat, ev.method)
		for j := range fs {
			fs[j].ImageDigest = group.ImageDigest
			fs[j].ContainerIDs = group.ContainerIDs()
		}
		res.Findings = append(res.Findings, fs...)
	}
}

// containerCoverage returns, for images that are not Alpine, the rule
// release of every evaluated image and a container_not_covered gap for
// every image with packages that was not evaluated.
func (e *Engine) containerCoverage(groups []*containers.ImageGroup, arch string) (releases []string, gaps []CoverageGap) {
	for _, g := range groups {
		if g == nil || g.Distro == "alpine" || len(g.Packages) == 0 {
			continue
		}
		plat := g.Platform(arch)
		if _, reason := e.containerEvaluation(g, plat); reason != "" {
			gaps = append(gaps, CoverageGap{
				Release: "container:" + imageLabel(g),
				Kind:    GapContainerNotCovered,
				Count:   len(g.Containers),
				Detail:  g.ImageDigest + ": " + reason,
			})
			continue
		}
		releases = append(releases, plat.DistributionID+"/"+plat.RuleRelease())
	}
	return releases, gaps
}

// imageLabel names an image for people: its reference, else its digest.
func imageLabel(g *containers.ImageGroup) string {
	for _, c := range g.Containers {
		if c.ImageReference != "" {
			return c.ImageReference
		}
	}
	return g.ImageDigest
}
