package resolver

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/runtime"
	rpmver "github.com/s4e-io/openness-resolver/internal/version/rpm"
)

// resolveHostVendor evaluates installed host packages against the vendor
// rules of the asset's own distribution and release (Debian, Rocky Linux,
// AlmaLinux, RHEL, openSUSE Leap). Rules are matched by binary name and by
// source package; the rule index is keyed by distribution + release, so a
// host never matches another distribution's or release's rules.
func (e *Engine) resolveHostVendor(res *RunResult, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex, ev hostEvaluator) {
	distro := res.Platform.DistributionID
	release := res.Platform.RuleRelease()
	stale := staleKernelPackages(pkgIndex, ev.ecosystem, res.Platform.KernelVersion)
	if len(stale) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d installed kernel package(s) do not match the running kernel %s and were not evaluated (old kernels on disk are not the running attack surface)", len(stale), res.Platform.KernelVersion))
	}
	for _, p := range pkgIndex.All {
		if p.Ecosystem != ev.ecosystem {
			continue
		}
		if stale[p.IdentityKey()] {
			continue
		}
		if p.SourcePackage != "" {
			res.Metrics.PackagesWithSourcePackage++
		}
		candidates := map[string]*rules.PackageVulnerabilityRule{}
		for _, r := range e.Rules.ForBinaryPackage(ev.ecosystem, distro, release, p.Name) {
			candidates[r.RuleID] = r
		}
		if p.SourcePackage != "" {
			for _, r := range e.Rules.ForSourcePackage(ev.ecosystem, distro, release, p.SourcePackage) {
				if !ruleAppliesToInstalledBinary(*p, r) {
					continue
				}
				candidates[r.RuleID] = r
			}
		}
		if len(candidates) == 0 {
			res.Metrics.PackagesWithoutVendorRules++
			continue
		}
		res.Metrics.PackagesWithVendorRules++
		fs := e.decidePackage(res, *p, candidates, res.Platform, ev.method)
		for i := range fs {
			e.enrichRuntime(&fs[i], *p, runtimeIdx)
		}
		res.Findings = append(res.Findings, fs...)
	}
}

// staleKernelPackages returns the identity keys of installed kernel
// packages that belong to a kernel other than the running one. Several
// kernels are normally installed side by side; only the running one is the
// attack surface (a fixed kernel on disk without a reboot stays reported
// through the running one). Nothing is filtered when the running kernel is
// unknown or no installed kernel matches it.
func staleKernelPackages(idx *pkgs.Index, ecosystem, running string) map[string]bool {
	running = strings.TrimSpace(running)
	out := map[string]bool{}
	if idx == nil || running == "" {
		return out
	}
	switch ecosystem {
	case "dpkg":
		// Debian kernel binaries carry the ABI in their name:
		// linux-image-6.1.0-18-amd64, linux-headers-6.1.0-18-common.
		abi := dpkgKernelABI(running)
		if abi == "" {
			return out
		}
		for _, p := range idx.All {
			if p.Ecosystem != "dpkg" {
				continue
			}
			suffix, ok := dpkgKernelSuffix(p.Name)
			if !ok || suffix == "" || suffix[0] < '0' || suffix[0] > '9' {
				continue // meta packages (linux-image-amd64) are evaluated
			}
			if suffix != abi && !strings.HasPrefix(suffix, abi+"-") {
				out[p.IdentityKey()] = true
			}
		}
	case "rpm":
		// RPM kernels share one name; versions differ.
		byName := map[string][]*pkgs.InstalledPackage{}
		for _, p := range idx.All {
			if p.Ecosystem == "rpm" && isRPMKernelPackage(p) {
				byName[p.Name] = append(byName[p.Name], p)
			}
		}
		for _, list := range byName {
			if len(list) < 2 {
				continue
			}
			matched := false
			for _, p := range list {
				if rpmKernelMatchesRunning(p, running) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			for _, p := range list {
				if !rpmKernelMatchesRunning(p, running) {
					out[p.IdentityKey()] = true
				}
			}
		}
	}
	return out
}

// dpkgKernelABI turns "6.1.0-18-amd64" into "6.1.0-18".
func dpkgKernelABI(running string) string {
	parts := strings.SplitN(running, "-", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "-" + parts[1]
}

func dpkgKernelSuffix(name string) (string, bool) {
	for _, prefix := range []string{"linux-image-", "linux-headers-", "linux-modules-", "linux-kbuild-"} {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimPrefix(name, prefix), true
		}
	}
	return "", false
}

func isRPMKernelPackage(p *pkgs.InstalledPackage) bool {
	if p.Name != "kernel" && !strings.HasPrefix(p.Name, "kernel-") {
		return false
	}
	src := p.SourcePackage
	return src == "" || src == "kernel" || strings.HasPrefix(src, "kernel-")
}

// rpmKernelMatchesRunning compares an installed kernel package with uname -r:
// RHEL family "5.14.0-427.13.1.el9_4.x86_64" starts with version-release;
// SUSE "6.4.0-150600.23.25-default" is version-release without the last
// release component and with a flavour suffix.
func rpmKernelMatchesRunning(p *pkgs.InstalledPackage, running string) bool {
	vr := p.Version
	if p.Release != "" {
		vr += "-" + p.Release
	}
	if vr == "" {
		vr = p.RawVersion
		if i := strings.IndexByte(vr, ':'); i >= 0 {
			vr = vr[i+1:]
		}
	}
	if vr == "" {
		return false
	}
	if strings.HasPrefix(running, vr) {
		return true
	}
	base := running
	if i := strings.LastIndexByte(base, '-'); i > 0 {
		flavour := base[i+1:]
		if flavour != "" && (flavour[0] < '0' || flavour[0] > '9') {
			base = base[:i]
		}
	}
	if !strings.Contains(base, "-") || !strings.HasPrefix(vr, base) {
		return false
	}
	rest := vr[len(base):]
	return rest == "" || rest[0] == '.'
}

// rpmStreamMismatch keeps modular (RHEL 8 modularity) fixes on their own
// stream. A fix built for a module stream ("...module+el8.9.0+...") says
// nothing about a non-modular build or another stream of the same package
// (nodejs 18 vs nodejs 20), so it is only applied when the installed
// package is modular too and shares the upstream major version.
func rpmStreamMismatch(installed, fixed string) string {
	if !rpmver.IsModular(fixed) {
		return ""
	}
	if !rpmver.IsModular(installed) {
		return fmt.Sprintf("module stream mismatch: fix %s is a modular build, installed %s is not", fixed, installed)
	}
	ie, err1 := rpmver.Parse(installed)
	fe, err2 := rpmver.Parse(fixed)
	if err1 != nil || err2 != nil {
		return ""
	}
	if upstreamMajor(ie.Version) != upstreamMajor(fe.Version) {
		return fmt.Sprintf("module stream mismatch: fix %s targets another stream than installed %s", fixed, installed)
	}
	return ""
}

func upstreamMajor(v string) string {
	if i := strings.IndexAny(v, ".~^+_"); i >= 0 {
		return v[:i]
	}
	return v
}
