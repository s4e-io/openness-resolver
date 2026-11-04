package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/kernel"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
	"github.com/s4e-io/openness-resolver/internal/runtime"
	"github.com/s4e-io/openness-resolver/internal/version"
)

// safeHintToken rejects shell metacharacters in package/unit names used in
// informational command_hint lines (hints are never executed by the resolver).
var safeHintToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@/-]*$`)

func sanitizeHintTokens(names []string) (safe []string, notes []string) {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !safeHintToken.MatchString(n) {
			notes = append(notes, "hint_token_dropped:"+n)
			continue
		}
		safe = append(safe, n)
	}
	return safe, notes
}

func hintCoverage(existing *string, notes []string) *string {
	if existing != nil || len(notes) == 0 {
		return existing
	}
	note := "hint_tokens_omitted"
	return &note
}

// attachRemediation builds action cards for host vulnerable findings.
// Container rebuilds and Python distribution upgrades are a later slice:
// those findings are left out of the cards rather than given a guessed action.
//
// A finding id is written into at most one card. A package that is still
// vulnerable and also needs a service restart keeps the upgrade card; the
// unit is recorded on requires_service_restart. A vulnerable_runtime finding
// is not state=vulnerable, so it gets its own restart card and an empty
// closes list. That keeps the sum of closes.count equal to the host
// vulnerable population.
func (e *Engine) attachRemediation(res *RunResult, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex, rebootRequired bool) {
	esmActive := hostESMEntitlement(pkgIndex)
	groups := groupHostUpgrades(res, pkgIndex, runtimeIdx, esmActive)
	groups = append(groups, restartCards(res, pkgIndex, runtimeIdx)...)
	if card := e.windowsUpdateCard(res); card != nil {
		groups = append(groups, *card)
	}
	if rebootRequired {
		groups = append(groups, rebootCard(res.AssetID))
	}
	sortRemediationGroups(groups)
	if groups == nil {
		groups = []findings.RemediationGroup{}
	}
	res.RemediationGroups = groups
}

type binaryRollup struct {
	name      string
	arch      string
	installed string
	target    string
	uncertain bool
	findings  []findings.Finding
	// comparator orders fixed versions when several findings name one
	// binary: dpkg for Debian and Ubuntu, rpm for the RPM family.
	comparator string
}

type sourceRollup struct {
	source             string
	distribution       string
	release            string
	groupKey           string
	bins               map[string]*binaryRollup
	advisories         map[string]bool
	services           map[string]bool
	needsEntitlement   bool
	kernel             bool
	kernelNeedsInstall bool
}

func groupHostUpgrades(res *RunResult, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex, esmActive bool) []findings.RemediationGroup {
	bySource := map[string]*sourceRollup{}
	var order []string
	for _, f := range res.Findings {
		if f.State != findings.StateVulnerable || f.Scope != pkgs.ScopeHost || f.DetectionMethod == MethodMSRCFixedBuild {
			// Windows OS findings get their own cumulative-update card.
			continue
		}
		src := f.SourcePackage
		if src == "" {
			src = f.BinaryPackage
		}
		if src == "" {
			src = f.FindingID
		}
		key := src
		kernel := f.DetectionMethod == MethodUbuntuRunningKernel
		if !kernel && withoutFix(f) {
			// Upgrading closes nothing here (Debian open and postponed
			// issues): the finding stays in findings[] but gets no card.
			continue
		}
		if kernel {
			// Keep the running kernel off the userspace apt card for the same source.
			key = src + "|running-kernel"
		}
		roll, ok := bySource[key]
		if !ok {
			roll = &sourceRollup{
				source:       src,
				distribution: f.Distribution,
				release:      f.Release,
				groupKey:     key,
				bins:         map[string]*binaryRollup{},
				advisories:   map[string]bool{},
				services:     map[string]bool{},
				kernel:       kernel,
			}
			bySource[key] = roll
			order = append(order, key)
		}
		binName := f.BinaryPackage
		if binName == "" {
			binName = src
		}
		binKey := binName + "\x00" + f.Architecture + "\x00" + f.InstalledVersion
		bin := roll.bins[binKey]
		if bin == nil {
			bin = &binaryRollup{name: binName, arch: f.Architecture, installed: f.InstalledVersion, comparator: findingComparator(f)}
			roll.bins[binKey] = bin
		}
		bin.findings = append(bin.findings, f)
		bin.considerFixed(f.FixedVersion)
		for _, id := range f.AdvisoryIDs {
			if id = strings.TrimSpace(id); id != "" {
				roll.advisories[id] = true
			}
		}
		if f.FixAvailability == findings.FixRequiresESM && !esmActive {
			roll.needsEntitlement = true
		}
		if kernel && !f.FixedImageInstalled {
			roll.kernelNeedsInstall = true
		}
		if staleOrRunning(f, pkgIndex, runtimeIdx) {
			for _, unit := range serviceNames(f, pkgIndex, runtimeIdx) {
				roll.services[unit] = true
			}
		}
		if candidateRequiresEntitlement(pkgIndex, binName, f.InstalledVersion) && !esmActive {
			roll.needsEntitlement = true
		}
	}
	sort.Strings(order)
	var out []findings.RemediationGroup
	for _, src := range order {
		out = append(out, sourceCard(res.AssetID, bySource[src], pkgIndex, esmActive))
	}
	return out
}

func (b *binaryRollup) considerFixed(fixed string) {
	fixed = strings.TrimSpace(fixed)
	if fixed == "" || b.uncertain {
		return
	}
	if b.target == "" {
		b.target = fixed
		return
	}
	higher, ok := higherVersion(b.comparator, b.target, fixed)
	if !ok {
		b.uncertain = true
		b.target = ""
		return
	}
	b.target = higher
}

func sourceCard(asset string, roll *sourceRollup, pkgIndex *pkgs.Index, esmActive bool) findings.RemediationGroup {
	action := findings.ActionUpgradePackages
	var entitlement *string
	if roll.needsEntitlement && !esmActive {
		action = findings.ActionRequiresEntitlement
		v := "ubuntu_pro"
		entitlement = &v
	}
	binKeys := make([]string, 0, len(roll.bins))
	for key := range roll.bins {
		binKeys = append(binKeys, key)
	}
	sort.Strings(binKeys)
	hintNames := map[string]bool{}
	targets := make([]findings.RemediationTarget, 0, len(binKeys))
	avail := findings.AvailabilityAvailable
	sawBinary := false
	for _, key := range binKeys {
		bin := roll.bins[key]
		targetVersion := bin.target
		binAvail := findings.AvailabilityUnknown
		if bin.uncertain {
			targetVersion = ""
		} else {
			binAvail = binaryAvailability(pkgIndex, bin.name, bin.installed, bin.target)
		}
		targets = append(targets, findings.RemediationTarget{
			Name:             bin.name,
			Architecture:     bin.arch,
			InstalledVersion: bin.installed,
			TargetVersion:    targetVersion,
			Kind:             findings.TargetKindBinary,
		})
		hintNames[bin.name] = true
		sawBinary = true
		avail = combineAvailability(avail, binAvail)
	}
	if !sawBinary {
		avail = findings.AvailabilityUnknown
	}
	names := sortedKeys(hintNames)
	var findingIDs, cves []string
	seenCVE := map[string]bool{}
	for _, key := range binKeys {
		for _, f := range roll.bins[key].findings {
			findingIDs = append(findingIDs, f.FindingID)
			if f.CVEID != "" && !seenCVE[f.CVEID] {
				seenCVE[f.CVEID] = true
				cves = append(cves, f.CVEID)
			}
		}
	}
	sort.Strings(findingIDs)
	sort.Strings(cves)
	count := len(findingIDs)
	hint, hintNotes := upgradeHint(action, roll.distribution, roll.release, names)
	var coverage *string
	if roll.kernel && !roll.kernelNeedsInstall {
		hint = "reboot"
		hintNotes = nil
	} else if roll.kernel {
		hint, coverage = kernelInstallHint(roll)
		hintNotes = nil
	}
	key := roll.groupKey
	if key == "" {
		key = roll.source
	}
	return findings.RemediationGroup{
		GroupID:                remediationGroupID(asset, pkgs.ScopeHost, action, key),
		Scope:                  pkgs.ScopeHost,
		Action:                 action,
		Targets:                targets,
		SourcePackage:          roll.source,
		AdvisoryIDs:            sortedKeys(roll.advisories),
		Closes:                 closeSet(findingIDs, cves, &count),
		RequiresReboot:         roll.kernel,
		RequiresServiceRestart: sortedKeys(roll.services),
		RequiresEntitlement:    entitlement,
		Availability:           avail,
		CoverageNote:           hintCoverage(coverage, hintNotes),
		CommandHint:            hint,
		Notes:                  hintNotes,
	}
}

// kernelInstallHint names the new ABI image. Upgrading the running
// linux-image-<abi> package does not install the next kernel.
func kernelInstallHint(roll *sourceRollup) (string, *string) {
	var flavour, fixed string
	for _, bin := range roll.bins {
		if bin.target == "" {
			continue
		}
		if fixed == "" {
			fixed = bin.target
		} else if higher, ok := higherDpkg(fixed, bin.target); ok {
			fixed = higher
		}
		if abi, fl, ok := kernel.ParseImageName(bin.name); ok && abi != "" {
			flavour = fl
		}
	}
	pkg, ok := kernel.ImagePackageName(fixed, flavour)
	if !ok {
		note := "kernel_package_unknown"
		return "", &note
	}
	safe, dropped := sanitizeHintTokens([]string{pkg})
	if len(safe) == 0 {
		note := "kernel_package_unsafe_name"
		if len(dropped) > 0 {
			note = dropped[0]
		}
		return "", &note
	}
	return "apt-get install " + safe[0], nil
}

func restartCards(res *RunResult, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex) []findings.RemediationGroup {
	// Units already recorded on the upgrade card for a vulnerable finding
	// are not given a second card.
	covered := map[string]bool{}
	for _, f := range res.Findings {
		if f.State != findings.StateVulnerable || f.Scope != pkgs.ScopeHost || f.DetectionMethod == MethodMSRCFixedBuild {
			// Windows OS findings get their own cumulative-update card.
			continue
		}
		if !staleOrRunning(f, pkgIndex, runtimeIdx) {
			continue
		}
		for _, unit := range serviceNames(f, pkgIndex, runtimeIdx) {
			covered[unit] = true
		}
	}
	units := map[string]bool{}
	for _, f := range res.Findings {
		if f.State != findings.StateVulnerableRuntime || f.Scope != pkgs.ScopeHost {
			continue
		}
		for _, unit := range serviceNames(f, pkgIndex, runtimeIdx) {
			if !covered[unit] {
				units[unit] = true
			}
		}
	}
	for _, p := range hostPackages(pkgIndex) {
		if !p.RuntimeStale {
			continue
		}
		if packageHasVulnerableFinding(res, p.Name) {
			continue
		}
		for _, unit := range exposureUnits(runtimeIdx, p.Name, p.SourcePackage) {
			if !covered[unit] {
				units[unit] = true
			}
		}
	}
	names := sortedKeys(units)
	if len(names) == 0 {
		return nil
	}
	targets := make([]findings.RemediationTarget, 0, len(names))
	for _, name := range names {
		targets = append(targets, findings.RemediationTarget{Name: name, Kind: findings.TargetKindUnit})
	}
	zero := 0
	hint, notes := restartHint(names)
	return []findings.RemediationGroup{{
		GroupID:                remediationGroupID(res.AssetID, pkgs.ScopeHost, findings.ActionRestartService, strings.Join(names, ",")),
		Scope:                  pkgs.ScopeHost,
		Action:                 findings.ActionRestartService,
		Targets:                targets,
		AdvisoryIDs:            []string{},
		Closes:                 closeSet(nil, nil, &zero),
		RequiresServiceRestart: names,
		Availability:           findings.AvailabilityUnknown,
		CoverageNote:           hintCoverage(nil, notes),
		CommandHint:            hint,
		Notes:                  notes,
	}}
}

func restartHint(units []string) (string, []string) {
	safe, notes := sanitizeHintTokens(units)
	if len(safe) == 0 {
		return "", notes
	}
	return "systemctl restart " + strings.Join(safe, " "), notes
}

func rebootCard(asset string) findings.RemediationGroup {
	zero := 0
	return findings.RemediationGroup{
		GroupID:        remediationGroupID(asset, pkgs.ScopeHost, findings.ActionReboot, "host"),
		Scope:          pkgs.ScopeHost,
		Action:         findings.ActionReboot,
		Targets:        []findings.RemediationTarget{{Name: "host", Kind: findings.TargetKindUnit}},
		AdvisoryIDs:    []string{},
		Closes:         closeSet(nil, nil, &zero),
		RequiresReboot: true,
		Availability:   findings.AvailabilityUnknown,
		CommandHint:    "reboot",
	}
}

func closeSet(findingIDs, cves []string, count *int) findings.RemediationCloses {
	if findingIDs == nil {
		findingIDs = []string{}
	}
	if cves == nil {
		cves = []string{}
	}
	return findings.RemediationCloses{FindingIDs: findingIDs, CVEIDs: cves, Count: count}
}

func remediationGroupID(asset, scope, action, key string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{asset, scope, action, key}, "|")))
	return "group-" + hex.EncodeToString(sum[:8])
}

func sortRemediationGroups(groups []findings.RemediationGroup) {
	sort.Slice(groups, func(i, j int) bool {
		ci, cj := 0, 0
		if groups[i].Closes.Count != nil {
			ci = *groups[i].Closes.Count
		}
		if groups[j].Closes.Count != nil {
			cj = *groups[j].Closes.Count
		}
		if ci != cj {
			return ci > cj
		}
		if groups[i].SourcePackage != groups[j].SourcePackage {
			return groups[i].SourcePackage < groups[j].SourcePackage
		}
		if groups[i].Action != groups[j].Action {
			return groups[i].Action < groups[j].Action
		}
		return groups[i].GroupID < groups[j].GroupID
	})
}

// findingComparator is the version comparator a finding was decided with.
func findingComparator(f findings.Finding) string {
	if f.Comparison != nil && f.Comparison.Comparator != "" {
		return f.Comparison.Comparator
	}
	if f.Rule != nil && f.Rule.Comparator != "" {
		return f.Rule.Comparator
	}
	return "dpkg"
}

// higherVersion returns the higher of two fixed versions under the named
// comparator (dpkg ordering is not rpm ordering).
func higherVersion(comparator, current, next string) (string, bool) {
	if comparator == "" {
		comparator = "dpkg"
	}
	next = strings.TrimSpace(next)
	if next == "" {
		return current, current != ""
	}
	if current == "" {
		return next, true
	}
	cmp, err := version.ForEcosystem(comparator)
	if err != nil {
		return current, false
	}
	n, err := cmp.Compare(current, next)
	if err != nil {
		return current, false
	}
	if n >= 0 {
		return current, true
	}
	return next, true
}

func higherDpkg(current, next string) (string, bool) {
	return higherVersion("dpkg", current, next)
}

func binaryAvailability(pkgIndex *pkgs.Index, name, installed, target string) string {
	if target == "" {
		return findings.AvailabilityUnknown
	}
	matched := matchingHostPackages(pkgIndex, name, installed)
	cmp, err := version.ForEcosystem("dpkg")
	if err != nil {
		return findings.AvailabilityUnknown
	}
	saw := false
	behind := false
	for _, p := range matched {
		if strings.TrimSpace(p.HighestListVersion) == "" {
			continue
		}
		saw = true
		n, err := cmp.Compare(p.HighestListVersion, target)
		if err != nil {
			return findings.AvailabilityUnknown
		}
		if n < 0 {
			behind = true
		}
	}
	if !saw {
		return findings.AvailabilityUnknown
	}
	if behind {
		return findings.AvailabilityNotYetInRepo
	}
	return findings.AvailabilityAvailable
}

func combineAvailability(current, next string) string {
	if current == findings.AvailabilityNotYetInRepo || next == findings.AvailabilityNotYetInRepo {
		return findings.AvailabilityNotYetInRepo
	}
	if current == findings.AvailabilityUnknown || next == findings.AvailabilityUnknown {
		return findings.AvailabilityUnknown
	}
	return findings.AvailabilityAvailable
}

func candidateRequiresEntitlement(pkgIndex *pkgs.Index, name, installed string) bool {
	for _, p := range matchingHostPackages(pkgIndex, name, installed) {
		if listOriginIsESM(p.HighestListOrigin) {
			return true
		}
	}
	return false
}

func listOriginIsESM(o *evidence.ListOriginObservation) bool {
	if o == nil {
		return false
	}
	if o.ESM {
		return true
	}
	return originIsESM(o.Origin) || originIsESM(o.URL) || originIsESM(o.Suite)
}

func originIsESM(origin string) bool {
	o := strings.ToLower(strings.TrimSpace(origin))
	switch {
	case strings.HasPrefix(o, "ubuntuesm"):
		return true
	case strings.Contains(o, "esm.ubuntu.com"):
		return true
	case strings.HasPrefix(o, "esm."): // esm.ubuntu.com host fragment without scheme
		return true
	default:
		return false
	}
}

func matchingHostPackages(pkgIndex *pkgs.Index, name, installed string) []*pkgs.InstalledPackage {
	all := hostPackagesNamed(pkgIndex, name)
	if installed == "" || len(all) == 0 {
		return all
	}
	var matched []*pkgs.InstalledPackage
	for _, p := range all {
		if p.RawVersion == installed {
			matched = append(matched, p)
		}
	}
	if len(matched) == 0 {
		return all
	}
	return matched
}

func hostPackagesNamed(pkgIndex *pkgs.Index, name string) []*pkgs.InstalledPackage {
	if pkgIndex == nil || pkgIndex.ByName == nil {
		return nil
	}
	return pkgIndex.ByName[pkgs.HostScopeKey()][name]
}

func hostPackages(pkgIndex *pkgs.Index) []*pkgs.InstalledPackage {
	if pkgIndex == nil {
		return nil
	}
	var out []*pkgs.InstalledPackage
	for _, p := range pkgIndex.All {
		if p.Scope == pkgs.ScopeHost {
			out = append(out, p)
		}
	}
	return out
}

func packageHasVulnerableFinding(res *RunResult, name string) bool {
	for _, f := range res.Findings {
		if f.State == findings.StateVulnerable && f.Scope == pkgs.ScopeHost && f.BinaryPackage == name {
			return true
		}
	}
	return false
}

func staleOrRunning(f findings.Finding, pkgIndex *pkgs.Index, _ *runtime.RuntimeIndex) bool {
	if f.RuntimeState == findings.RuntimeRunning {
		return true
	}
	return packageRuntimeStale(pkgIndex, f.BinaryPackage, f.InstalledVersion)
}

func packageRuntimeStale(pkgIndex *pkgs.Index, name, installed string) bool {
	for _, p := range matchingHostPackages(pkgIndex, name, installed) {
		if p.RuntimeStale {
			return true
		}
	}
	return false
}

func serviceNames(f findings.Finding, pkgIndex *pkgs.Index, runtimeIdx *runtime.RuntimeIndex) []string {
	if len(f.RuntimeServices) > 0 {
		return append([]string(nil), f.RuntimeServices...)
	}
	return exposureUnits(runtimeIdx, f.BinaryPackage, f.SourcePackage)
}

func exposureUnits(runtimeIdx *runtime.RuntimeIndex, name, source string) []string {
	if runtimeIdx == nil {
		return nil
	}
	exp := runtimeIdx.ExposureFor(name, source)
	if len(exp.Services) == 0 {
		return nil
	}
	return append([]string(nil), exp.Services...)
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// upgradeHint is the package manager command that installs the fixed
// versions on the asset's own distribution and release (Amazon Linux 2
// ships yum, Amazon Linux 2023 dnf).
func upgradeHint(action, distribution, release string, bins []string) (string, []string) {
	safe, notes := sanitizeHintTokens(bins)
	if len(safe) == 0 {
		return "", notes
	}
	var hint string
	switch distribution {
	case "rocky", "almalinux", "rhel":
		hint = "dnf upgrade " + strings.Join(safe, " ")
	case "amazon":
		if release == "2" {
			hint = "yum update " + strings.Join(safe, " ")
		} else {
			// Amazon Linux 2023 locks its repositories to the installed
			// release version; fixes from the latest updateinfo need the
			// latest release repositories.
			hint = "dnf upgrade --releasever=latest " + strings.Join(safe, " ")
		}
	case "alpine":
		hint = "apk upgrade " + strings.Join(safe, " ")
	case "opensuse":
		hint = "zypper update " + strings.Join(safe, " ")
	default:
		hint = "apt-get install --only-upgrade " + strings.Join(safe, " ")
	}
	if action == findings.ActionRequiresEntitlement {
		hint += " # requires Ubuntu Pro"
	}
	return hint, notes
}

// remediationInvariant reports whether every host vulnerable finding sits in
// exactly one card and the sum of closes.count equals that population.
// withoutFix is a finding the vendor has not fixed yet (open, postponed):
// there is nothing to install, so it is on no card.
func withoutFix(f findings.Finding) bool {
	return f.FixAvailability == findings.FixUnavailable || f.FixAvailability == findings.FixDeferred
}

func remediationInvariant(res *RunResult) (groups, closes int, ok bool) {
	seen := map[string]int{}
	sum := 0
	for _, g := range res.RemediationGroups {
		n := 0
		if g.Closes.Count != nil {
			n = *g.Closes.Count
		}
		if n != len(g.Closes.FindingIDs) {
			return len(res.RemediationGroups), sum, false
		}
		sum += n
		for _, id := range g.Closes.FindingIDs {
			seen[id]++
			if seen[id] != 1 {
				return len(res.RemediationGroups), sum, false
			}
		}
	}
	hostVuln := 0
	for _, f := range res.Findings {
		if f.State != findings.StateVulnerable || f.Scope != pkgs.ScopeHost ||
			(f.DetectionMethod != MethodUbuntuRunningKernel && withoutFix(f)) {
			continue
		}
		hostVuln++
		if seen[f.FindingID] != 1 {
			return len(res.RemediationGroups), sum, false
		}
	}
	return len(res.RemediationGroups), sum, sum == hostVuln && len(seen) == hostVuln
}
