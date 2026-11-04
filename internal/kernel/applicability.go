package kernel

import (
	"regexp"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// versionTrackRe extracts the upstream kernel track prefix from a dpkg kernel
// package version, e.g. "6.8.0-106.106~22.04.1" -> "6.8.0".
var versionTrackRe = regexp.MustCompile(`^(\d+\.\d+\.\d+)-`)

// VersionTrack returns the kernel upstream track (major.minor.patch) from a
// dpkg-comparable kernel package version, or "" when it cannot be parsed.
func VersionTrack(pkgVersion string) string {
	m := versionTrackRe.FindStringSubmatch(pkgVersion)
	if m == nil {
		return ""
	}
	return m[1]
}

// RuleApplicable reports whether a normalized kernel rule may be evaluated
// against the running kernel context. Selection happens before version
// comparison: release/source/track/flavour family must match exactly.
func RuleApplicable(kctx *Context, r *rules.PackageVulnerabilityRule) bool {
	if kctx == nil || r == nil || !r.IsKernel {
		return false
	}
	if kctx.SourceFamily == "" || kctx.PackageVersion == "" {
		return false
	}
	if r.SourcePackage != kctx.SourceFamily {
		return false
	}
	if r.FixedVersion == "" {
		return true
	}
	instTrack := VersionTrack(kctx.PackageVersion)
	fixTrack := VersionTrack(r.FixedVersion)
	if instTrack != "" && fixTrack != "" && instTrack != fixTrack {
		return false
	}
	return true
}
