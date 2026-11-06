package python

import (
	"regexp"
	"sort"
)

// A distribution name from evidence is untrusted. Keep only valid PyPI names
// before sending them to OSV or using them in the local raw-feed cache.
var pypiName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$`)

func ValidPyPIName(name string) bool { return pypiName.MatchString(name) }

// PyPINames returns distinct normalized PyPI distribution names.
func PyPINames(inv *Inventory) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range inv.Distributions {
		if d.ResolverEcosystem != EcosystemPyPI || !ValidPyPIName(d.NameNormalized) {
			continue
		}
		if !seen[d.NameNormalized] {
			seen[d.NameNormalized] = true
			out = append(out, d.NameNormalized)
		}
	}
	sort.Strings(out)
	return out
}

// Counts returns inventory summary counts.
func (inv *Inventory) Counts() (total, ubuntuDPKG, pypi, confirmed, notLoaded, envs, procs int) {
	envSet := map[string]bool{}
	for _, d := range inv.Distributions {
		total++
		switch d.ResolverEcosystem {
		case EcosystemUbuntuDPKG:
			ubuntuDPKG++
		case EcosystemPyPI:
			pypi++
		}
		switch d.RuntimeLoadStatus {
		case "confirmed_loaded":
			confirmed++
		case "installed_not_proven_loaded":
			notLoaded++
		}
		if d.EnvironmentID != "" {
			envSet[d.EnvironmentID] = true
		}
	}
	return total, ubuntuDPKG, pypi, confirmed, notLoaded, len(envSet), inv.Processes
}
