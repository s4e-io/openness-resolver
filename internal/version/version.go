// Package version defines the ecosystem-specific version comparison
// contract. Generic SemVer is deliberately not offered for OS packages:
// dpkg, rpm and apk each get a native comparator implementation.
package version

import "fmt"

// VersionComparator compares an installed version against a fixed version
// using ecosystem-native semantics.
//
// Compare returns:
//
//	-1 installed <  fixed
//	 0 installed == fixed
//	 1 installed >  fixed
type VersionComparator interface {
	// Ecosystem is the comparator id ("dpkg", "apk", ...).
	Ecosystem() string
	Compare(installed string, fixed string) (int, error)
}

var registry = map[string]VersionComparator{}

// Register adds a comparator to the global registry (called from init()).
func Register(c VersionComparator) {
	registry[c.Ecosystem()] = c
}

// ForEcosystem returns the comparator registered for an ecosystem.
func ForEcosystem(eco string) (VersionComparator, error) {
	c, ok := registry[eco]
	if !ok {
		return nil, fmt.Errorf("no native version comparator registered for ecosystem %q", eco)
	}
	return c, nil
}

// Ecosystems lists registered comparator ids.
func Ecosystems() []string {
	var out []string
	for k := range registry {
		out = append(out, k)
	}
	return out
}
