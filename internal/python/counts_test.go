package python

import "testing"

func TestPyPINamesRejectsUnsafeEvidenceNames(t *testing.T) {
	inv := &Inventory{Distributions: []Distribution{
		{ResolverEcosystem: EcosystemPyPI, NameNormalized: "requests"},
		{ResolverEcosystem: EcosystemPyPI, NameNormalized: "../escape"},
		{ResolverEcosystem: EcosystemPyPI, NameNormalized: `..\\escape`},
		{ResolverEcosystem: EcosystemPyPI, NameNormalized: "nested/name"},
		{ResolverEcosystem: EcosystemPyPI, NameNormalized: ""},
	}}
	names := PyPINames(inv)
	if len(names) != 1 || names[0] != "requests" {
		t.Fatalf("PyPINames() = %q", names)
	}
}
