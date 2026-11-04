package resolver

import (
	"sort"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
)

// Software resolution statuses. The resolver has no vendor feed for
// catalog-detected products yet, so every instance is passed through with
// an explicit reason instead of a verdict.
const (
	SoftwareNoRules           = "no_rules_for_product"
	SoftwareVersionUnreadable = "version_unreadable"
	SoftwareCatalogUnverified = "catalog_entry_unverified"
)

// SoftwareInstanceResult is one collector software_instance carried into the
// output with the resolver's stance on it. Consumers render it as "seen, not
// evaluated" until a product feed exists.
type SoftwareInstanceResult struct {
	EntityID        string               `json:"entity_id"`
	EvidenceID      string               `json:"evidence_id"`
	ProductKey      string               `json:"product_key"`
	Vendor          string               `json:"vendor"`
	Product         string               `json:"product"`
	CPEPrefix       string               `json:"cpe_prefix,omitempty"`
	Scope           string               `json:"scope"`
	InstallPath     string               `json:"install_path,omitempty"`
	Version         string               `json:"version,omitempty"`
	VersionSource   *evidence.VersionHit `json:"version_source,omitempty"`
	PatchIDs        []string             `json:"patch_ids"`
	Running         bool                 `json:"running"`
	Ports           []int                `json:"ports"`
	Confidence      string               `json:"confidence"`
	CatalogVerified bool                 `json:"catalog_verified"`
	Resolution      SoftwareResolution   `json:"resolution"`
}

// SoftwareResolution says what the resolver did with the instance.
type SoftwareResolution struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// Unknown is one thing the resolver could not judge. The list exists so a
// consumer never has to infer "not evaluated" from missing findings.
type Unknown struct {
	Kind      string `json:"kind"`    // platform | rule_coverage | finding | software | comparator
	Subject   string `json:"subject"` // release, package, product, finding id
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id,omitempty"`
	EntityID  string `json:"entity_id,omitempty"`
}

// buildSoftwareInventory passes collector software instances through with a
// resolution status. Order is deterministic (product_key, install_path).
func buildSoftwareInventory(recs []evidence.TypedRecord[evidence.SoftwareInstanceValue]) []SoftwareInstanceResult {
	out := make([]SoftwareInstanceResult, 0, len(recs))
	for _, r := range recs {
		v := r.Value
		res := SoftwareInstanceResult{
			EntityID:        v.EntityID,
			EvidenceID:      r.EvidenceID,
			ProductKey:      v.ProductKey,
			Vendor:          v.Vendor,
			Product:         v.Product,
			CPEPrefix:       v.CPEPrefix,
			Scope:           v.Scope,
			InstallPath:     v.InstallPath,
			Version:         v.Version,
			VersionSource:   v.VersionSource,
			PatchIDs:        nonNilStrings(v.PatchIDs),
			Running:         v.Running,
			Ports:           nonNilInts(v.Signals.Ports),
			Confidence:      v.Confidence,
			CatalogVerified: v.CatalogVerified,
			Resolution:      SoftwareResolution{Status: SoftwareNoRules, Reasons: []string{}},
		}
		if v.Version == "" || v.Gap != "" {
			res.Resolution.Status = SoftwareVersionUnreadable
			res.Resolution.Reasons = append(res.Resolution.Reasons, "collector read no version for this install")
		}
		if !v.CatalogVerified {
			res.Resolution.Reasons = append(res.Resolution.Reasons, SoftwareCatalogUnverified)
		}
		if res.Resolution.Status == SoftwareNoRules {
			res.Resolution.Reasons = append(res.Resolution.Reasons, "no vendor feed is wired for "+v.ProductKey+" yet")
		}
		out = append(out, res)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ProductKey != out[j].ProductKey {
			return out[i].ProductKey < out[j].ProductKey
		}
		return out[i].InstallPath < out[j].InstallPath
	})
	return out
}

// buildUnknowns collects everything that was seen but not judged.
func buildUnknowns(res *RunResult) []Unknown {
	var out []Unknown
	if res.PlatformSupport != "supported" {
		out = append(out, Unknown{Kind: "platform", Subject: res.Platform.DistributionID + " " + res.Platform.DistributionVersion, Reason: res.SupportReason})
	}
	if res.RuleCoverage.State == CoverageMissing {
		out = append(out, Unknown{Kind: "rule_coverage", Subject: res.RuleCoverage.AssetRelease, Reason: res.RuleCoverage.Reason})
	}
	for _, g := range res.RuleCoverage.Gaps {
		out = append(out, Unknown{Kind: "rule_coverage", Subject: g.Release, Reason: g.Kind})
	}
	for _, f := range res.Findings {
		switch f.State {
		case findings.StateUnknown, findings.StateConflictingEvidence, findings.StatePotentiallyVulnerable:
			subject := f.BinaryPackage
			if f.CVEID != "" {
				subject += " " + f.CVEID
			}
			out = append(out, Unknown{Kind: "finding", Subject: subject, Reason: f.State, FindingID: f.FindingID})
		}
	}
	for _, s := range res.SoftwareInventory {
		out = append(out, Unknown{Kind: "software", Subject: s.ProductKey + " " + s.Version, Reason: s.Resolution.Status, EntityID: s.EntityID})
	}
	if res.Metrics.ComparatorErrors > 0 {
		out = append(out, Unknown{Kind: "comparator", Subject: "version comparison", Reason: "comparator errors occurred; see findings with state unknown"})
	}
	if out == nil {
		out = []Unknown{}
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilInts(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}
