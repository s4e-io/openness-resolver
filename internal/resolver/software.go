package resolver

import (
	"sort"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// Software resolution statuses. The resolver has no vendor feed for
// catalog-detected products yet, so an instance is passed through with an
// explicit reason instead of a verdict, unless its files belong to a
// distribution package that the distribution advisories already judged.
const (
	// SoftwareCoveredByPackage: the instance is the content of a distribution
	// package, and that package was evaluated. It is not an unknown.
	SoftwareCoveredByPackage  = "covered_by_package"
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
	// OwnerPackage is the package owning the instance's files and
	// OwnerPackageStatus what the collector found (owned | not_owned |
	// not_checked); both omitted on evidence older than schema 1.7.0.
	OwnerPackage       *evidence.OwnerPackage `json:"owner_package,omitempty"`
	OwnerPackageStatus string                 `json:"owner_package_status,omitempty"`
	Resolution         SoftwareResolution     `json:"resolution"`
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
// hostEvaluated says whether the host packages were compared with
// distribution rules; only then can an owning package cover an instance.
func buildSoftwareInventory(recs []evidence.TypedRecord[evidence.SoftwareInstanceValue], idx *pkgs.Index, distributionID string, hostEvaluated bool) []SoftwareInstanceResult {
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

			OwnerPackage:       v.OwnerPackage,
			OwnerPackageStatus: v.OwnerPackageStatus,
		}
		if reason, covered := ownerStance(v, idx, distributionID, hostEvaluated); covered {
			res.Resolution = SoftwareResolution{Status: SoftwareCoveredByPackage, Reasons: []string{reason}}
			out = append(out, res)
			continue
		} else if reason != "" {
			res.Resolution.Reasons = append(res.Resolution.Reasons, reason)
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

// ownerStance reads the owner facts of an instance. covered is true only
// when the files belong to an installed package of the distribution itself
// and the host packages were evaluated; otherwise reason, when set, says
// what the owner facts show.
func ownerStance(v evidence.SoftwareInstanceValue, idx *pkgs.Index, distributionID string, hostEvaluated bool) (reason string, covered bool) {
	switch v.OwnerPackageStatus {
	case "not_owned":
		return "no installed package owns this install", false
	case "owned":
	default:
		return "", false
	}
	o := v.OwnerPackage
	if o == nil || o.Name == "" {
		return "", false
	}
	var p *pkgs.InstalledPackage
	if idx != nil {
		if p = idx.ByEntityID[o.EntityID]; p == nil {
			p = idx.LookupHost(o.Name)
		}
	}
	if p == nil {
		return "owned by package " + o.Name + ", which is not in the package inventory", false
	}
	switch p.Provenance(distributionID) {
	case pkgs.ProvenanceVendor:
		if !hostEvaluated {
			return "owned by distribution package " + p.Name + ", but the host packages were not evaluated", false
		}
		return "installed by distribution package " + p.Name + " " + p.RawVersion + ", which the distribution advisories cover", true
	case pkgs.ProvenanceThirdParty:
		return "owned by third-party package " + p.Name + " (origin " + p.OriginName() + ")", false
	}
	return "owned by package " + p.Name + ", whose origin could not be established", false
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
		reason := g.Kind
		if g.Kind == GapContainerNotCovered {
			reason += ": " + g.Detail
		}
		out = append(out, Unknown{Kind: "rule_coverage", Subject: g.Release, Reason: reason})
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
	out = append(out, thirdPartyUnknowns(res.PackageOrigins)...)
	for _, s := range res.SoftwareInventory {
		if s.Resolution.Status == SoftwareCoveredByPackage {
			continue
		}
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
