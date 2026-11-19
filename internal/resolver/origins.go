package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// GapThirdPartyPackages: host packages that do not come from the
// distribution. Distribution advisories describe the distribution's own
// builds only, so these packages have no rule that speaks for them. The rest
// of the asset is evaluated.
const GapThirdPartyPackages = "third_party_packages"

// ThirdPartyNotEvaluated is the status of a third-party package no
// application rule covers.
const ThirdPartyNotEvaluated = "not_evaluated"

// PackageOrigins splits the host packages by where they came from, so a
// consumer can see how much of the host the distribution advisories speak
// for. Counts use the provenance values of findings: vendor (the
// distribution's own build), third_party, unknown; not_classified packages
// carry no origin evidence at all.
type PackageOrigins struct {
	Vendor        int `json:"vendor"`
	ThirdParty    int `json:"third_party"`
	Unknown       int `json:"unknown"`
	NotClassified int `json:"not_classified"`
	// ThirdPartyPackages lists the third-party packages. Empty list, never null.
	ThirdPartyPackages []ThirdPartyPackage `json:"third_party_packages"`
}

// ThirdPartyPackage is one host package from outside the distribution.
type ThirdPartyPackage struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Architecture string `json:"architecture,omitempty"`
	// Version is the upstream part of the version, RawVersion the exact string.
	Version    string `json:"version,omitempty"`
	RawVersion string `json:"raw_version"`
	// Origin names where it came from: the repository's name for itself, else
	// the package vendor or maintainer.
	Origin        string `json:"origin,omitempty"`
	RepositoryURL string `json:"repository_url,omitempty"`
	SigningKeyID  string `json:"signing_key_id,omitempty"`
	EntityID      string `json:"entity_id,omitempty"`
	// Status is not_evaluated until an application rule covers the package.
	Status string `json:"status"`
}

// buildPackageOrigins classifies every installed host package.
func buildPackageOrigins(idx *pkgs.Index, distributionID string) *PackageOrigins {
	out := &PackageOrigins{ThirdPartyPackages: []ThirdPartyPackage{}}
	for _, p := range idx.All {
		if p.Scope != pkgs.ScopeHost {
			continue
		}
		switch p.Provenance(distributionID) {
		case pkgs.ProvenanceVendor:
			out.Vendor++
		case pkgs.ProvenanceUnknown:
			out.Unknown++
		case pkgs.ProvenanceThirdParty:
			out.ThirdParty++
			tp := ThirdPartyPackage{
				Name: p.Name, Ecosystem: p.Ecosystem, Architecture: p.Architecture,
				Version: p.Version, RawVersion: p.RawVersion,
				Origin: p.OriginName(), RepositoryURL: p.RepositoryURL,
				EntityID: p.EntityID, Status: ThirdPartyNotEvaluated,
			}
			if p.Origin != nil {
				tp.SigningKeyID = p.Origin.SigningKeyID
				if tp.RepositoryURL == "" {
					tp.RepositoryURL = p.Origin.RepositoryURL
				}
			}
			out.ThirdPartyPackages = append(out.ThirdPartyPackages, tp)
		default:
			out.NotClassified++
		}
	}
	sort.SliceStable(out.ThirdPartyPackages, func(i, j int) bool {
		a, b := out.ThirdPartyPackages[i], out.ThirdPartyPackages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Architecture < b.Architecture
	})
	return out
}

// notEvaluated returns the third-party packages no rule covers.
func (o *PackageOrigins) notEvaluated() []ThirdPartyPackage {
	if o == nil {
		return nil
	}
	var out []ThirdPartyPackage
	for _, p := range o.ThirdPartyPackages {
		if p.Status == ThirdPartyNotEvaluated {
			out = append(out, p)
		}
	}
	return out
}

// thirdPartyGap is the coverage gap for third-party packages that were not
// evaluated, or nil when there are none.
func thirdPartyGap(o *PackageOrigins, release string) []CoverageGap {
	list := o.notEvaluated()
	if len(list) == 0 {
		return nil
	}
	const show = 5
	names := make([]string, 0, show)
	for _, p := range list {
		if len(names) == show {
			break
		}
		names = append(names, p.Name)
	}
	detail := strings.Join(names, ", ")
	if len(list) > show {
		detail += fmt.Sprintf(" and %d more", len(list)-show)
	}
	return []CoverageGap{{Release: release, Kind: GapThirdPartyPackages, Count: len(list), Detail: detail}}
}

// thirdPartyUnknowns lists each third-party package that was not evaluated.
func thirdPartyUnknowns(o *PackageOrigins) []Unknown {
	var out []Unknown
	for _, p := range o.notEvaluated() {
		reason := "third_party_package"
		if p.Origin != "" {
			reason += ": origin " + p.Origin
		}
		out = append(out, Unknown{Kind: "package", Subject: p.Name + " " + p.RawVersion, Reason: reason, EntityID: p.EntityID})
	}
	return out
}
