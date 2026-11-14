package pkgs

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// originsJSON names, per distribution, the origin facts that identify the
// distribution's own packages. It is data so a new distribution or vendor
// string needs no code change.
//
//go:embed origins.json
var originsJSON []byte

// distributionOrigins are the origin facts of one distribution's own archives.
type distributionOrigins struct {
	// AptOrigins are apt Release Origin values (including Ubuntu Pro/ESM).
	AptOrigins []string `json:"apt_origins"`
	// RPMVendors are rpm Vendor tag values.
	RPMVendors []string `json:"rpm_vendors"`
}

var knownOrigins = func() map[string]distributionOrigins {
	m := map[string]distributionOrigins{}
	if err := json.Unmarshal(originsJSON, &m); err != nil {
		panic("pkgs: origins.json: " + err.Error())
	}
	return m
}()

func hasFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// Provenance classifies where the installed package came from, relative to
// the asset's distribution vendor (T04: vendor and support applicability):
// vendor (the distribution's own build), third_party or unknown.
//
// It returns "" when there is no origin evidence to classify, because
// missing evidence must not be treated as a negative signal. Only an
// affirmative fact makes a package third_party; everything else that carries
// some evidence is unknown.
func (p InstalledPackage) Provenance(distributionID string) string {
	switch p.Ecosystem {
	case "rpm":
		return p.rpmProvenance(distributionID)
	case "apk":
		// apk records carry only a maintainer, which does not tell an Alpine
		// package from a third-party one.
		return ""
	}
	return p.dpkgProvenance(distributionID)
}

// dpkgProvenance goes by the apt list the installed version was matched to.
// The Maintainer field is not used: packages synced from Debian keep their
// Debian maintainer and rebuilt packages keep the distribution's.
func (p InstalledPackage) dpkgProvenance(distributionID string) string {
	if p.RepositoryMetadataStatus == "" && p.RepositoryOrigin == "" {
		return ""
	}
	if p.RepositoryOrigin == "" || p.RepositoryMetadataStatus == "not_in_apt_lists" {
		return ProvenanceUnknown
	}
	if hasFold(knownOrigins[distributionID].AptOrigins, p.RepositoryOrigin) {
		return ProvenanceVendor
	}
	return ProvenanceThirdParty
}

// rpmProvenance goes by the rpm Vendor tag. Vendor repositories often leave
// it empty; a signed package without a vendor is then third party, because
// every package of the distributions in origins.json carries the vendor tag.
func (p InstalledPackage) rpmProvenance(distributionID string) string {
	if p.Origin == nil {
		return ""
	}
	vendors := knownOrigins[distributionID].RPMVendors
	if len(vendors) == 0 {
		// A distribution whose vendor string is not on record: nothing can be
		// said about any of its packages.
		return ProvenanceUnknown
	}
	switch {
	case p.Origin.Vendor != "":
		if hasFold(vendors, p.Origin.Vendor) {
			return ProvenanceVendor
		}
		return ProvenanceThirdParty
	case p.Origin.SigningKeyID != "":
		return ProvenanceThirdParty
	}
	return ProvenanceUnknown
}

// OriginName is the best name of where the package came from, for messages.
func (p InstalledPackage) OriginName() string {
	if p.RepositoryOrigin != "" {
		return p.RepositoryOrigin
	}
	if p.Origin != nil {
		if p.Origin.Vendor != "" {
			return p.Origin.Vendor
		}
		return p.Origin.Maintainer
	}
	return ""
}
