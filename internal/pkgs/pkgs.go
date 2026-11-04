// Package pkgs implements Tasks 2 and 3 of the resolver backlog:
// exact binary package identity and binary -> source package mapping.
//
// Invariants:
//   - RawVersion is preserved byte-for-byte; distro versions are never
//     converted to semantic versions and epochs/suffixes are never stripped.
//   - Host and container packages are separate scopes and are never merged.
//   - Package identity always includes scope, ecosystem, name, architecture
//     and the exact raw version.
package pkgs

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/platform"
)

// Scope values.
const (
	ScopeHost      = "host"
	ScopeContainer = "container"
)

// InstalledPackage is the canonical package model.
type InstalledPackage struct {
	Scope               string `json:"scope"`     // host | container
	ScopeID             string `json:"scope_id"`  // "" for host, image digest for containers
	Ecosystem           string `json:"ecosystem"` // dpkg | rpm | apk
	Name                string `json:"name"`
	SourcePackage       string `json:"source_package"`
	Epoch               string `json:"epoch"`
	Version             string `json:"version"`
	Release             string `json:"release"`
	RawVersion          string `json:"raw_version"`
	Architecture        string `json:"architecture"`
	RepositoryOrigin    string `json:"repository_origin"`
	RepositorySuite     string `json:"repository_suite"`
	RepositoryComponent string `json:"repository_component"`
	RepositoryURL       string `json:"repository_url,omitempty"`
	// RepositoryMetadataStatus is the collector's apt-lists correlation
	// result (e.g. matched_apt_lists, not_in_apt_lists).
	RepositoryMetadataStatus string `json:"repository_metadata_status,omitempty"`

	// EvidenceID links back to the .openness record that produced this package.
	EvidenceID string `json:"evidence_id"`
	// EntityID is the collector-side entity id (e.g. pkg:dpkg:openssl:...).
	EntityID string `json:"entity_id"`
	// PackageStatus is the raw dpkg/rpm status string.
	PackageStatus string `json:"package_status,omitempty"`
	// HighestListVersion / HighestListOrigin come from the collector apt-lists
	// parse (not apt pin candidate). Empty version means unknown availability.
	HighestListVersion string                          `json:"highest_list_version,omitempty"`
	HighestListOrigin  *evidence.ListOriginObservation `json:"highest_list_origin,omitempty"`
	RuntimeStale       bool                            `json:"runtime_stale,omitempty"`

	Source SourceRelationship `json:"source_relationship"`
}

// SourceRelationship is the Task 3 model: binary -> source package link.
type SourceRelationship struct {
	BinaryPackage  string `json:"binary_package"`
	SourcePackage  string `json:"source_package"`
	SourceVersion  string `json:"source_version,omitempty"`
	Confidence     string `json:"confidence"`      // direct | inferred | ""
	EvidenceSource string `json:"evidence_source"` // e.g. dpkg:Source, binary_name_fallback
}

// Provenance classifications (T04). "unknown" is never collapsed into
// "local": a package that could not be matched to apt lists may still be a
// vendor package from a removed/stale repository.
const (
	ProvenanceVendor     = "vendor"
	ProvenanceThirdParty = "third_party"
	ProvenanceUnknown    = "unknown"
)

// vendorOrigins maps a distribution ID to apt Origin values that identify
// the distribution vendor's own archives (including Ubuntu Pro/ESM).
var vendorOrigins = map[string][]string{
	"ubuntu": {"Ubuntu", "UbuntuESM", "UbuntuESMApps"},
	"debian": {"Debian", "Debian Backports"},
}

// Provenance classifies where the installed package came from, relative to
// the asset's distribution vendor (T04: vendor and support applicability).
// It returns "" when the collector gathered no repository evidence at all,
// because missing evidence must not be treated as a negative signal.
func (p InstalledPackage) Provenance(distributionID string) string {
	if p.RepositoryMetadataStatus == "" && p.RepositoryOrigin == "" {
		return ""
	}
	if p.RepositoryOrigin == "" || p.RepositoryMetadataStatus == "not_in_apt_lists" {
		return ProvenanceUnknown
	}
	for _, o := range vendorOrigins[distributionID] {
		if strings.EqualFold(p.RepositoryOrigin, o) {
			return ProvenanceVendor
		}
	}
	return ProvenanceThirdParty
}

// IdentityKey is the canonical package identity:
// scope + ecosystem + name + architecture + exact raw version.
func (p InstalledPackage) IdentityKey() string {
	return strings.Join([]string{p.Scope, p.ScopeID, p.Ecosystem, p.Name, platform.NormalizeArchitecture(p.Architecture), p.RawVersion}, "|")
}

// Installed reports whether the package is actually installed (dpkg keeps
// removed-but-configured entries in the status database).
func (p InstalledPackage) Installed() bool {
	if p.PackageStatus == "" {
		return true
	}
	return strings.Contains(p.PackageStatus, "installed") && !strings.Contains(p.PackageStatus, "not-installed")
}

// FromHostRecord converts a typed .openness packages record.
func FromHostRecord(rec evidence.TypedRecord[evidence.PackageValue]) (InstalledPackage, error) {
	v := rec.Value
	if v.Name == "" {
		return InstalledPackage{}, fmt.Errorf("package record %s has no name", rec.EvidenceID)
	}
	if v.RawVersionString == "" {
		return InstalledPackage{}, fmt.Errorf("package %q (%s) has no raw_version_string", v.Name, rec.EvidenceID)
	}
	p := InstalledPackage{
		Scope:                    ScopeHost,
		Ecosystem:                normalizeEcosystem(v.PackageManager),
		Name:                     v.Name,
		Epoch:                    deref(v.Epoch),
		Version:                  v.Version,
		Release:                  v.Release,
		RawVersion:               v.RawVersionString,
		Architecture:             v.Architecture,
		RepositoryOrigin:         v.RepositoryOrigin,
		RepositorySuite:          v.RepositorySuite,
		RepositoryComponent:      v.RepositoryComponent,
		RepositoryURL:            v.RepositoryURL,
		RepositoryMetadataStatus: v.RepositoryMetadataStatus,
		EvidenceID:               rec.EvidenceID,
		EntityID:                 v.EntityID,
		PackageStatus:            v.PackageStatus,
		HighestListVersion:       v.HighestListVersion,
		HighestListOrigin:        v.HighestListOrigin,
		RuntimeStale:             v.RuntimeStale,
	}
	p.Source = sourceRelationship(v)
	p.SourcePackage = p.Source.SourcePackage
	return p, nil
}

// sourceRelationship implements Task 3. Native package metadata (dpkg Source
// field) yields confidence "direct"; falling back to the binary name yields
// "inferred". The distinction is never hidden.
func sourceRelationship(v evidence.PackageValue) SourceRelationship {
	rel := SourceRelationship{BinaryPackage: v.Name}

	// Prefer the relationship emitted by the collector because it carries an
	// explicit evidence source.
	for _, r := range v.Relationships {
		if r.Type != "package_built_from_source_package" {
			continue
		}
		rel.SourcePackage = entityIDName(r.TargetEntityID)
		rel.Confidence = normalizeConfidence(r.Confidence)
		rel.EvidenceSource = r.EvidenceSource
		break
	}

	// The source_package field is authoritative when present.
	if v.SourcePackage != "" {
		if rel.SourcePackage == "" {
			rel.SourcePackage = v.SourcePackage
		}
		// "dpkg Source field present" beats a fallback relationship record.
		if rel.EvidenceSource == "" || rel.EvidenceSource == "binary_name_fallback" {
			if v.SourcePackage != v.Name {
				// A differing name can only come from real package metadata.
				rel.Confidence = "direct"
				rel.EvidenceSource = "package_metadata:source_field"
				rel.SourcePackage = v.SourcePackage
			}
		}
	}

	if rel.SourcePackage == "" {
		rel.SourcePackage = v.Name
		rel.Confidence = "inferred"
		rel.EvidenceSource = "binary_name_fallback"
	}

	// Source fields such as "openssl (3.0.2-0ubuntu1.16)" carry a version.
	if v.SourceVersion != nil && *v.SourceVersion != "" {
		rel.SourceVersion = *v.SourceVersion
	}
	if name, ver, ok := splitSourceField(rel.SourcePackage); ok {
		rel.SourcePackage = name
		if rel.SourceVersion == "" {
			rel.SourceVersion = ver
		}
	}
	if rel.Confidence == "" {
		rel.Confidence = "inferred"
	}
	return rel
}

// FromContainerPackage converts a container package entry. Container packages
// carry the image digest as ScopeID so findings stay attached to the image
// identity and can never merge with host packages.
func FromContainerPackage(cp evidence.ContainerPackage, imageDigest, containerEvidenceID string) (InstalledPackage, error) {
	if cp.Name == "" || cp.RawVersionString == "" {
		return InstalledPackage{}, fmt.Errorf("container package entry missing name or version (%q %q)", cp.Name, cp.RawVersionString)
	}
	p := InstalledPackage{
		Scope:        ScopeContainer,
		ScopeID:      imageDigest,
		Ecosystem:    normalizeEcosystem(cp.PackageManager),
		Name:         cp.Name,
		RawVersion:   cp.RawVersionString,
		Architecture: cp.Architecture,
		EvidenceID:   containerEvidenceID,
		EntityID:     cp.EntityID,
	}
	// APK databases do not expose a separate source field in this evidence;
	// use the binary name and mark it inferred.
	p.Source = SourceRelationship{
		BinaryPackage:  cp.Name,
		SourcePackage:  cp.Name,
		Confidence:     "inferred",
		EvidenceSource: "binary_name_fallback",
	}
	p.SourcePackage = cp.Name
	return p, nil
}

// splitSourceField handles dpkg "Source: name (version)" values.
func splitSourceField(s string) (name, version string, ok bool) {
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return s, "", false
	}
	j := strings.IndexByte(s[i:], ')')
	if j < 0 {
		return s, "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1 : i+j]), true
}

// entityIDName extracts the trailing name from ids like "srcpkg:dpkg:openssl".
func entityIDName(entityID string) string {
	parts := strings.Split(entityID, ":")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func normalizeConfidence(c string) string {
	switch strings.ToLower(c) {
	case "direct", "strong":
		return "direct"
	case "inferred", "weak":
		return "inferred"
	default:
		return strings.ToLower(c)
	}
}

func normalizeEcosystem(pm string) string {
	switch strings.ToLower(pm) {
	case "dpkg", "apt", "deb":
		return "dpkg"
	case "rpm", "dnf", "yum", "zypper":
		return "rpm"
	case "apk":
		return "apk"
	default:
		return strings.ToLower(pm)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Index provides the lookups the resolver engine needs. It never mixes scopes.
type Index struct {
	// BySourcePackage maps scopeKey -> source package -> packages.
	BySourcePackage map[string]map[string][]*InstalledPackage
	// ByName maps scopeKey -> binary package name -> packages.
	ByName map[string]map[string][]*InstalledPackage
	// ByEntityID maps collector entity ids ("pkg:dpkg:openssl:...") to packages.
	ByEntityID map[string]*InstalledPackage
	All        []*InstalledPackage
	// Duplicates counts identity collisions (same IdentityKey seen twice).
	Duplicates int
}

func scopeKey(scope, scopeID string) string { return scope + "|" + scopeID }

// HostScopeKey is the index key for host packages.
func HostScopeKey() string { return scopeKey(ScopeHost, "") }

// ContainerScopeKey is the index key for one container image scope.
func ContainerScopeKey(imageDigest string) string { return scopeKey(ScopeContainer, imageDigest) }

// NewIndex builds lookup structures over installed packages.
func NewIndex(packages []InstalledPackage) *Index {
	idx := &Index{
		BySourcePackage: map[string]map[string][]*InstalledPackage{},
		ByName:          map[string]map[string][]*InstalledPackage{},
		ByEntityID:      map[string]*InstalledPackage{},
	}
	seen := map[string]bool{}
	for i := range packages {
		p := &packages[i]
		key := p.IdentityKey()
		if seen[key] {
			idx.Duplicates++
			continue
		}
		seen[key] = true
		idx.All = append(idx.All, p)
		sk := scopeKey(p.Scope, p.ScopeID)
		if idx.BySourcePackage[sk] == nil {
			idx.BySourcePackage[sk] = map[string][]*InstalledPackage{}
			idx.ByName[sk] = map[string][]*InstalledPackage{}
		}
		idx.BySourcePackage[sk][p.SourcePackage] = append(idx.BySourcePackage[sk][p.SourcePackage], p)
		idx.ByName[sk][p.Name] = append(idx.ByName[sk][p.Name], p)
		if p.EntityID != "" {
			idx.ByEntityID[p.EntityID] = p
		}
	}
	return idx
}

// LookupHost returns the first host-scoped package with the given binary name.
func (idx *Index) LookupHost(name string) *InstalledPackage {
	for _, p := range idx.ByName[HostScopeKey()][name] {
		return p
	}
	return nil
}
