// Package rules defines the normalized vendor vulnerability rule models
// (Task 5) and the advisory source registry. Raw vendor statuses are always
// preserved next to their normalized form; vendor notes are never discarded.
package rules

import (
	"strings"
	"time"
)

// Normalized vendor statuses.
const (
	StatusReleased     = "released"
	StatusNeeded       = "needed"
	StatusDeferred     = "deferred"
	StatusNotAffected  = "not_affected"
	StatusDoesNotExist = "does_not_exist"
	StatusIgnored      = "ignored"
	StatusUnknown      = "unknown"
)

// UbuntuPackageRule is the normalized Ubuntu vulnerability rule model.
type UbuntuPackageRule struct {
	RuleID          string `json:"rule_id"`
	CVEID           string `json:"cve_id"`
	ReleaseCodename string `json:"release_codename"`
	SourcePackage   string `json:"source_package"`
	// BinaryPackages lists the binary packages produced by the source
	// package according to the vendor feed (OVAL variable values).
	BinaryPackages []string `json:"binary_packages,omitempty"`
	Architecture   string   `json:"architecture"` // "" = all architectures
	Status         string   `json:"status"`       // normalized status
	RawStatus      string   `json:"raw_status"`   // vendor wording, preserved
	FixedVersion   string   `json:"fixed_version"`
	Urgency        string   `json:"urgency"`
	USNIDs         []string `json:"usn_ids,omitempty"`
	// SupportTier: "" (standard security pocket), "esm-infra", "esm-apps".
	SupportTier    string    `json:"support_tier,omitempty"`
	VendorNotes    string    `json:"vendor_notes,omitempty"`
	SourceURL      string    `json:"source_url"`
	SourceRevision string    `json:"source_revision"`
	PublishedAt    time.Time `json:"published_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

// AlpinePackageRule is the normalized Alpine secdb rule model.
type AlpinePackageRule struct {
	RuleID         string `json:"rule_id"`
	CVEID          string `json:"cve_id"`
	Branch         string `json:"branch"` // e.g. "v3.18"
	Repository     string `json:"repository"`
	PackageName    string `json:"package_name"`
	FixedVersion   string `json:"fixed_version"`
	Status         string `json:"status"`     // released | not_affected
	RawStatus      string `json:"raw_status"` // raw secdb fixed-version key
	SourceURL      string `json:"source_url"`
	SourceRevision string `json:"source_revision"`
}

// FeedSourceMetadata records provenance for one raw feed snapshot.
type FeedSourceMetadata struct {
	SourceName      string     `json:"source_name"`
	SourceURL       string     `json:"source_url"`
	DownloadedAt    time.Time  `json:"downloaded_at"`
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`
	SHA256          string     `json:"sha256"`
	ETag            string     `json:"etag,omitempty"`
	SizeBytes       int64      `json:"size_bytes"`
	ParserVersion   string     `json:"parser_version"`
	RawObjectID     string     `json:"raw_object_id"`
	SnapshotDir     string     `json:"snapshot_dir"`
	// PackageNames is the set of PyPI distributions this snapshot covers, including names
	// that had no vulnerabilities, for data from the per-package OSV queries of older
	// versions. The osv-pypi archive covers every package and leaves it empty.
	PackageNames []string `json:"package_names,omitempty"`
	// Vendor and Release are the directory the snapshot was loaded from
	// (normalized/<vendor>/<release>); they are not stored in metadata.json.
	Vendor  string `json:"-"`
	Release string `json:"-"`
}

// PackageVulnerabilityRule is the generic normalized rule model that the
// resolver engine consumes. Ecosystem-specific identity is preserved;
// nothing is forced into CPE.
type PackageVulnerabilityRule struct {
	RuleID       string `json:"rule_id"`
	Ecosystem    string `json:"ecosystem"` // dpkg | apk | rpm
	Vendor       string `json:"vendor"`    // ubuntu | alpine | ...
	Distribution string `json:"distribution"`
	// Release is the codename for Ubuntu ("jammy") or branch for Alpine ("v3.18").
	Release       string `json:"release"`
	Architecture  string `json:"architecture"` // "" = all
	PackageName   string `json:"package_name"` // binary package (apk: package)
	SourcePackage string `json:"source_package"`
	Status        string `json:"status"`
	RawStatus     string `json:"raw_status"`
	FixedVersion  string `json:"fixed_version"`
	// IntroducedVersion is the first affected version when the source states
	// one (OSV "introduced" other than "0"). Empty means every version below
	// FixedVersion is affected.
	IntroducedVersion string   `json:"introduced_version,omitempty"`
	Comparator        string   `json:"comparator"` // dpkg | apk | rpm
	CVEID             string   `json:"cve_id"`
	AdvisoryIDs       []string `json:"advisory_ids,omitempty"`
	Urgency           string   `json:"urgency,omitempty"`
	SupportTier       string   `json:"support_tier,omitempty"`
	VendorNotes       string   `json:"vendor_notes,omitempty"`
	// SourcePriority is the precedence rank of the producing source
	// (lower = more authoritative). Distribution vendor advisories are 1.
	SourcePriority   int        `json:"source_priority"`
	PublishedAt      *time.Time `json:"published_at,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
	SourceSnapshotID string     `json:"source_snapshot_id"`
	RawObjectID      string     `json:"raw_object_id"`
	SourceURL        string     `json:"source_url,omitempty"`
	// IsKernel marks kernel-flavour rules (SourcePackage = kernel source
	// family, e.g. "linux-hwe-6.8"). They are evaluated against the running
	// kernel (T06), never against ordinary installed packages.
	IsKernel bool `json:"is_kernel,omitempty"`
	// RestartRequired is the vendor's statement that applying the fix needs
	// a reboot (MSRC RestartRequired).
	RestartRequired bool `json:"restart_required,omitempty"`
	// Supersedes lists advisories this fix replaces (MSRC Supercedence KB).
	Supersedes []string `json:"supersedes,omitempty"`
}

// AdvisorySource describes one entry of the source registry.
type AdvisorySource struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Ecosystem       string        `json:"ecosystem"`
	Vendor          string        `json:"vendor"`
	URL             string        `json:"url"`
	Format          string        `json:"format"`
	Priority        int           `json:"priority"` // source precedence: 1 = distro vendor
	Enabled         bool          `json:"enabled"`
	Parser          string        `json:"parser"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	Notes           string        `json:"notes,omitempty"`
}

// AppMapperURL is where the S4E catalog publishes the latest mapper bundle; SHA256SUMS
// sits next to it.
const AppMapperURL = "https://github.com/s4e-io/openness-catalog/releases/latest/download/app-mapper.json.gz"

// Registry returns the built-in advisory source registry.
//
// Source precedence tiers (lower number wins; a lower-priority source can
// never override a higher-priority vendor status without a conflict record):
//
//	1 distribution vendor security advisory
//	2 ecosystem maintainer advisory
//	3 upstream vendor advisory
//	4 OSV / GitHub Advisory Database
//	5 NVD
//	6 AI-generated inference (never used for final decisions)
func Registry() []AdvisorySource {
	out := []AdvisorySource{
		{
			ID: "ubuntu-oval-usn-jammy", Name: "Ubuntu USN OVAL (jammy)",
			Ecosystem: "dpkg", Vendor: "ubuntu",
			URL:    "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2",
			Format: "oval-xml-bz2", Priority: 1, Enabled: true, Parser: "ubuntu-oval",
			RefreshInterval: 24 * time.Hour,
		},
		{
			ID: "ubuntu-oval-usn-focal", Name: "Ubuntu USN OVAL (focal)",
			Ecosystem: "dpkg", Vendor: "ubuntu",
			URL:    "https://security-metadata.canonical.com/oval/com.ubuntu.focal.usn.oval.xml.bz2",
			Format: "oval-xml-bz2", Priority: 1, Enabled: false, Parser: "ubuntu-oval",
			RefreshInterval: 24 * time.Hour,
			Notes:           "enable when focal assets appear",
		},
		{
			ID: "ubuntu-oval-usn-noble", Name: "Ubuntu USN OVAL (noble)",
			Ecosystem: "dpkg", Vendor: "ubuntu",
			URL:    "https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2",
			Format: "oval-xml-bz2", Priority: 1, Enabled: false, Parser: "ubuntu-oval",
			RefreshInterval: 24 * time.Hour,
			Notes:           "enable when noble assets appear",
		},
		{
			ID: "ubuntu-oval-cve-jammy", Name: "Ubuntu CVE OVAL (jammy)",
			Ecosystem: "dpkg", Vendor: "ubuntu",
			URL:    "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2",
			Format: "oval-xml-bz2", Priority: 1, Enabled: false, Parser: "ubuntu-oval",
			RefreshInterval: 24 * time.Hour,
			Notes:           "adds needed/deferred/ignored statuses; enable after USN baseline is stable",
		},
	}
	// Alpine secdb: one main and one community document per branch.
	out = append(out, releaseRegistry("alpine", AlpineBranches)...)
	// Amazon Linux: one core repository updateinfo per release.
	out = append(out, releaseRegistry("amazon", AmazonReleases)...)
	return append(out, []AdvisorySource{
		// One document covers every Debian release; rules are stored per
		// codename (bookworm, trixie).
		{
			ID: "debian-security-tracker", Name: "Debian Security Tracker JSON",
			Ecosystem: "dpkg", Vendor: "debian",
			URL:    "https://security-tracker.debian.org/tracker/data/json",
			Format: "json", Priority: 1, Enabled: true, Parser: "debian-tracker",
			RefreshInterval: 24 * time.Hour,
		},
		// OSV bulk exports published by the distribution vendors themselves
		// (RESF, AlmaLinux, Red Hat, SUSE). One archive covers every release
		// of the vendor; rules are stored per release (major version, or
		// Leap version for openSUSE).
		{
			ID: "osv-rocky", Name: "Rocky Linux errata (OSV)",
			Ecosystem: "rpm", Vendor: "rocky",
			URL:    "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip",
			Format: "osv-zip", Priority: 1, Enabled: true, Parser: "osv-distro",
			RefreshInterval: 24 * time.Hour,
		},
		{
			ID: "osv-almalinux", Name: "AlmaLinux errata (OSV)",
			Ecosystem: "rpm", Vendor: "almalinux",
			URL:    "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip",
			Format: "osv-zip", Priority: 1, Enabled: true, Parser: "osv-distro",
			RefreshInterval: 24 * time.Hour,
		},
		{
			ID: "osv-rhel", Name: "Red Hat errata (OSV)",
			Ecosystem: "rpm", Vendor: "rhel",
			URL:    "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip",
			Format: "osv-zip", Priority: 1, Enabled: true, Parser: "osv-distro",
			RefreshInterval: 24 * time.Hour,
		},
		{
			ID: "osv-opensuse", Name: "openSUSE Leap updates (OSV)",
			Ecosystem: "rpm", Vendor: "opensuse",
			URL:    "https://osv-vulnerabilities.storage.googleapis.com/openSUSE/all.zip",
			Format: "osv-zip", Priority: 1, Enabled: true, Parser: "osv-distro",
			RefreshInterval: 24 * time.Hour,
		},
		// PyPI advisories (PyPA advisory database and GitHub advisories, through OSV): one
		// archive for every PyPI package, downloaded like the distribution feeds so resolve
		// never asks OSV per package. Rules go to pypi/pypi.
		{
			ID: "osv-pypi", Name: "PyPI advisories (OSV)",
			Ecosystem: "pypi", Vendor: "pypi",
			URL:    "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
			Format: "osv-zip", Priority: 4, Enabled: true, Parser: "osv-pypi",
			RefreshInterval: 24 * time.Hour,
		},
		// The application and device mapper (catalog by S4E plus NVD data), published as a
		// release asset of a public GitHub repository; no account or key.
		{
			ID: "app-mapper", Name: "OpenNess application and device mapper",
			Ecosystem: "mapper", Vendor: "openness",
			URL:    AppMapperURL,
			Format: "openness-app-mapper-gz", Priority: 5, Enabled: true, Parser: "app-mapper",
			RefreshInterval: 24 * time.Hour,
		},
		// Generic OSV (registered, disabled; PyPI has its own source, osv-pypi).
		{ID: "osv", Name: "OSV", Ecosystem: "multi", Vendor: "osv", URL: "https://osv-vulnerabilities.storage.googleapis.com", Format: "osv-json", Priority: 4, Enabled: false, Parser: "osv", RefreshInterval: 24 * time.Hour},
	}...)
}

// SourceByID looks up a registry entry.
func SourceByID(id string) (AdvisorySource, bool) {
	for _, s := range Registry() {
		if s.ID == id {
			return s, true
		}
	}
	// Release-derived ids (ubuntu-oval-usn-noble, msrc-cvrf-2026-Oct, ...)
	// are not enumerated in the registry; rebuild them from the id.
	for vendor, f := range releaseFeeds {
		if !strings.HasPrefix(id, f.idPrefix) {
			continue
		}
		rest := strings.TrimPrefix(id, f.idPrefix)
		srcs, err := ReleaseSources(vendor, rest)
		if err != nil {
			continue
		}
		for _, s := range srcs {
			if s.ID == id {
				return s, true
			}
		}
	}
	return AdvisorySource{}, false
}
