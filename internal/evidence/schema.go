// Package evidence parses Openness .openness evidence documents (JSON schema 1.x).
//
// The parser is tolerant by design: missing categories yield empty slices and
// the resolver later reports "unknown" / "not_applicable" states instead of
// failing. Malformed individual records are collected as record-level errors
// rather than aborting the whole document.
package evidence

import "encoding/json"

// Document is the top-level .openness structure.
type Document struct {
	SchemaVersion   string          `json:"schema_version"`
	Collector       Collector       `json:"collector"`
	Collection      Collection      `json:"collection"`
	Asset           Asset           `json:"asset"`
	OperatingSystem OperatingSystem `json:"operating_system"`
	Kernel          Kernel          `json:"kernel"`

	Packages        []Record `json:"packages"`
	Processes       []Record `json:"processes"`
	Services        []Record `json:"services"`
	ListeningPorts  []Record `json:"listening_ports"`
	Containers      []Record `json:"containers"`
	LoadedLibraries []Record `json:"loaded_libraries"`
	EvidenceChains  []Record `json:"evidence_chains"`
	LanguageDeps    []Record `json:"language_deps"`
	// SoftwareInventory is the collector's catalog-detected products
	// (schema 1.5.0+). Absent on older evidence.
	SoftwareInventory []Record `json:"software_inventory"`
	// Applications are a Windows host's installed applications (Add/Remove Programs,
	// AppX); the resolver's application mapper reads their values.
	Applications []Record `json:"applications"`

	// SecurityConfiguration is retained raw; individual control modules
	// consume the sub-objects they understand.
	SecurityConfiguration json.RawMessage `json:"security_configuration"`

	Modules []ModuleRun `json:"modules"`
	Errors  []any       `json:"errors"`
}

type Collector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	BuildID string `json:"build_id"`
}

type Collection struct {
	CollectionID   string `json:"collection_id"`
	StartedAt      string `json:"started_at"`
	CompletedAt    string `json:"completed_at"`
	DurationMS     int64  `json:"duration_ms"`
	ExecutionMode  string `json:"execution_mode"`
	PrivilegeLevel string `json:"privilege_level"`
	Status         string `json:"status"`
	Partial        bool   `json:"partial"`
}

type Asset struct {
	AssetID      string `json:"asset_id"`
	Hostname     string `json:"hostname"`
	FQDN         string `json:"fqdn"`
	MachineID    string `json:"machine_id"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// OperatingSystem carries normalized /etc/os-release + uname evidence.
type OperatingSystem struct {
	Architecture        string `json:"architecture"`
	DistributionID      string `json:"distribution_id"`
	DistributionName    string `json:"distribution_name"`
	DistributionVersion string `json:"distribution_version"`
	VersionID           string `json:"version_id"`
	VersionCodename     string `json:"version_codename"`
	PrettyName          string `json:"pretty_name"`
	KernelVersion       string `json:"kernel_version"`
	InitSystem          string `json:"init_system"`
	Hostname            string `json:"hostname"`
	MachineID           string `json:"machine_id"`
	Variant             string `json:"variant"`

	// Windows identity (collector os_inventory 1.2.0+). Numbers may arrive
	// as JSON numbers (CIM) or strings (registry), hence FlexString.
	ProductName      string     `json:"product_name"`
	BuildNumber      FlexString `json:"build_number"`
	UBR              FlexString `json:"ubr"`
	DisplayVersion   string     `json:"display_version"`
	OSBuild          string     `json:"os_build"`
	ProductType      FlexString `json:"product_type"`
	InstallationType string     `json:"installation_type"`
}

// FlexString accepts a JSON string or number and keeps it as text.
type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = FlexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = FlexString(n.String())
	return nil
}

func (f FlexString) String() string { return string(f) }

type Kernel struct {
	KernelArchitecture string   `json:"kernel_architecture"`
	KernelPackageHint  string   `json:"kernel_package_hint"`
	LoadedModules      []string `json:"loaded_modules"`
	RebootRequired     bool     `json:"reboot_required"`
	RunningKernel      string   `json:"running_kernel"`
}

// Record is the generic evidence envelope shared by all list categories.
// Value stays raw until decoded by the typed accessors below.
type Record struct {
	EvidenceID       string          `json:"evidence_id"`
	Source           string          `json:"source"`
	SourceModule     string          `json:"source_module"`
	ObservedAt       string          `json:"observed_at"`
	Value            json.RawMessage `json:"value"`
	RawValue         json.RawMessage `json:"raw_value,omitempty"`
	CollectionStatus string          `json:"collection_status"`
}

type ModuleRun struct {
	ModuleID      string `json:"module_id"`
	ModuleVersion string `json:"module_version"`
	Status        string `json:"status"`
	Records       int    `json:"records"`
	Errors        []any  `json:"errors"`
	// Truncated is set by the collector when it cut the module's records.
	Truncated bool `json:"truncated,omitempty"`
}

// Relationship links two evidence entities (e.g. process -> binary).
type Relationship struct {
	Confidence     string `json:"confidence"`
	EvidenceSource string `json:"evidence_source"`
	SourceEntityID string `json:"source_entity_id,omitempty"`
	TargetEntityID string `json:"target_entity_id"`
	Type           string `json:"type"`
}

// PackageValue is the value payload of a packages record (host scope).
type PackageValue struct {
	EntityID                 string  `json:"entity_id"`
	Name                     string  `json:"name"`
	Architecture             string  `json:"architecture"`
	Epoch                    *string `json:"epoch"`
	Version                  string  `json:"version"`
	Release                  string  `json:"release"`
	RawVersionString         string  `json:"raw_version_string"`
	PackageManager           string  `json:"package_manager"`
	PackageStatus            string  `json:"package_status"`
	PackageDatabasePath      string  `json:"package_database_path"`
	SourcePackage            string  `json:"source_package"`
	SourceVersion            *string `json:"source_version"`
	InstalledFromRepository  bool    `json:"installed_from_repository"`
	RepositoryOrigin         string  `json:"repository_origin"`
	RepositorySuite          string  `json:"repository_suite"`
	RepositoryComponent      string  `json:"repository_component"`
	RepositoryCodename       string  `json:"repository_codename"`
	RepositoryURL            string  `json:"repository_url"`
	RepositoryMetadataStatus string  `json:"repository_metadata_status"`
	// HighestListVersion is the highest version for name|arch in the
	// collector's /var/lib/apt/lists parse (not apt pin "candidate").
	// Empty means the collector did not report a list max.
	HighestListVersion string `json:"highest_list_version,omitempty"`
	// HighestListOrigin is the origin observation for that list max.
	HighestListOrigin *ListOriginObservation `json:"highest_list_origin,omitempty"`
	// RuntimeStale is true when the collector observed a running process
	// still using the package after the on-disk files changed.
	RuntimeStale  bool           `json:"runtime_stale,omitempty"`
	Relationships []Relationship `json:"relationships"`
}

// ListOriginObservation is collector highest_list_origin (object, not a bare string).
type ListOriginObservation struct {
	Origin    string `json:"origin,omitempty"`
	Label     string `json:"label,omitempty"`
	Suite     string `json:"suite,omitempty"`
	Component string `json:"component,omitempty"`
	URL       string `json:"url,omitempty"`
	ESM       bool   `json:"esm,omitempty"`
}

// UnmarshalJSON accepts collector 0.5+ highest_list_* fields and legacy
// candidate_version / candidate_origin (string) from older .openness files.
func (v *PackageValue) UnmarshalJSON(data []byte) error {
	type alias PackageValue
	aux := struct {
		*alias
		CandidateVersion string          `json:"candidate_version,omitempty"`
		CandidateOrigin  json.RawMessage `json:"candidate_origin,omitempty"`
	}{alias: (*alias)(v)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if v.HighestListVersion == "" && aux.CandidateVersion != "" {
		v.HighestListVersion = aux.CandidateVersion
	}
	if v.HighestListOrigin == nil && len(aux.CandidateOrigin) > 0 && string(aux.CandidateOrigin) != "null" {
		var asString string
		if err := json.Unmarshal(aux.CandidateOrigin, &asString); err == nil && asString != "" {
			v.HighestListOrigin = &ListOriginObservation{Origin: asString}
		}
	}
	return nil
}

// ProcessValue is the value payload of a processes record.
type ProcessValue struct {
	EntityID           string         `json:"entity_id"`
	PID                int            `json:"pid"`
	PPID               int            `json:"ppid"`
	Name               string         `json:"name"`
	CommandLine        string         `json:"command_line"`
	ExecutablePath     string         `json:"executable_path"`
	ExecutableRealpath string         `json:"executable_realpath"`
	ExecutableDeleted  bool           `json:"executable_deleted"`
	UID                int            `json:"uid"`
	GID                int            `json:"gid"`
	CWD                string         `json:"cwd"`
	Relationships      []Relationship `json:"relationships"`
}

// ServiceValue is the value payload of a services record.
type ServiceValue struct {
	EntityID      string         `json:"entity_id"`
	ServiceName   string         `json:"service_name"`
	UnitName      string         `json:"unit_name"`
	ActiveState   string         `json:"active_state"`
	SubState      string         `json:"sub_state"`
	LoadState     string         `json:"load_state"`
	UnitFileState string         `json:"unit_file_state"`
	MainPID       int            `json:"main_pid"`
	FragmentPath  string         `json:"fragment_path"`
	InitSystem    string         `json:"init_system"`
	Relationships []Relationship `json:"relationships"`
}

// ListeningPortValue is the value payload of a listening_ports record.
type ListeningPortValue struct {
	EntityID         string         `json:"entity_id"`
	Protocol         string         `json:"protocol"`
	AddressFamily    string         `json:"address_family"`
	LocalAddress     string         `json:"local_address"`
	LocalPort        int            `json:"local_port"`
	State            string         `json:"state"`
	Exposure         string         `json:"exposure"`
	PID              int            `json:"pid"`
	ProcessName      string         `json:"process_name"`
	NetworkNamespace string         `json:"network_namespace"`
	ContainerID      *string        `json:"container_id"`
	Relationships    []Relationship `json:"relationships"`
}

// ContainerPackage is a package entry inside a container record.
type ContainerPackage struct {
	EntityID         string `json:"entity_id"`
	Name             string `json:"name"`
	Architecture     string `json:"architecture"`
	PackageManager   string `json:"package_manager"`
	PackagesScope    string `json:"packages_scope"`
	RawVersionString string `json:"raw_version_string"`
	// SourcePackage / SourceVersion: the dpkg Source field (collector
	// containers 1.2.0+); empty on older evidence and for apk/rpm.
	SourcePackage string  `json:"source_package,omitempty"`
	SourceVersion *string `json:"source_version,omitempty"`
}

// ContainerOSRelease is the image's os-release identity (collector
// containers 1.2.0+). Absent on older evidence and scratch images.
type ContainerOSRelease struct {
	ID              string `json:"id"`
	IDLike          string `json:"id_like,omitempty"`
	Name            string `json:"name,omitempty"`
	VersionID       string `json:"version_id,omitempty"`
	VersionCodename string `json:"version_codename,omitempty"`
	PrettyName      string `json:"pretty_name,omitempty"`
	Source          string `json:"source,omitempty"`
	SourceFile      string `json:"source_file,omitempty"`
}

// ContainerValue is the value payload of a containers record.
type ContainerValue struct {
	EntityID           string `json:"entity_id"`
	ContainerID        string `json:"container_id"`
	Name               string `json:"name"`
	Runtime            string `json:"runtime"`
	State              string `json:"state"`
	ImageDigest        string `json:"image_digest"`
	ImageID            string `json:"image_id"`
	ImageReference     string `json:"image_reference"`
	IdentityPrimary    string `json:"identity_primary"`
	RootFSPath         string `json:"rootfs_path"`
	PID                *int   `json:"pid"`
	PackageCount       int    `json:"package_count"`
	PackageSource      string `json:"package_source"`
	PackagesScope      string `json:"packages_scope"`
	HostPackagesMerged bool   `json:"host_packages_merged"`
	// PackagesTruncated: the collector cut this container's package list.
	PackagesTruncated bool                `json:"packages_truncated,omitempty"`
	OSRelease         *ContainerOSRelease `json:"os_release,omitempty"`
	Packages          []ContainerPackage  `json:"packages"`
	Relationships     []Relationship      `json:"relationships"`
}

// LoadedLibrary is one shared object mapped into a process.
type LoadedLibrary struct {
	EntityID           string `json:"entity_id"`
	Path               string `json:"path"`
	Deleted            bool   `json:"deleted"`
	PackageManager     string `json:"package_manager"`
	PackageName        string `json:"package_name"`
	PackageOwnerStatus string `json:"package_owner_status"`
	RawVersionString   string `json:"raw_version_string"`
	SourcePackage      string `json:"source_package"`
}

// LoadedLibrariesValue is the value payload of a loaded_libraries record.
type LoadedLibrariesValue struct {
	EntityID       string          `json:"entity_id"`
	ExecutablePath string          `json:"executable_path"`
	DeletedCount   int             `json:"deleted_count"`
	Interesting    []LoadedLibrary `json:"interesting"`
	Libraries      []LoadedLibrary `json:"libraries"`
}

// ChainPackageOwner describes package ownership discovered for a binary.
type ChainPackageOwner struct {
	PackageManager string `json:"package_manager"`
	PackageName    string `json:"package_name"`
	Path           string `json:"path"`
	Status         string `json:"status"`
}

// ChainBinary is the binary node of an evidence chain.
type ChainBinary struct {
	EntityID     string             `json:"entity_id"`
	Path         string             `json:"path"`
	Exists       bool               `json:"exists"`
	SHA256       string             `json:"sha256"`
	Size         int64              `json:"size"`
	PackageOwner *ChainPackageOwner `json:"package_owner"`
}

// ChainPackage is the package node of an evidence chain.
type ChainPackage struct {
	Name           string  `json:"name"`
	PackageManager string  `json:"package_manager"`
	SourcePackage  string  `json:"source_package"`
	SourceVersion  *string `json:"source_version"`
}

// EvidenceChainValue is the value payload of an evidence_chains record.
type EvidenceChainValue struct {
	EntityID      string         `json:"entity_id"`
	Chain         []string       `json:"chain"`
	Complete      bool           `json:"complete"`
	Binary        *ChainBinary   `json:"binary"`
	Package       *ChainPackage  `json:"package"`
	Process       *ProcessValue  `json:"process"`
	Relationships []Relationship `json:"relationships"`
}

// SoftwareInstanceValue is one software_inventory record (collector 0.5.x,
// schema 1.5.0+). Summary rows (entity_type software_inventory_summary) use
// the same envelope but only EntityType/EntityID are meaningful there.
type SoftwareInstanceValue struct {
	EntityType        string          `json:"entity_type"`
	EntityID          string          `json:"entity_id"`
	ProductKey        string          `json:"product_key"`
	Vendor            string          `json:"vendor"`
	Product           string          `json:"product"`
	CPEPrefix         string          `json:"cpe_prefix"`
	Scope             string          `json:"scope"`
	InstallPath       string          `json:"install_path"`
	Version           string          `json:"version"`
	VersionSource     *VersionHit     `json:"version_source"`
	VersionCandidates []VersionHit    `json:"version_candidates"`
	PatchIDs          []string        `json:"patch_ids"`
	PatchSource       string          `json:"patch_source"`
	Confidence        string          `json:"confidence"`
	Gap               string          `json:"gap"`
	Running           bool            `json:"running"`
	Signals           SoftwareSignals `json:"signals"`
	CatalogVerified   bool            `json:"catalog_verified"`
	CatalogVersion    string          `json:"catalog_version"`
}

// VersionHit is one value a collector reader found and where.
type VersionHit struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Value  string `json:"value"`
}

// SoftwareSignals are the presence hints the collector recorded.
type SoftwareSignals struct {
	Paths     []string          `json:"paths"`
	Processes []SoftwareProcess `json:"processes"`
	Ports     []int             `json:"ports"`
	Registry  []string          `json:"registry"`
}

type SoftwareProcess struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe"`
}
