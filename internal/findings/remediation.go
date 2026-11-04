package findings

// OutputSchemaVersion is the findings.json contract.
// Version 1 adds remediation_groups. Scoring is not part of this contract.
const OutputSchemaVersion = "2"

// Remediation actions. The resolver names the action. It does not run it.
const (
	ActionUpgradePackages     = "upgrade_packages"
	ActionRestartService      = "restart_service"
	ActionReboot              = "reboot"
	ActionRequiresEntitlement = "requires_entitlement"
	// ActionInstallUpdate is a Windows cumulative update (KB) card.
	ActionInstallUpdate = "install_update"
	// ActionUpdateApplication updates a third-party application to a fixed version.
	ActionUpdateApplication = "update_application"
)

// Availability is decided only from the collector's candidate version.
const (
	AvailabilityAvailable    = "available"
	AvailabilityNotYetInRepo = "not_yet_in_repo"
	AvailabilityUnknown      = "unknown"
)

// Target kinds carried on a remediation card.
const (
	TargetKindBinary = "binary"
	TargetKindUnit   = "unit"
	// TargetKindOSBuild targets the operating system build (<build>.<ubr>).
	TargetKindOSBuild = "os_build"
	// TargetKindApplication targets an installed application (Add/Remove Programs entry).
	TargetKindApplication = "application"
)

// RemediationTarget is one package, unit, or other object the action touches.
type RemediationTarget struct {
	Name             string `json:"name"`
	Architecture     string `json:"architecture,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	TargetVersion    string `json:"target_version,omitempty"`
	Kind             string `json:"kind"`
}

// RemediationCloses is the set of findings one action addresses.
// Count is nil only when the feed has no CVE list for the action (later).
type RemediationCloses struct {
	FindingIDs []string `json:"finding_ids"`
	CVEIDs     []string `json:"cve_ids"`
	Count      *int     `json:"count"`
}

// RemediationGroup is one action card. Groups are deterministic for a
// fixed evidence file and a fixed feed snapshot.
type RemediationGroup struct {
	GroupID                string              `json:"group_id"`
	Scope                  string              `json:"scope"`
	Action                 string              `json:"action"`
	Targets                []RemediationTarget `json:"targets"`
	SourcePackage          string              `json:"source_package"`
	AdvisoryIDs            []string            `json:"advisory_ids"`
	Closes                 RemediationCloses   `json:"closes"`
	RequiresReboot         bool                `json:"requires_reboot"`
	RequiresServiceRestart []string            `json:"requires_service_restart"`
	RequiresEntitlement    *string             `json:"requires_entitlement"`
	Availability           string              `json:"availability"`
	CoverageNote           *string             `json:"coverage_note"`
	CommandHint            string              `json:"command_hint"`
	// Notes records non-fatal card issues (e.g. hint tokens dropped as unsafe).
	Notes []string `json:"notes,omitempty"`
}
