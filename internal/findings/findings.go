// Package findings defines the resolver output model. Findings are never
// boolean: every decision carries a state, confidence, the vendor rule that
// produced it, the exact comparison performed and the evidence chain.
package findings

// Finding states.
const (
	StateVulnerable            = "vulnerable"
	StateFixed                 = "fixed"
	StateNotApplicable         = "not_applicable"
	StatePotentiallyVulnerable = "potentially_vulnerable"
	StateUnknown               = "unknown"
	StateConflictingEvidence   = "conflicting_evidence"
	StateVulnerableRuntime     = "vulnerable_runtime"
)

// Fix availability values.
const (
	FixAvailable   = "available"
	FixUnavailable = "unavailable"
	FixDeferred    = "deferred"
	FixRequiresESM = "requires_esm"
)

// Runtime states.
const (
	RuntimeRunning     = "running"
	RuntimeNotObserved = "not_observed_running"
	RuntimeUnknown     = ""
)

// Comparison records the exact version comparison that drove a decision.
type Comparison struct {
	Comparator string `json:"comparator"`
	Installed  string `json:"installed"`
	Fixed      string `json:"fixed"`
	Expression string `json:"expression"` // e.g. "installed < fixed"
	Result     bool   `json:"result"`
	Error      string `json:"error,omitempty"`
}

// RuleRef explains which vendor rule was applied and where it came from.
type RuleRef struct {
	RuleID         string `json:"rule_id"`
	Source         string `json:"source"`
	SourceURL      string `json:"source_url,omitempty"`
	SourceSnapshot string `json:"source_snapshot,omitempty"`
	Release        string `json:"release"`
	FixedVersion   string `json:"fixed_version,omitempty"`
	Comparator     string `json:"comparator"`
	VendorStatus   string `json:"vendor_status"`
	RawStatus      string `json:"raw_status,omitempty"`
	SupportTier    string `json:"support_tier,omitempty"`
}

// Finding types.
const (
	FindingTypeCVE               = "cve"
	FindingTypeAdvisoryOnly      = "advisory_only"
	FindingTypePythonEnvironment = "python_environment"
)

// Finding is one resolver decision for (asset|image, package, CVE).
type Finding struct {
	FindingID       string   `json:"finding_id"`
	AssetID         string   `json:"asset_id"`
	Scope           string   `json:"scope"` // host | container | python_environment
	ImageDigest     string   `json:"image_digest,omitempty"`
	ContainerIDs    []string `json:"container_ids,omitempty"`
	FindingType     string   `json:"finding_type,omitempty"` // cve | advisory_only | python_environment
	CVEID           string   `json:"cve_id,omitempty"`
	State           string   `json:"state"`
	Confidence      string   `json:"confidence"` // high | medium | low
	DetectionMethod string   `json:"detection_method"`

	BinaryPackage    string   `json:"binary_package"`
	RawPackageName   string   `json:"raw_package_name,omitempty"`
	SourcePackage    string   `json:"source_package"`
	SourceConfidence string   `json:"source_package_confidence,omitempty"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Distribution     string   `json:"distribution"`
	Release          string   `json:"release"`
	Architecture     string   `json:"architecture"`
	VendorStatus     string   `json:"vendor_status"`
	FixAvailability  string   `json:"fix_availability,omitempty"`
	Urgency          string   `json:"urgency,omitempty"`
	AdvisoryIDs      []string `json:"advisory_ids,omitempty"`
	// Severity and CVSSScore come with the source's own rating (the NVD for third-party
	// applications); empty when the source has none and the consumer rates the finding.
	Severity  string   `json:"severity,omitempty"`
	CVSSScore *float64 `json:"cvss_score,omitempty"`
	// MatchStrength says how a third-party application was tied to its catalog entry:
	// signature, product_code or name (name only, unconfirmed).
	MatchStrength string `json:"match_strength,omitempty"`

	// Provenance (T04): vendor | third_party | unknown — where the installed
	// package came from relative to the distribution vendor.
	Provenance          string `json:"provenance,omitempty"`
	RepositorySuite     string `json:"repository_suite,omitempty"`
	RepositoryComponent string `json:"repository_component,omitempty"`

	// Runtime enrichment (Task 10).
	RuntimeState       string   `json:"runtime_state,omitempty"`
	RuntimeProcessIDs  []string `json:"runtime_process_ids,omitempty"`
	RuntimeBinaryPaths []string `json:"runtime_binary_paths,omitempty"`
	RuntimeServices    []string `json:"runtime_services,omitempty"`
	// FixedImageInstalled is set when a fixed kernel image is already on disk
	// and only a reboot is missing. Remediation reads this field.
	FixedImageInstalled bool `json:"fixed_image_installed,omitempty"`

	RuleIDs     []string `json:"rule_ids"`
	EvidenceIDs []string `json:"evidence_ids"`
	Reasons     []string `json:"reasons"`
	Conflicts   []string `json:"conflicts,omitempty"`

	// Explainability payload.
	Rule       *RuleRef    `json:"rule,omitempty"`
	Comparison *Comparison `json:"comparison,omitempty"`
	// MissingEvidence lists evidence categories that were required but absent.
	MissingEvidence []string `json:"missing_evidence,omitempty"`
	// SupersededRules lists same-CVE rules replaced by a newer fixed version.
	SupersededRules []string `json:"superseded_rules,omitempty"`

	// Python environment scope (T25 PyPI findings).
	EnvironmentID         string   `json:"environment_id,omitempty"`
	ResolverEcosystem     string   `json:"resolver_ecosystem,omitempty"`
	NormalizedPackageName string   `json:"normalized_package_name,omitempty"`
	RuntimeLoadStatus     string   `json:"runtime_load_status,omitempty"`
	LoadedModulePaths     []string `json:"loaded_module_paths,omitempty"`

	// Python-correlated Ubuntu package findings (T25 ubuntu_dpkg).
	PythonDistributionEntityIDs []string `json:"python_distribution_entity_ids,omitempty"`
	PythonEnvironmentIDs        []string `json:"python_environment_ids,omitempty"`
	PythonRuntimeLoadStatus     []string `json:"python_runtime_load_status,omitempty"`
	PythonRuntimeProcessIDs     []string `json:"python_runtime_process_ids,omitempty"`
	PythonRuntimeEvidenceIDs    []string `json:"python_runtime_evidence_ids,omitempty"`
}

// DeduplicatedFinding records a Python evaluation merged into a canonical finding.
type DeduplicatedFinding struct {
	CanonicalFindingID         string   `json:"canonical_finding_id"`
	ResolverEcosystem          string   `json:"resolver_ecosystem"`
	PythonDistributionEntityID string   `json:"python_distribution_entity_id"`
	EnvironmentID              string   `json:"environment_id,omitempty"`
	NormalizedPackageName      string   `json:"normalized_package_name"`
	CVEID                      string   `json:"cve_id,omitempty"`
	AdvisoryIDs                []string `json:"advisory_ids,omitempty"`
	FindingType                string   `json:"finding_type"`
	State                      string   `json:"state"`
	Reason                     string   `json:"reason"`
}

// OutputReconciliation verifies metrics == serialized + deduplicated counts.
type OutputReconciliation struct {
	SerializedVulnerable      int  `json:"serialized_vulnerable"`
	SerializedFixed           int  `json:"serialized_fixed"`
	DeduplicatedVulnerable    int  `json:"deduplicated_vulnerable"`
	DeduplicatedFixed         int  `json:"deduplicated_fixed"`
	CVEFindings               int  `json:"cve_findings"`
	AdvisoryOnlyFindings      int  `json:"advisory_only_findings"`
	PythonCorrelatedUbuntu    int  `json:"python_correlated_ubuntu_package_findings"`
	PythonEnvironmentFindings int  `json:"python_environment_findings"`
	Balanced                  bool `json:"balanced"`
	// Remediation fields check that every host vulnerable finding is in
	// exactly one group and that closes.count sums to that population.
	RemediationGroups   int  `json:"remediation_groups"`
	RemediationCloses   int  `json:"remediation_closes"`
	RemediationBalanced bool `json:"remediation_balanced"`
}
