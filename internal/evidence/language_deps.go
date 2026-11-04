package evidence

import "encoding/json"

// LanguageDepValue is a flat language_deps entity (schema 1.3.4+).
type LanguageDepValue struct {
	EntityType             string   `json:"entity_type"`
	EntityID               string   `json:"entity_id"`
	Scope                  string   `json:"scope"`
	EnvironmentID          string   `json:"environment_id"`
	EnvironmentKind        string   `json:"environment_kind"`
	Name                   string   `json:"name"`
	NameNormalized         string   `json:"name_normalized"`
	NameRaw                string   `json:"name_raw"`
	Version                string   `json:"version"`
	RawVersionString       string   `json:"raw_version_string"`
	ResolverEcosystem      string   `json:"resolver_ecosystem"`
	InstallationOrigin     string   `json:"installation_origin"`
	RuntimeLoadStatus      string   `json:"runtime_load_status"`
	RuntimeDetectionMethod string   `json:"runtime_detection_method"`
	RuntimeEvidenceIDs     []string `json:"runtime_evidence_ids"`
	LoadedByProcessIDs     []int    `json:"loaded_by_process_ids"`
	LoadedModulePaths      []string `json:"loaded_module_paths"`
	OSBinaryPackage        string   `json:"os_binary_package"`
	OSSourcePackage        string   `json:"os_source_package"`
	OSPackageVersion       string   `json:"os_package_version"`
	OSPackageManager       string   `json:"os_package_manager"`
	MetaPath               string   `json:"meta_path"`
	ProcessID              int      `json:"process_id"`
	ExecutablePath         string   `json:"executable_path"`
}

func (lr *LoadResult) LanguageDepRecords() []TypedRecord[LanguageDepValue] {
	return decodeAll[LanguageDepValue](lr.Doc.LanguageDeps, "language_deps", &lr.RecordErrors)
}

// DecodeLanguageDep accepts either envelope records or flat maps (tests/fixtures).
func DecodeLanguageDep(raw json.RawMessage) (LanguageDepValue, error) {
	var v LanguageDepValue
	if err := json.Unmarshal(raw, &v); err != nil {
		return LanguageDepValue{}, err
	}
	return v, nil
}
