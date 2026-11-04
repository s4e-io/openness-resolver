// Package python resolves language_deps Python distributions (T25).
package python

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

const (
	EcosystemUbuntuDPKG = "ubuntu_dpkg"
	EcosystemPyPI       = "pypi"
)

// Distribution is one scoped Python distribution from language_deps evidence.
type Distribution struct {
	EntityID           string
	EvidenceID         string
	Scope              string
	EnvironmentID      string
	EnvironmentKind    string
	ResolverEcosystem  string
	NameNormalized     string
	NameRaw            string
	Version            string
	RawVersion         string
	RuntimeLoadStatus  string
	ProcessIDs         []int
	LoadedModulePaths  []string
	RuntimeEvidenceIDs []string
	OSBinaryPackage    string
	OSSourcePackage    string
	OSPackageVersion   string
	OSPackageManager   string
	MetaPath           string
}

// Inventory holds parsed Python evidence entities.
type Inventory struct {
	Distributions []Distribution
	Environments  int
	Processes     int
	Notes         []string
}

// BuildInventory parses python_distribution records from language_deps.
func BuildInventory(recs []evidence.TypedRecord[evidence.LanguageDepValue]) *Inventory {
	inv := &Inventory{}
	envs := map[string]bool{}
	procs := 0
	for _, rec := range recs {
		v := rec.Value
		switch v.EntityType {
		case "python_environment":
			if v.EntityID != "" {
				envs[v.EntityID] = true
			}
		case "process":
			if strings.Contains(strings.ToLower(v.ExecutablePath), "python") {
				procs++
			}
		case "python_distribution":
			d, err := fromRecord(rec)
			if err != nil {
				inv.Notes = append(inv.Notes, err.Error())
				continue
			}
			inv.Distributions = append(inv.Distributions, d)
		}
	}
	inv.Environments = len(envs)
	inv.Processes = procs
	return inv
}

func fromRecord(rec evidence.TypedRecord[evidence.LanguageDepValue]) (Distribution, error) {
	v := rec.Value
	if v.EntityType != "python_distribution" {
		return Distribution{}, fmt.Errorf("not a python_distribution record")
	}
	name := v.NameNormalized
	if name == "" {
		name = normalizeName(v.Name)
	}
	ver := v.Version
	if ver == "" {
		ver = v.RawVersionString
	}
	eco := v.ResolverEcosystem
	if eco == "" {
		return Distribution{}, fmt.Errorf("python distribution %q missing resolver_ecosystem", name)
	}
	runtime := v.RuntimeLoadStatus
	if runtime == "" {
		return Distribution{}, fmt.Errorf("python distribution %q missing runtime_load_status", name)
	}
	return Distribution{
		EntityID:           v.EntityID,
		EvidenceID:         rec.EvidenceID,
		Scope:              defaultScope(v.Scope),
		EnvironmentID:      v.EnvironmentID,
		EnvironmentKind:    v.EnvironmentKind,
		ResolverEcosystem:  eco,
		NameNormalized:     name,
		NameRaw:            firstNonEmpty(v.NameRaw, v.Name),
		Version:            ver,
		RawVersion:         firstNonEmpty(v.RawVersionString, ver),
		RuntimeLoadStatus:  runtime,
		ProcessIDs:         append([]int(nil), v.LoadedByProcessIDs...),
		LoadedModulePaths:  append([]string(nil), v.LoadedModulePaths...),
		RuntimeEvidenceIDs: append([]string(nil), v.RuntimeEvidenceIDs...),
		OSBinaryPackage:    v.OSBinaryPackage,
		OSSourcePackage:    v.OSSourcePackage,
		OSPackageVersion:   v.OSPackageVersion,
		OSPackageManager:   v.OSPackageManager,
		MetaPath:           v.MetaPath,
	}, nil
}

func normalizeName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func defaultScope(s string) string {
	if s == "" {
		return "host"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// IdentityKey is the scoped finding identity for one distribution.
func (d Distribution) IdentityKey() string {
	return strings.Join([]string{d.Scope, d.EnvironmentID, d.ResolverEcosystem, d.NameNormalized, d.RawVersion}, "|")
}
