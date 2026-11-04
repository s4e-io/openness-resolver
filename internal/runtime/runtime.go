// Package runtime implements Task 10 of the resolver backlog: correlating
// processes, executables, packages, services and containers into a runtime
// index used to enrich findings with actual execution state.
//
// The index only consumes relationships already present in .openness evidence.
// Runtime exposure is never claimed when a package is merely installed:
// a vulnerable-but-not-running package keeps state "vulnerable" with
// runtime_state "not_observed_running".
package runtime

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// ProcessRuntime is a resolved process -> executable -> package chain.
type ProcessRuntime struct {
	PID                int      `json:"pid"`
	EvidenceID         string   `json:"evidence_id"`
	Name               string   `json:"name"`
	ExecutablePath     string   `json:"executable_path"`
	ExecutableRealpath string   `json:"executable_realpath"`
	ExecutableDeleted  bool     `json:"executable_deleted"`
	PackageName        string   `json:"package_name,omitempty"`
	PackageManager     string   `json:"package_manager,omitempty"`
	SourcePackage      string   `json:"source_package,omitempty"`
	Services           []string `json:"services,omitempty"`
	// Confidence of the executable->package link (direct | inferred | "").
	OwnershipConfidence string `json:"ownership_confidence,omitempty"`
	// KernelThread marks processes without an executable path (kthreads).
	KernelThread bool `json:"kernel_thread"`
}

// RuntimeIndex holds all runtime correlation lookups for one asset.
type RuntimeIndex struct {
	ProcessesByPID map[int]*ProcessRuntime
	// ProcessesByPackage maps binary package name -> running processes
	// owned by that package (host scope only).
	ProcessesByPackage map[string][]*ProcessRuntime
	// ProcessesBySourcePackage maps source package -> running processes.
	ProcessesBySourcePackage map[string][]*ProcessRuntime
	// ServicesByPID maps main PID -> service unit names.
	ServicesByPID map[int][]string
	// DeletedExecutables lists processes whose executable was deleted
	// after start (candidates for vulnerable_runtime).
	DeletedExecutables []*ProcessRuntime
	// LibrariesByPackage maps package name -> PIDs with that library loaded.
	LibrariesByPackage map[string][]LibraryUse
	// Notes records correlation anomalies (missing exe path, PID reuse
	// candidates, etc.); they are reported, not silently dropped.
	Notes []string
}

// LibraryUse records one loaded shared library owned by a package.
type LibraryUse struct {
	PID         int    `json:"pid"`
	LibraryPath string `json:"library_path"`
	Deleted     bool   `json:"deleted"`
	RawVersion  string `json:"raw_version"`
}

// Build creates the runtime index from .openness evidence.
func Build(
	processes []evidence.TypedRecord[evidence.ProcessValue],
	services []evidence.TypedRecord[evidence.ServiceValue],
	chains []evidence.TypedRecord[evidence.EvidenceChainValue],
	libraries []evidence.TypedRecord[evidence.LoadedLibrariesValue],
	pkgIndex *pkgs.Index,
) *RuntimeIndex {
	idx := &RuntimeIndex{
		ProcessesByPID:           map[int]*ProcessRuntime{},
		ProcessesByPackage:       map[string][]*ProcessRuntime{},
		ProcessesBySourcePackage: map[string][]*ProcessRuntime{},
		ServicesByPID:            map[int][]string{},
		LibrariesByPackage:       map[string][]LibraryUse{},
	}

	// Services first: MainPID -> unit name.
	for _, s := range services {
		if s.Value.MainPID > 0 {
			idx.ServicesByPID[s.Value.MainPID] = append(idx.ServicesByPID[s.Value.MainPID], s.Value.UnitName)
		}
	}

	// Processes.
	for _, p := range processes {
		v := p.Value
		pr := &ProcessRuntime{
			PID:                v.PID,
			EvidenceID:         p.EvidenceID,
			Name:               v.Name,
			ExecutablePath:     v.ExecutablePath,
			ExecutableRealpath: v.ExecutableRealpath,
			ExecutableDeleted:  v.ExecutableDeleted,
			Services:           idx.ServicesByPID[v.PID],
		}
		if v.ExecutablePath == "" && v.CommandLine == "" {
			pr.KernelThread = true
		}
		if existing, dup := idx.ProcessesByPID[v.PID]; dup {
			// Same PID from different modules: PID reuse between collection
			// modules. Keep the first, note the anomaly.
			idx.Notes = append(idx.Notes, fmt.Sprintf("pid %d seen twice (%s, %s): possible PID reuse between collection modules", v.PID, existing.EvidenceID, p.EvidenceID))
			continue
		}
		idx.ProcessesByPID[v.PID] = pr
		if pr.ExecutableDeleted {
			idx.DeletedExecutables = append(idx.DeletedExecutables, pr)
		}
		if v.ExecutablePath == "" && !pr.KernelThread {
			idx.Notes = append(idx.Notes, fmt.Sprintf("pid %d (%s): executable path unavailable", v.PID, v.Name))
		}
	}

	// Evidence chains carry the authoritative binary -> package ownership.
	for _, c := range chains {
		v := c.Value
		if v.Process == nil {
			continue
		}
		pr, ok := idx.ProcessesByPID[v.Process.PID]
		if !ok {
			// The process exited between collection modules; record it so
			// the gap is visible.
			idx.Notes = append(idx.Notes, fmt.Sprintf("chain %s references pid %d not present in process inventory (process exited between modules?)", v.EntityID, v.Process.PID))
			continue
		}
		if v.Binary != nil && v.Binary.PackageOwner != nil {
			po := v.Binary.PackageOwner
			pr.PackageName = po.PackageName
			pr.PackageManager = po.PackageManager
			pr.OwnershipConfidence = "direct"
		}
		if v.Package != nil {
			if pr.PackageName == "" {
				pr.PackageName = v.Package.Name
				pr.PackageManager = v.Package.PackageManager
				pr.OwnershipConfidence = "direct"
			}
			pr.SourcePackage = v.Package.SourcePackage
		}
	}

	// Fallback ownership: process executable path relationships in the
	// package index (collector may emit process_executed_binary +
	// binary_owned_by_package). We only use the name-based fallback when
	// realpath resolution keeps it unambiguous, and mark it inferred.
	for _, pr := range idx.ProcessesByPID {
		if pr.PackageName != "" || pr.KernelThread || pr.ExecutablePath == "" {
			continue
		}
		if pkgIndex != nil {
			path := pr.ExecutableRealpath
			if path == "" {
				path = pr.ExecutablePath
			}
			base := path[strings.LastIndexByte(path, '/')+1:]
			candidates := pkgIndex.ByName[pkgs.HostScopeKey()][base]
			if len(candidates) == 1 {
				pr.PackageName = candidates[0].Name
				pr.SourcePackage = candidates[0].SourcePackage
				pr.OwnershipConfidence = "inferred"
			}
		}
	}

	// Source-package resolution via the installed package index.
	for _, pr := range idx.ProcessesByPID {
		if pr.PackageName == "" {
			continue
		}
		if pr.SourcePackage == "" && pkgIndex != nil {
			if cands := pkgIndex.ByName[pkgs.HostScopeKey()][pr.PackageName]; len(cands) > 0 {
				pr.SourcePackage = cands[0].SourcePackage
			}
		}
		idx.ProcessesByPackage[pr.PackageName] = append(idx.ProcessesByPackage[pr.PackageName], pr)
		if pr.SourcePackage != "" {
			idx.ProcessesBySourcePackage[pr.SourcePackage] = append(idx.ProcessesBySourcePackage[pr.SourcePackage], pr)
		}
	}

	// Loaded libraries: package -> processes using it.
	for _, l := range libraries {
		v := l.Value
		pid := pidFromLibsEntity(v.EntityID)
		libs := v.Libraries
		if len(libs) == 0 {
			libs = v.Interesting
		}
		for _, lib := range libs {
			if lib.PackageName == "" {
				continue
			}
			idx.LibrariesByPackage[lib.PackageName] = append(idx.LibrariesByPackage[lib.PackageName], LibraryUse{
				PID: pid, LibraryPath: lib.Path, Deleted: lib.Deleted, RawVersion: lib.RawVersionString,
			})
		}
	}
	return idx
}

// pidFromLibsEntity extracts the PID from "libs:process:2948".
func pidFromLibsEntity(entityID string) int {
	parts := strings.Split(entityID, ":")
	if len(parts) == 0 {
		return 0
	}
	var pid int
	fmt.Sscanf(parts[len(parts)-1], "%d", &pid)
	return pid
}

// Exposure summarizes runtime exposure for one package (by binary and
// source package names).
type Exposure struct {
	Running     bool
	ProcessIDs  []string
	BinaryPaths []string
	Services    []string
	// DeletedExecutable is true when a matching process runs a deleted
	// executable (old binary still mapped after an upgrade).
	DeletedExecutable bool
}

// ExposureFor reports whether any running process belongs to the package.
func (idx *RuntimeIndex) ExposureFor(binaryPackage, sourcePackage string) Exposure {
	var exp Exposure
	seen := map[int]bool{}
	collect := func(list []*ProcessRuntime) {
		for _, pr := range list {
			if seen[pr.PID] {
				continue
			}
			seen[pr.PID] = true
			exp.Running = true
			exp.ProcessIDs = append(exp.ProcessIDs, fmt.Sprintf("%d", pr.PID))
			path := pr.ExecutableRealpath
			if path == "" {
				path = pr.ExecutablePath
			}
			if path != "" {
				exp.BinaryPaths = append(exp.BinaryPaths, path)
			}
			exp.Services = append(exp.Services, pr.Services...)
			if pr.ExecutableDeleted {
				exp.DeletedExecutable = true
			}
		}
	}
	collect(idx.ProcessesByPackage[binaryPackage])
	if sourcePackage != "" && sourcePackage != binaryPackage {
		collect(idx.ProcessesBySourcePackage[sourcePackage])
	}
	// Loaded shared libraries also constitute runtime use of the package.
	for _, use := range idx.LibrariesByPackage[binaryPackage] {
		exp.Running = true
		if !seen[use.PID] && use.PID > 0 {
			seen[use.PID] = true
			exp.ProcessIDs = append(exp.ProcessIDs, fmt.Sprintf("%d", use.PID))
		}
		exp.BinaryPaths = append(exp.BinaryPaths, use.LibraryPath)
		if use.Deleted {
			exp.DeletedExecutable = true
		}
	}
	return exp
}
