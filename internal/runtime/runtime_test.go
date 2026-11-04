package runtime

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

func proc(pid int, name, exe string, deleted bool) evidence.TypedRecord[evidence.ProcessValue] {
	return evidence.TypedRecord[evidence.ProcessValue]{
		EvidenceID: "ev-proc",
		Value: evidence.ProcessValue{
			PID: pid, Name: name, CommandLine: exe,
			ExecutablePath: exe, ExecutableRealpath: exe, ExecutableDeleted: deleted,
		},
	}
}

func svc(unit string, mainPID int) evidence.TypedRecord[evidence.ServiceValue] {
	return evidence.TypedRecord[evidence.ServiceValue]{
		EvidenceID: "ev-svc",
		Value:      evidence.ServiceValue{UnitName: unit, MainPID: mainPID, ActiveState: "active"},
	}
}

func chain(pid int, exe, pkg, src string) evidence.TypedRecord[evidence.EvidenceChainValue] {
	return evidence.TypedRecord[evidence.EvidenceChainValue]{
		EvidenceID: "ev-chain",
		Value: evidence.EvidenceChainValue{
			EntityID: "chain:x",
			Binary: &evidence.ChainBinary{
				Path: exe, Exists: true,
				PackageOwner: &evidence.ChainPackageOwner{PackageManager: "dpkg", PackageName: pkg, Path: exe, Status: "observed"},
			},
			Package: &evidence.ChainPackage{Name: pkg, PackageManager: "dpkg", SourcePackage: src},
			Process: &evidence.ProcessValue{PID: pid, ExecutablePath: exe},
		},
	}
}

func hostPkg(name, src, ver string) pkgs.InstalledPackage {
	return pkgs.InstalledPackage{
		Scope: pkgs.ScopeHost, Ecosystem: "dpkg", Name: name,
		SourcePackage: src, RawVersion: ver, Architecture: "arm64",
		Source: pkgs.SourceRelationship{BinaryPackage: name, SourcePackage: src, Confidence: "direct"},
	}
}

func TestProcessToPackageCorrelation(t *testing.T) {
	pkgIdx := pkgs.NewIndex([]pkgs.InstalledPackage{hostPkg("cups-daemon", "cups", "2.4.1-1")})
	idx := Build(
		[]evidence.TypedRecord[evidence.ProcessValue]{proc(2948, "cupsd", "/usr/sbin/cupsd", false)},
		[]evidence.TypedRecord[evidence.ServiceValue]{svc("cups.service", 2948)},
		[]evidence.TypedRecord[evidence.EvidenceChainValue]{chain(2948, "/usr/sbin/cupsd", "cups-daemon", "cups")},
		nil, pkgIdx,
	)
	exp := idx.ExposureFor("cups-daemon", "cups")
	if !exp.Running {
		t.Fatal("cups must be observed running")
	}
	if len(exp.ProcessIDs) != 1 || exp.ProcessIDs[0] != "2948" {
		t.Errorf("pids=%v", exp.ProcessIDs)
	}
	if len(exp.Services) != 1 || exp.Services[0] != "cups.service" {
		t.Errorf("services=%v", exp.Services)
	}
	if exp.DeletedExecutable {
		t.Error("no deleted executable expected")
	}
}

func TestNotRunningPackage(t *testing.T) {
	idx := Build(nil, nil, nil, nil, pkgs.NewIndex(nil))
	if exp := idx.ExposureFor("openssh-client", "openssh"); exp.Running {
		t.Error("nothing is running")
	}
}

func TestDeletedExecutableDetected(t *testing.T) {
	idx := Build(
		[]evidence.TypedRecord[evidence.ProcessValue]{proc(100, "oldd", "/usr/sbin/oldd", true)},
		nil,
		[]evidence.TypedRecord[evidence.EvidenceChainValue]{chain(100, "/usr/sbin/oldd", "oldpkg", "oldsrc")},
		nil, pkgs.NewIndex(nil),
	)
	exp := idx.ExposureFor("oldpkg", "oldsrc")
	if !exp.Running || !exp.DeletedExecutable {
		t.Errorf("deleted executable must be detected: %+v", exp)
	}
	if len(idx.DeletedExecutables) != 1 {
		t.Errorf("deleted list=%d", len(idx.DeletedExecutables))
	}
}

// Kernel threads (no executable, no cmdline) are recognized and never
// correlated to packages.
func TestKernelThreads(t *testing.T) {
	idx := Build(
		[]evidence.TypedRecord[evidence.ProcessValue]{proc(2, "kthreadd", "", false)},
		nil, nil, nil, pkgs.NewIndex(nil),
	)
	pr := idx.ProcessesByPID[2]
	if pr == nil || !pr.KernelThread {
		t.Errorf("kthreadd must be marked as kernel thread: %+v", pr)
	}
	if len(idx.ProcessesByPackage) != 0 {
		t.Error("kernel threads must not map to packages")
	}
}

// PID collision between collection modules is noted, not silently merged.
func TestPIDReuseNoted(t *testing.T) {
	idx := Build(
		[]evidence.TypedRecord[evidence.ProcessValue]{
			proc(500, "a", "/bin/a", false),
			proc(500, "b", "/bin/b", false),
		},
		nil, nil, nil, pkgs.NewIndex(nil),
	)
	if len(idx.Notes) == 0 {
		t.Error("PID reuse must be noted")
	}
}

// A process whose chain is missing falls back to unambiguous name matching,
// marked inferred.
func TestInferredOwnershipFallback(t *testing.T) {
	pkgIdx := pkgs.NewIndex([]pkgs.InstalledPackage{hostPkg("nginx", "nginx", "1.18.0-1")})
	idx := Build(
		[]evidence.TypedRecord[evidence.ProcessValue]{proc(700, "nginx", "/usr/sbin/nginx", false)},
		nil, nil, nil, pkgIdx,
	)
	pr := idx.ProcessesByPID[700]
	if pr.PackageName != "nginx" || pr.OwnershipConfidence != "inferred" {
		t.Errorf("fallback ownership: %+v", pr)
	}
}

// Loaded shared libraries count as runtime use of the owning package.
func TestLoadedLibraryExposure(t *testing.T) {
	libs := []evidence.TypedRecord[evidence.LoadedLibrariesValue]{{
		EvidenceID: "ev-libs",
		Value: evidence.LoadedLibrariesValue{
			EntityID: "libs:process:2948",
			Interesting: []evidence.LoadedLibrary{{
				Path: "/usr/lib/libssl.so.3", PackageName: "libssl3",
				PackageManager: "dpkg", SourcePackage: "openssl", RawVersionString: "3.0.2-0ubuntu1.16",
			}},
		},
	}}
	idx := Build(nil, nil, nil, libs, pkgs.NewIndex(nil))
	exp := idx.ExposureFor("libssl3", "openssl")
	if !exp.Running {
		t.Error("loaded library must count as runtime use")
	}
	if len(exp.BinaryPaths) != 1 || exp.BinaryPaths[0] != "/usr/lib/libssl.so.3" {
		t.Errorf("paths=%v", exp.BinaryPaths)
	}
}
