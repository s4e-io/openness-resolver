// Package testfixtures builds synthetic .openness documents and vendor rules for
// unit and integration tests. Fixtures mirror the real collector schema
// (schema_version 1.3.x) observed in production evidence.
package testfixtures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// Doc is a builder for synthetic .openness documents.
type Doc struct {
	doc map[string]any
}

// NewUbuntuJammyARM64 creates a minimal Ubuntu 22.04 arm64 host document.
func NewUbuntuJammyARM64() *Doc {
	return &Doc{doc: map[string]any{
		"schema_version": "1.3.2",
		"collector":      map[string]any{"name": "openness-collector", "version": "test"},
		"collection":     map[string]any{"collection_id": "test", "status": "complete"},
		"asset": map[string]any{
			"asset_id": "asset-test", "hostname": "t", "platform": "linux", "architecture": "arm64",
		},
		"operating_system": map[string]any{
			"architecture":         "arm64",
			"distribution_id":      "ubuntu",
			"distribution_name":    "Ubuntu",
			"distribution_version": "22.04.4 LTS (Jammy Jellyfish)",
			"version_id":           "22.04",
			"kernel_version":       "6.8.0-106-generic",
		},
		"kernel": map[string]any{"running_kernel": "6.8.0-106-generic", "reboot_required": false},
	}}
}

// SetKernel overrides kernel fields.
func (d *Doc) SetKernel(fields map[string]any) *Doc {
	k, _ := d.doc["kernel"].(map[string]any)
	if k == nil {
		k = map[string]any{}
		d.doc["kernel"] = k
	}
	for key, v := range fields {
		k[key] = v
	}
	return d
}

// SetOS overrides operating_system fields.
func (d *Doc) SetOS(fields map[string]any) *Doc {
	os := d.doc["operating_system"].(map[string]any)
	for k, v := range fields {
		os[k] = v
	}
	return d
}

func (d *Doc) appendRecord(category string, value any) *Doc {
	rec := map[string]any{
		"evidence_id":       fmt.Sprintf("ev-%s-%d", category, d.count(category)),
		"source":            "native",
		"source_module":     category,
		"observed_at":       "2026-08-01T22:09:36Z",
		"value":             value,
		"collection_status": "observed",
	}
	list, _ := d.doc[category].([]any)
	d.doc[category] = append(list, rec)
	return d
}

// AddRawRecord appends a record whose value is used as given, for malformed
// record tests (a string, a number, an object of the wrong shape).
func (d *Doc) AddRawRecord(category string, value any) *Doc {
	return d.appendRecord(category, value)
}

// Set replaces a top-level field; nil writes JSON null.
func (d *Doc) Set(key string, value any) *Doc {
	d.doc[key] = value
	return d
}

// Delete removes a top-level field.
func (d *Doc) Delete(key string) *Doc {
	delete(d.doc, key)
	return d
}

func (d *Doc) count(category string) int {
	list, _ := d.doc[category].([]any)
	return len(list)
}

// PkgOpt customizes a package record.
type PkgOpt func(map[string]any)

// WithSource sets dpkg Source metadata (direct relationship).
func WithSource(src string) PkgOpt {
	return func(v map[string]any) {
		v["source_package"] = src
		v["relationships"] = []any{map[string]any{
			"confidence": "direct", "evidence_source": "dpkg:Source",
			"target_entity_id": "srcpkg:dpkg:" + src, "type": "package_built_from_source_package",
		}}
	}
}

// WithArch sets the package architecture.
func WithArch(arch string) PkgOpt {
	return func(v map[string]any) { v["architecture"] = arch }
}

// WithPackageManager sets the package manager (apk, rpm) of the record.
func WithPackageManager(pm string) PkgOpt {
	return func(v map[string]any) {
		v["package_manager"] = pm
		v["entity_id"] = "pkg:" + pm + ":" + v["name"].(string)
		v["package_status"] = "installed"
	}
}

// WithEpoch sets the epoch field.
func WithEpoch(e string) PkgOpt {
	return func(v map[string]any) { v["epoch"] = e }
}

// WithRepo sets repository provenance fields (T04/T05).
func WithRepo(origin, suite, component, url, metadataStatus string) PkgOpt {
	return func(v map[string]any) {
		v["repository_origin"] = origin
		v["repository_suite"] = suite
		v["repository_component"] = component
		v["repository_url"] = url
		v["repository_metadata_status"] = metadataStatus
	}
}

// AddPackage appends a dpkg host package record.
func (d *Doc) AddPackage(name, rawVersion string, opts ...PkgOpt) *Doc {
	v := map[string]any{
		"entity_id":          "pkg:dpkg:" + name,
		"entity_type":        "package",
		"name":               name,
		"architecture":       "arm64",
		"raw_version_string": rawVersion,
		"package_manager":    "dpkg",
		"package_status":     "install ok installed",
	}
	for _, o := range opts {
		o(v)
	}
	return d.appendRecord("packages", v)
}

// AddService appends a systemd service whose main PID is pid.
func (d *Doc) AddService(pid int, unit string) *Doc {
	name := unit
	if i := strings.LastIndex(unit, "."); i > 0 {
		name = unit[:i]
	}
	return d.appendRecord("services", map[string]any{
		"entity_id": "svc:" + unit, "entity_type": "service",
		"service_name": name, "unit_name": unit,
		"active_state": "active", "sub_state": "running",
		"main_pid": pid, "init_system": "systemd",
	})
}

// AddProcess appends a process record.
func (d *Doc) AddProcess(pid int, name, exePath string, deleted bool) *Doc {
	return d.appendRecord("processes", map[string]any{
		"entity_id": fmt.Sprintf("proc:%d", pid), "entity_type": "process",
		"pid": pid, "ppid": 1, "name": name,
		"command_line":        exePath,
		"executable_path":     exePath,
		"executable_realpath": exePath,
		"executable_deleted":  deleted,
	})
}

// AddChain appends an evidence chain linking a pid to a package.
func (d *Doc) AddChain(pid int, exePath, pkgName, srcPkg string) *Doc {
	return d.appendRecord("evidence_chains", map[string]any{
		"entity_id": fmt.Sprintf("chain:proc:%d", pid), "entity_type": "evidence_chain",
		"chain": []any{"process", "binary", "package"}, "complete": true,
		"binary": map[string]any{
			"entity_id": "bin:" + exePath, "path": exePath, "exists": true,
			"package_owner": map[string]any{
				"package_manager": "dpkg", "package_name": pkgName, "path": exePath, "status": "observed",
			},
		},
		"package": map[string]any{"name": pkgName, "package_manager": "dpkg", "source_package": srcPkg},
		"process": map[string]any{
			"entity_id": fmt.Sprintf("proc:%d", pid), "pid": pid, "name": pkgName,
			"executable_path": exePath, "executable_realpath": exePath,
		},
	})
}

// ContainerSpec describes a synthetic container.
type ContainerSpec struct {
	ID       string
	Name     string
	Digest   string
	ImageRef string
	State    string
	Packages [][3]string // name, version, package manager
}

// AddContainer appends a container record.
func (d *Doc) AddContainer(c ContainerSpec) *Doc {
	var pkgList []any
	for _, p := range c.Packages {
		pkgList = append(pkgList, map[string]any{
			"entity_id":          "pkg:container:" + p[2] + ":" + p[0] + ":" + p[1],
			"entity_type":        "package",
			"name":               p[0],
			"raw_version_string": p[1],
			"package_manager":    p[2],
			"packages_scope":     "container",
			"architecture":       "x86_64",
		})
	}
	return d.appendRecord("containers", map[string]any{
		"entity_id": "container:" + c.ID, "entity_type": "container",
		"container_id": c.ID, "name": c.Name, "runtime": "docker",
		"image_digest": c.Digest, "image_id": c.Digest, "image_reference": c.ImageRef,
		"identity_primary": "image_digest", "state": c.State,
		"package_count": len(pkgList), "package_source": "runtime_cp",
		"packages_scope": "container", "packages": pkgList,
	})
}

// Load parses the synthetic document through the production evidence loader.
func (d *Doc) Load() (*evidence.LoadResult, error) {
	data, err := json.Marshal(d.doc)
	if err != nil {
		return nil, err
	}
	return evidence.Parse(bytes.NewReader(data))
}

// JSON returns the raw document bytes.
func (d *Doc) JSON() []byte {
	data, _ := json.MarshalIndent(d.doc, "", " ")
	return data
}

// UbuntuRule builds a normalized Ubuntu rule for tests.
func UbuntuRule(cve, release, srcPkg, binPkg, status, fixedVersion string) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID:    fmt.Sprintf("ubuntu:%s:TEST:%s:%s:%s", release, cve, srcPkg, binPkg),
		Ecosystem: "dpkg", Vendor: "ubuntu", Distribution: "ubuntu",
		Release: release, PackageName: binPkg, SourcePackage: srcPkg,
		Status: status, RawStatus: status, FixedVersion: fixedVersion,
		Comparator: "dpkg", CVEID: cve, SourcePriority: 1,
	}
}

// UbuntuKernelRule builds a normalized kernel-flavour rule (T06).
func UbuntuKernelRule(cve, release, family, status, fixedVersion string) rules.PackageVulnerabilityRule {
	r := UbuntuRule(cve, release, family, "", status, fixedVersion)
	r.RuleID = fmt.Sprintf("ubuntu:%s:TEST:%s:kernel:%s", release, cve, family)
	r.IsKernel = true
	return r
}

// AlpineRule builds a normalized Alpine rule for tests.
func AlpineRule(cve, branch, pkg, status, fixedVersion string) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID:    fmt.Sprintf("alpine:%s:test:%s:%s:%s", branch, cve, pkg, fixedVersion),
		Ecosystem: "apk", Vendor: "alpine", Distribution: "alpine",
		Release: branch, PackageName: pkg, SourcePackage: pkg,
		Status: status, RawStatus: fixedVersion, FixedVersion: fixedVersion,
		Comparator: "apk", CVEID: cve, SourcePriority: 1,
	}
}

// AddLanguageDep appends a language_deps entity record.
func (d *Doc) AddLanguageDep(value map[string]any) *Doc {
	return d.appendRecord("language_deps", value)
}

// AddPythonDistribution adds a python_distribution language_deps record.
func (d *Doc) AddPythonDistribution(opts map[string]any) *Doc {
	v := map[string]any{
		"entity_type":         "python_distribution",
		"scope":               "host",
		"runtime_load_status": "installed_not_proven_loaded",
	}
	for k, val := range opts {
		v[k] = val
	}
	return d.AddLanguageDep(v)
}

// PyPIRule builds a normalized PyPI OSV rule for tests.
func PyPIRule(cve, pkg, advisoryID, status, fixedVersion string) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID:         fmt.Sprintf("osv:pypi:%s:%s:%s", pkg, cve, advisoryID),
		Ecosystem:      "pypi",
		Vendor:         "osv",
		Distribution:   "pypi",
		PackageName:    pkg,
		SourcePackage:  pkg,
		Status:         status,
		RawStatus:      advisoryID,
		FixedVersion:   fixedVersion,
		Comparator:     "pep440",
		CVEID:          cve,
		AdvisoryIDs:    []string{advisoryID},
		SourcePriority: 4,
	}
}

// RuleSet builds an indexed rule set from rules.
func RuleSet(ruleList ...rules.PackageVulnerabilityRule) *rules.RuleSet {
	rs := &rules.RuleSet{Rules: ruleList}
	rs.Reindex()
	return rs
}

// AddSoftwareInstance appends a collector software_inventory instance
// (schema 1.5.0 shape).
func (d *Doc) AddSoftwareInstance(value map[string]any) *Doc {
	if _, ok := value["entity_type"]; !ok {
		value["entity_type"] = "software_instance"
	}
	return d.appendRecord("software_inventory", value)
}

// NewWindowsServer2022 creates a minimal Windows Server 2022 amd64 host
// document in the collector 1.4.0+ os_inventory shape.
func NewWindowsServer2022(ubr string) *Doc {
	return &Doc{doc: map[string]any{
		"schema_version": "1.5.0",
		"collector":      map[string]any{"name": "openness", "version": "test"},
		"collection":     map[string]any{"collection_id": "test", "status": "complete", "privilege_level": "admin"},
		"asset": map[string]any{
			"asset_id": "asset-win", "hostname": "WIN", "platform": "windows", "architecture": "amd64",
		},
		"operating_system": map[string]any{
			"distribution_id":   "windows",
			"distribution_name": "Windows",
			"product_name":      "Microsoft Windows Server 2022 Datacenter",
			"display_version":   "21H2",
			"version_id":        "21H2",
			"build_number":      "20348",
			"ubr":               ubr,
			"os_build":          "20348." + ubr,
			"product_type":      3,
			"installation_type": "Server",
			"architecture":      "amd64",
		},
	}}
}

// MSRCRule builds a normalized MSRC winbuild rule for tests.
func MSRCRule(cve, product, arch, kb, fixedBuild string, restart bool) rules.PackageVulnerabilityRule {
	return rules.PackageVulnerabilityRule{
		RuleID: "msrc:" + cve + ":" + product + ":" + kb, Ecosystem: "winbuild", Vendor: "microsoft",
		Distribution: "windows", Release: product, Architecture: arch, PackageName: "windows",
		SourcePackage: product, Status: rules.StatusReleased, RawStatus: "Security Update",
		FixedVersion: fixedBuild, Comparator: "winbuild", CVEID: cve, AdvisoryIDs: []string{kb},
		SourcePriority: 1, RestartRequired: restart, Urgency: "important",
	}
}
