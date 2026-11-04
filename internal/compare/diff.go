package compare

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/s4e-io/openness-resolver/internal/findings"
)

// findingsDoc is the subset of the resolver's findings.json we read back.
type findingsDoc struct {
	AssetID  string             `json:"asset_id"`
	Findings []findings.Finding `json:"findings"`
}

// ResolverView is the resolver side of the comparison, reduced to CVE sets.
type ResolverView struct {
	AssetID string
	// VulnerableHostCVEs are CVEs with a vulnerable/vulnerable_runtime state
	// in host scope (the only scope a credentialed host scan can see).
	VulnerableHostCVEs map[string]*findings.Finding
	// KernelCVEs is the subset of host CVEs attributed to the running kernel.
	KernelCVEs map[string]bool
	// ContainerCVEs are container-scope vulnerable CVEs (out of scope for a
	// host credentialed scan; tracked so they are not counted as misses).
	ContainerCVEs map[string]bool
	// FixedHostCVEs are CVEs the resolver decided are already fixed on the
	// host (used to explain Nessus-only findings).
	FixedHostCVEs map[string]bool
}

// LoadResolverView reads findings.json into CVE-indexed sets.
func LoadResolverView(path string) (*ResolverView, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc findingsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	v := &ResolverView{
		AssetID:            doc.AssetID,
		VulnerableHostCVEs: map[string]*findings.Finding{},
		KernelCVEs:         map[string]bool{},
		ContainerCVEs:      map[string]bool{},
		FixedHostCVEs:      map[string]bool{},
	}
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if f.CVEID == "" || !isCVE(f.CVEID) {
			continue
		}
		if f.Scope == "python_environment" {
			continue
		}
		switch f.Scope {
		case "container":
			if isVulnerable(f.State) {
				v.ContainerCVEs[f.CVEID] = true
			}
		default: // host
			switch {
			case isVulnerable(f.State):
				v.VulnerableHostCVEs[f.CVEID] = f
				if f.DetectionMethod == "ubuntu_running_kernel_fixed_version" {
					v.KernelCVEs[f.CVEID] = true
				}
			case f.State == findings.StateFixed:
				v.FixedHostCVEs[f.CVEID] = true
			}
		}
	}
	return v, nil
}

// Diff is the CVE-level comparison outcome for host scope.
type Diff struct {
	ResolverAsset     string `json:"resolver_asset"`
	NessusHost        string `json:"nessus_host"`
	NessusLocalChecks bool   `json:"nessus_local_checks_present"`
	NessusOS          string `json:"nessus_os,omitempty"`
	ComparedLocalOnly bool   `json:"compared_local_checks_only"`

	Agreement          []string `json:"agreement"`            // both flagged vulnerable
	OnlyResolver       []string `json:"only_resolver"`        // resolver vuln, Nessus silent
	OnlyNessus         []string `json:"only_nessus"`          // Nessus vuln, resolver silent
	OnlyResolverKernel []string `json:"only_resolver_kernel"` // subset of OnlyResolver

	// Explanations for only_nessus CVEs the resolver decided were fixed
	// (potential resolver false negatives worth inspecting).
	NessusVsResolverFixed []string `json:"nessus_flagged_resolver_fixed"`
	// only_nessus CVEs the resolver only saw in a container (scope mismatch,
	// not a real disagreement).
	NessusMatchedContainerOnly []string `json:"nessus_matched_container_only"`

	Counts map[string]int `json:"counts"`
}

// Compare produces the host-scope CVE diff. When localOnly is true, only
// Nessus CVEs backed by a credentialed local security check are compared.
func Compare(rv *ResolverView, nr *NessusResult, localOnly bool) *Diff {
	d := &Diff{
		ResolverAsset:     rv.AssetID,
		NessusHost:        nr.Host,
		NessusLocalChecks: nr.LocalChecksPresent,
		NessusOS:          nr.OSInfo,
		ComparedLocalOnly: localOnly,
		Counts:            map[string]int{},
	}
	nessusSet := map[string]bool{}
	for _, cve := range nr.CVESet(localOnly) {
		nessusSet[cve] = true
	}

	for cve := range rv.VulnerableHostCVEs {
		if nessusSet[cve] {
			d.Agreement = append(d.Agreement, cve)
		} else {
			d.OnlyResolver = append(d.OnlyResolver, cve)
			if rv.KernelCVEs[cve] {
				d.OnlyResolverKernel = append(d.OnlyResolverKernel, cve)
			}
		}
	}
	for cve := range nessusSet {
		if _, ok := rv.VulnerableHostCVEs[cve]; ok {
			continue
		}
		d.OnlyNessus = append(d.OnlyNessus, cve)
		if rv.FixedHostCVEs[cve] {
			d.NessusVsResolverFixed = append(d.NessusVsResolverFixed, cve)
		}
		if rv.ContainerCVEs[cve] {
			d.NessusMatchedContainerOnly = append(d.NessusMatchedContainerOnly, cve)
		}
	}

	for _, s := range []*[]string{&d.Agreement, &d.OnlyResolver, &d.OnlyNessus,
		&d.OnlyResolverKernel, &d.NessusVsResolverFixed, &d.NessusMatchedContainerOnly} {
		sort.Strings(*s)
	}

	d.Counts["resolver_vulnerable_host"] = len(rv.VulnerableHostCVEs)
	d.Counts["nessus_vulnerable_host"] = len(nessusSet)
	d.Counts["agreement"] = len(d.Agreement)
	d.Counts["only_resolver"] = len(d.OnlyResolver)
	d.Counts["only_resolver_kernel"] = len(d.OnlyResolverKernel)
	d.Counts["only_nessus"] = len(d.OnlyNessus)
	d.Counts["nessus_flagged_resolver_fixed"] = len(d.NessusVsResolverFixed)
	d.Counts["nessus_matched_container_only"] = len(d.NessusMatchedContainerOnly)
	d.Counts["resolver_container_vulnerable"] = len(rv.ContainerCVEs)
	return d
}

func isVulnerable(state string) bool {
	return state == findings.StateVulnerable || state == findings.StateVulnerableRuntime
}

// isCVE filters out USN-only finding ids (USNs without a CVE reference are
// keyed by the USN id, which Nessus does not emit as <cve>).
func isCVE(id string) bool {
	return len(id) > 4 && (id[:4] == "CVE-" || id[:4] == "cve-")
}
