// Package containers implements Task 8 of the resolver backlog: immutable
// container identity based on the image digest.
//
// Rules enforced here:
//   - The image digest is the primary identity; tags are never used as
//     identity (mutable).
//   - Host packages and container packages are never merged.
//   - Containers sharing an image digest share image-level findings.
//   - A missing digest makes the container's packages unresolvable at image
//     level; findings degrade to unknown identity instead of guessing.
package containers

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// ContainerContext is the canonical container model.
type ContainerContext struct {
	ContainerID    string `json:"container_id"`
	Name           string `json:"name"`
	Runtime        string `json:"runtime"`
	ImageDigest    string `json:"image_digest"`
	ImageReference string `json:"image_reference"` // informational only, never identity
	State          string `json:"state"`
	RootFSPath     string `json:"rootfs_path"`
	EvidenceID     string `json:"evidence_id"`

	// Distro is the inferred container distribution ("alpine", ...).
	Distro string `json:"distro"`
	// Branch is the inferred release branch (e.g. "v3.18").
	Branch string `json:"branch"`
	// BranchConfidence is "inferred" (anchor packages) or "" when unknown.
	BranchConfidence string `json:"branch_confidence"`
	BranchEvidence   string `json:"branch_evidence,omitempty"`

	PackageCount int  `json:"package_count"`
	HasPackageDB bool `json:"has_package_db"`
}

// ImageGroup groups containers that share one image digest. Image-level
// findings are produced once per group and reference all container ids.
type ImageGroup struct {
	ImageDigest      string             `json:"image_digest"`
	Containers       []ContainerContext `json:"containers"`
	Packages         []pkgs.InstalledPackage
	Distro           string `json:"distro"`
	Branch           string `json:"branch"`
	BranchConfidence string `json:"branch_confidence"`
}

// Inventory is the container-scope view of one .openness document.
type Inventory struct {
	Groups []*ImageGroup
	// MissingDigest lists containers without a usable image digest.
	MissingDigest []ContainerContext
	// PackageErrors counts container package entries that failed conversion.
	PackageErrors []string
}

// anchorVersions maps versions of anchor packages to Alpine branches.
// Deterministic inference only: if anchors disagree or are absent the branch
// stays unknown and findings become state=unknown rather than guessed.
var alpineBaselayoutBranches = map[string]string{
	"3.2.0": "v3.14", // 3.13/3.14 disambiguated via busybox below
	"3.4.0": "v3.17",
	"3.4.3": "v3.18", // -r1 => 3.18, -r2 => 3.19 (handled below)
	"3.6.5": "v3.20",
	"3.6.8": "v3.21",
}

// inferAlpineBranch determines the Alpine branch from anchor package
// versions found in the container package list.
func inferAlpineBranch(packages []evidence.ContainerPackage) (branch, confidence, evidenceNote string) {
	anchors := map[string]string{}
	for _, p := range packages {
		switch p.Name {
		case "alpine-baselayout", "apk-tools", "musl", "busybox":
			anchors[p.Name] = p.RawVersionString
		}
	}
	if bl, ok := anchors["alpine-baselayout"]; ok {
		base, rev := splitAPKRevision(bl)
		switch {
		case base == "3.4.3" && rev == "r1":
			return "v3.18", "inferred", "alpine-baselayout=" + bl
		case base == "3.4.3" && rev == "r2":
			return "v3.19", "inferred", "alpine-baselayout=" + bl
		case base == "3.2.0":
			// 3.13 and 3.14 share baselayout 3.2.0; busybox disambiguates.
			if bb, ok := anchors["busybox"]; ok {
				bbBase, _ := splitAPKRevision(bb)
				if strings.HasPrefix(bbBase, "1.33.") {
					return "v3.14", "inferred", fmt.Sprintf("alpine-baselayout=%s busybox=%s", bl, bb)
				}
				if strings.HasPrefix(bbBase, "1.32.") {
					return "v3.13", "inferred", fmt.Sprintf("alpine-baselayout=%s busybox=%s", bl, bb)
				}
			}
			return "", "", "alpine-baselayout=3.2.0 ambiguous (3.13/3.14), busybox anchor missing"
		default:
			if b, ok := alpineBaselayoutBranches[base]; ok {
				return b, "inferred", "alpine-baselayout=" + bl
			}
		}
	}
	// Secondary anchor: apk-tools minor versions are branch-specific.
	if at, ok := anchors["apk-tools"]; ok {
		base, rev := splitAPKRevision(at)
		switch {
		case base == "2.14.0" && (rev == "r0" || rev == "r1" || rev == "r2" || rev == "r3"):
			return "v3.18", "inferred", "apk-tools=" + at
		case base == "2.14.0":
			return "v3.19", "inferred", "apk-tools=" + at
		case strings.HasPrefix(base, "2.12."):
			return "v3.14", "inferred", "apk-tools=" + at
		case strings.HasPrefix(base, "2.10."):
			return "v3.12", "inferred", "apk-tools=" + at
		}
	}
	return "", "", "no usable anchor package (alpine-baselayout/apk-tools)"
}

func splitAPKRevision(v string) (base, rev string) {
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// detectDistro identifies the container distro from its package manager mix.
func detectDistro(packages []evidence.ContainerPackage) string {
	counts := map[string]int{}
	for _, p := range packages {
		counts[strings.ToLower(p.PackageManager)]++
	}
	switch {
	case counts["apk"] > 0 && counts["dpkg"] == 0 && counts["rpm"] == 0:
		return "alpine"
	case counts["dpkg"] > 0:
		return "debian-family" // ubuntu vs debian requires os-release evidence
	case counts["rpm"] > 0:
		return "rpm-family"
	default:
		return ""
	}
}

// BuildInventory converts container records into digest-grouped inventory.
func BuildInventory(records []evidence.TypedRecord[evidence.ContainerValue]) *Inventory {
	inv := &Inventory{}
	groups := map[string]*ImageGroup{}

	for _, rec := range records {
		v := rec.Value
		ctx := ContainerContext{
			ContainerID:    v.ContainerID,
			Name:           v.Name,
			Runtime:        v.Runtime,
			ImageDigest:    v.ImageDigest,
			ImageReference: v.ImageReference,
			State:          v.State,
			RootFSPath:     v.RootFSPath,
			EvidenceID:     rec.EvidenceID,
			PackageCount:   v.PackageCount,
			HasPackageDB:   len(v.Packages) > 0,
		}
		ctx.Distro = detectDistro(v.Packages)
		if ctx.Distro == "alpine" {
			ctx.Branch, ctx.BranchConfidence, ctx.BranchEvidence = inferAlpineBranch(v.Packages)
		}

		if !strings.HasPrefix(v.ImageDigest, "sha256:") {
			inv.MissingDigest = append(inv.MissingDigest, ctx)
			continue
		}
		g, ok := groups[v.ImageDigest]
		if !ok {
			g = &ImageGroup{ImageDigest: v.ImageDigest}
			groups[v.ImageDigest] = g
			inv.Groups = append(inv.Groups, g)
			// Packages come from the first container carrying a package DB;
			// same digest => same image content.
			for _, cp := range v.Packages {
				ip, err := pkgs.FromContainerPackage(cp, v.ImageDigest, rec.EvidenceID)
				if err != nil {
					inv.PackageErrors = append(inv.PackageErrors, err.Error())
					continue
				}
				g.Packages = append(g.Packages, ip)
			}
		}
		g.Containers = append(g.Containers, ctx)
		if g.Distro == "" {
			g.Distro = ctx.Distro
		}
		if g.Branch == "" && ctx.Branch != "" {
			g.Branch = ctx.Branch
			g.BranchConfidence = ctx.BranchConfidence
		}
	}
	return inv
}

// ContainerIDs lists the container ids of a group (for finding references).
func (g *ImageGroup) ContainerIDs() []string {
	var out []string
	for _, c := range g.Containers {
		out = append(out, c.ContainerID)
	}
	return out
}

// RunningContainerIDs lists ids of currently running containers in a group.
func (g *ImageGroup) RunningContainerIDs() []string {
	var out []string
	for _, c := range g.Containers {
		if c.State == "running" {
			out = append(out, c.ContainerID)
		}
	}
	return out
}
