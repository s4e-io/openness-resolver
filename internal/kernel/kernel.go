// Package kernel implements T06/T07: mapping the running kernel (uname -r)
// to the exact installed kernel image package and its source family, and
// enumerating installed-but-not-running kernels.
package kernel

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/pkgs"
)

// unameRe splits "6.8.0-106-generic" into version-ABI ("6.8.0-106") and
// flavour ("generic"). Kernel versions are not SemVer; only the vendor
// package version (e.g. "6.8.0-106.106~22.04.1") is ever compared, with dpkg
// semantics.
var unameRe = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)-(.+)$`)

// imageNameRe matches versioned kernel image package names
// ("linux-image-6.8.0-106-generic"), deliberately excluding meta-packages
// ("linux-image-generic-hwe-22.04"), which are not the running image.
var imageNameRe = regexp.MustCompile(`^linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+)-(.+)$`)

// InstalledImage is one versioned kernel image package on disk.
type InstalledImage struct {
	PackageName  string `json:"package_name"`
	VersionABI   string `json:"version_abi"` // e.g. 6.8.0-106
	Flavour      string `json:"flavour"`     // e.g. generic
	RawVersion   string `json:"raw_version"` // dpkg-comparable, e.g. 6.8.0-106.106~22.04.1
	SourceFamily string `json:"source_family"`
	Running      bool   `json:"running"`
	EvidenceID   string `json:"evidence_id"`
}

// Context is the canonical running-kernel model.
type Context struct {
	RunningKernel  string `json:"running_kernel"` // raw uname -r
	VersionABI     string `json:"version_abi"`
	Flavour        string `json:"flavour"`
	RebootRequired bool   `json:"reboot_required"`
	// SourceFamily is the unsigned kernel source package family the running
	// kernel belongs to (e.g. "linux", "linux-hwe-6.8", "linux-aws"), which
	// is the identity Ubuntu kernel advisories use.
	SourceFamily string `json:"source_family"`
	// PackageVersion is the dpkg-comparable version of the running kernel's
	// image/modules package.
	PackageVersion string `json:"package_version"`
	// EvidenceIDs of the packages that established the mapping.
	EvidenceIDs []string `json:"evidence_ids,omitempty"`

	InstalledImages []InstalledImage `json:"installed_images"`
	Notes           []string         `json:"notes,omitempty"`
}

// Build derives the kernel context from .openness kernel evidence and the host
// package index.
func Build(k *evidence.Kernel, pkgIndex *pkgs.Index) *Context {
	ctx := &Context{}
	if k == nil || k.RunningKernel == "" {
		ctx.Notes = append(ctx.Notes, "no running-kernel evidence collected")
		return ctx
	}
	ctx.RunningKernel = k.RunningKernel
	ctx.RebootRequired = k.RebootRequired

	m := unameRe.FindStringSubmatch(k.RunningKernel)
	if m == nil {
		ctx.Notes = append(ctx.Notes, fmt.Sprintf("running kernel %q does not match the Ubuntu uname pattern (custom/manually built kernel?)", k.RunningKernel))
		return ctx
	}
	ctx.VersionABI, ctx.Flavour = m[1], m[2]

	// Enumerate all versioned kernel images on disk (T07). Host scope only:
	// a kernel inside a container image is never the running kernel.
	for _, p := range pkgIndex.All {
		if p.Scope != pkgs.ScopeHost {
			continue
		}
		im := imageNameRe.FindStringSubmatch(p.Name)
		if im == nil || !p.Installed() {
			continue
		}
		fam, _ := SourceFamily(p.SourcePackage)
		img := InstalledImage{
			PackageName:  p.Name,
			VersionABI:   im[1],
			Flavour:      im[2],
			RawVersion:   p.RawVersion,
			SourceFamily: fam,
			Running:      im[1] == ctx.VersionABI && im[2] == ctx.Flavour,
			EvidenceID:   p.EvidenceID,
		}
		ctx.InstalledImages = append(ctx.InstalledImages, img)
	}

	// Map the running kernel to its package. The modules package carries the
	// unsigned source family directly; the image package may be signed.
	suffix := ctx.VersionABI + "-" + ctx.Flavour
	hostByName := pkgIndex.ByName[pkgs.HostScopeKey()]
	for _, name := range []string{"linux-modules-" + suffix, "linux-image-" + suffix, "linux-image-unsigned-" + suffix} {
		for _, p := range hostByName[name] {
			if !p.Installed() {
				continue
			}
			if ctx.PackageVersion == "" {
				ctx.PackageVersion = p.RawVersion
			}
			if ctx.SourceFamily == "" {
				if fam, ok := SourceFamily(p.SourcePackage); ok {
					ctx.SourceFamily = fam
				}
			}
			ctx.EvidenceIDs = append(ctx.EvidenceIDs, p.EvidenceID)
		}
	}
	if ctx.PackageVersion == "" {
		ctx.Notes = append(ctx.Notes, fmt.Sprintf("running kernel %s has no matching installed kernel package; kernel advisories cannot be evaluated deterministically", k.RunningKernel))
	}
	return ctx
}

// NewerInstalledImage returns an installed, not-running kernel image of the
// same source family whose version satisfies the fixed version (>= fixed),
// or nil. Used for the T07 "fixed kernel installed but vulnerable kernel
// still running" enrichment.
func (c *Context) NewerInstalledImage(fixedVersion string, cmp func(a, b string) (int, error)) *InstalledImage {
	for i := range c.InstalledImages {
		img := &c.InstalledImages[i]
		if img.Running || img.SourceFamily != c.SourceFamily {
			continue
		}
		r, err := cmp(img.RawVersion, fixedVersion)
		if err == nil && r >= 0 {
			return img
		}
	}
	return nil
}

// ParseImageName splits a versioned kernel image package into its ABI and flavour.
func ParseImageName(name string) (abi, flavour string, ok bool) {
	m := imageNameRe.FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ImagePackageName builds the package a fixed dpkg version installs.
// 6.8.0-110.110~22.04.1 with flavour generic is linux-image-6.8.0-110-generic.
// The running ABI package is a different package, so it cannot be upgraded into this one.
func ImagePackageName(fixedVersion, flavour string) (string, bool) {
	fixedVersion = strings.TrimSpace(fixedVersion)
	flavour = strings.TrimSpace(flavour)
	if fixedVersion == "" || flavour == "" {
		return "", false
	}
	if i := strings.IndexByte(fixedVersion, ':'); i >= 0 {
		fixedVersion = fixedVersion[i+1:]
	}
	dash := strings.LastIndex(fixedVersion, "-")
	if dash <= 0 || dash == len(fixedVersion)-1 {
		return "", false
	}
	upstream := fixedVersion[:dash]
	rev := fixedVersion[dash+1:]
	abiRev := rev
	for i, c := range rev {
		if c == '.' || c == '~' {
			abiRev = rev[:i]
			break
		}
	}
	if abiRev == "" {
		return "", false
	}
	for _, c := range abiRev {
		if !unicode.IsDigit(c) {
			return "", false
		}
	}
	name := "linux-image-" + upstream + "-" + abiRev + "-" + flavour
	if _, fl, ok := ParseImageName(name); !ok || fl != flavour {
		return "", false
	}
	return name, true
}
