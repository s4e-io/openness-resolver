package appvuln

import (
	"fmt"
	"strings"
)

// A name match alone can be wrong: any program can be given the Add/Remove Programs name
// "Microsoft Silverlight". A catalog entry with Verify takes the name match only as a
// candidate and accepts it when a product-specific sign holds: the entry's Uninstall key or
// MSI ProductCode is one of ProductCodes, or the collector found File under its base folder
// with a valid Authenticode signature whose signer CN is Signer.

// Verify is a catalog entry's confirmation of a name match.
type Verify struct {
	ProductCodes []string    `json:"product_codes,omitempty"`
	File         *VerifyFile `json:"file,omitempty"`
}

// VerifyFile is a file of the product the collector checks (collect --file-probes).
type VerifyFile struct {
	// Path is relative to Base ("Microsoft Silverlight\\sllauncher.exe").
	Path string `json:"path"`
	// Base is install_location, program_files or display_icon_dir.
	Base string `json:"base"`
	// Signer is the CN of the Authenticode signer ("Microsoft Corporation").
	Signer string `json:"signer"`
	// VersionFromFile takes the version from the file (VS_FIXEDFILEINFO) instead of
	// the Add/Remove Programs DisplayVersion.
	VersionFromFile bool `json:"version_from_file,omitempty"`
}

// Match strengths: how an application was tied to its catalog entry.
const (
	StrengthSignature   = "signature"    // the product's signed file is there
	StrengthProductCode = "product_code" // the Uninstall key or ProductCode is the product's
	StrengthName        = "name"         // name (and publisher) only: the entry has no Verify
)

// AppVerifyFailed: the name matched a catalog entry with Verify, but no sign held.
const AppVerifyFailed = "verify_failed"

// fileCheck is one collector file_checks entry of an application.
type fileCheck struct {
	ProbeID         string `json:"probe_id"`
	Path            string `json:"path"`
	Exists          bool   `json:"exists"`
	FileVersion     string `json:"file_version"`
	SignatureStatus string `json:"signature_status"`
	SignerCN        string `json:"signer_cn"`
	Error           string `json:"error"`
}

// verify says how the application is tied to entry p and the file version when the entry
// takes the version from its file. It refuses (strength "") only when a sign was checked
// and did not hold; when nothing could be checked (a collector without file probes, an
// entry without an install location) the name match stands as StrengthName with a note.
// note is the refusal's reason, or what could not be confirmed.
func verify(p *Product, a app) (strength, fileVersion, note string) {
	if p.Verify == nil {
		return StrengthName, "", ""
	}
	for _, code := range p.Verify.ProductCodes {
		if code != "" && (strings.EqualFold(code, a.ProductCode) || strings.EqualFold(code, a.Key)) {
			return StrengthProductCode, "", ""
		}
	}
	var reasons []string
	checked := false
	if f := p.Verify.File; f != nil {
		for _, c := range a.FileChecks {
			if c.ProbeID != p.ID {
				continue
			}
			if c.Error != "" && !c.Exists {
				reasons = append(reasons, fmt.Sprintf("%s: %s", c.Path, c.Error))
				continue // not checked: no verdict from this file
			}
			checked = true
			switch {
			case !c.Exists:
				reasons = append(reasons, c.Path+" is not there")
			case c.SignatureStatus != "valid":
				reasons = append(reasons, fmt.Sprintf("%s signature is %s", c.Path, orNone(c.SignatureStatus)))
			case !strings.EqualFold(strings.TrimSpace(c.SignerCN), strings.TrimSpace(f.Signer)):
				reasons = append(reasons, fmt.Sprintf("%s is signed by %q, not %q", c.Path, c.SignerCN, f.Signer))
			default:
				if f.VersionFromFile {
					fileVersion = c.FileVersion
				}
				return StrengthSignature, fileVersion, ""
			}
		}
	}
	if len(p.Verify.ProductCodes) > 0 {
		reasons = append(reasons, "its uninstall key is none of the product's codes")
	}
	if checked || p.Verify.File == nil {
		return "", "", strings.Join(reasons, "; ")
	}
	return StrengthName, "", "not confirmed: the product's file could not be checked (" + orNone(strings.Join(reasons, "; ")) + ")"
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Probe is one file the collector is asked to check (collect --file-probes).
type Probe struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher,omitempty"`
	Path      string `json:"path"`
	Base      string `json:"base"`
}

// Probes lists the files of the catalog entries whose Verify names one, for the
// collector; name and publisher are the entries' own patterns.
func (d *Data) Probes() []Probe {
	out := []Probe{}
	for _, p := range d.Catalog {
		if p.Verify == nil || p.Verify.File == nil {
			continue
		}
		out = append(out, Probe{ID: p.ID, Name: p.Match.Name, Publisher: p.Match.Publisher,
			Path: p.Verify.File.Path, Base: p.Verify.File.Base})
	}
	return out
}
