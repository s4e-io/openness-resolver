package appvuln

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Finding is one CVE of one installed application. The resolver turns it into a
// findings.Finding; the fields keep the names the desktop used when the matcher lived there.
type Finding struct {
	FindingID        string
	Scope            string
	State            string // vulnerable (catalog) or potentially_vulnerable (fallback guess)
	Severity         string
	CVEID            string
	AdvisoryIDs      []string
	BinaryPackage    string // the application as it is named
	SourcePackage    string // catalog id, or the guessed "vendor:product"
	InstalledVersion string
	FixedVersion     string
	CVSSScore        *float64
	Reasons          []string
	// CPE is the NVD product the CVE was found under; Verified says a person checked the
	// catalog entry; Guess marks a fallback finding.
	CPE      string
	Verified bool
	Guess    bool
	// MatchStrength is signature, product_code or name (a fallback guess has none).
	MatchStrength string
}

// Remediation is the update card of one application version.
type Remediation struct {
	GroupID          string
	Action           string
	Scope            string
	SourcePackage    string
	TargetsSummary   string
	ClosesCount      int
	CVEIDs           []string
	AdvisoryIDs      []string
	Availability     string
	CommandHint      string
	MaxSeverity      string
	FindingIDs       []string
	ProductName      string
	InstalledVersion string
	FixedVersion     string
}

// Application match statuses.
const (
	AppMatched   = "matched"    // a catalog entry
	AppGuessed   = "guessed"    // the fallback matched an NVD product by name
	AppUnmatched = "unmatched"  // neither: nothing is known about its vulnerabilities
	AppNoVersion = "no_version" // matched, but its version could not be read
	AppSkipped   = "unverified" // only an unverified catalog entry matched and those are off
	// AppVerifyFailed (verify.go): the name matched but the product's sign did not hold
)

// Application is one installed application and what the matcher made of it. Every
// application of the evidence is listed, so a consumer can report the ones nothing matched.
type Application struct {
	Name         string `json:"name"`
	Publisher    string `json:"publisher,omitempty"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	InstallScope string `json:"install_scope,omitempty"`
	ProductCode  string `json:"product_code,omitempty"`
	Key          string `json:"key,omitempty"`
	View         string `json:"view,omitempty"`
	InstallPath  string `json:"install_location,omitempty"`
	Status       string `json:"status"`
	// MatchStrength is how a matched application was tied to its entry: signature,
	// product_code or name. VerifyReason says why a verify_failed one was refused.
	MatchStrength string   `json:"match_strength,omitempty"`
	VerifyReason  string   `json:"verify_reason,omitempty"`
	ProductID     string   `json:"product_id,omitempty"`
	CPE           []string `json:"cpe,omitempty"`
	// MatchedVersion is the version as the catalog reads it ("1.8.0.401" for Java 8u401).
	MatchedVersion string `json:"matched_version,omitempty"`
	CVEs           int    `json:"cves"`
}

// BundleFormat is the format id of a mapper file.
const BundleFormat = "openness-app-mapper/1"

// Bundle is a mapper file (resolve --mapper): the catalog, the vulnerability database of
// its products and, optionally, the fallback database, in one JSON document (gzip or not).
// A bundle without a fallback keeps the built-in one.
type Bundle struct {
	Format   string          `json:"format"`
	Version  string          `json:"version"`
	Catalog  json.RawMessage `json:"catalog"`
	Vulns    json.RawMessage `json:"vulns"`
	Fallback json.RawMessage `json:"fallback,omitempty"`
}

// LoadFile reads a mapper file.
func LoadFile(path string) (*Data, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mapper: %w", err)
	}
	if bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("mapper %s: %w", path, err)
		}
		if raw, err = io.ReadAll(zr); err != nil {
			return nil, fmt.Errorf("mapper %s: %w", path, err)
		}
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("mapper %s: %w", path, err)
	}
	if b.Format != BundleFormat {
		return nil, fmt.Errorf("mapper %s: format %q, want %q", path, b.Format, BundleFormat)
	}
	if len(b.Catalog) == 0 || len(b.Vulns) == 0 {
		return nil, fmt.Errorf("mapper %s: catalog and vulns are required", path)
	}
	d, err := Load(b.Catalog, b.Vulns)
	if err != nil {
		return nil, fmt.Errorf("mapper %s: %w", path, err)
	}
	d.Version = b.Version
	if len(b.Fallback) > 0 {
		if err := d.LoadFallback(b.Fallback); err != nil {
			return nil, fmt.Errorf("mapper %s: %w", path, err)
		}
		return d, nil
	}
	bi, err := Builtin()
	if err != nil {
		return nil, err
	}
	d.fb = bi.fb
	return d, nil
}

// WriteBundle writes the data a mapper file needs: the inverse of LoadFile for the files
// cmd/cpegen produces. fallback may be nil.
func WriteBundle(w io.Writer, version string, catalog, vulns, fallback []byte) error {
	b := Bundle{Format: BundleFormat, Version: version, Catalog: catalog, Vulns: vulns}
	if len(fallback) > 0 {
		b.Fallback = fallback
	}
	return json.NewEncoder(w).Encode(b)
}
