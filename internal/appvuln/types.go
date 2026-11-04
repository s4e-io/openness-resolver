package appvuln

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
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

// MaxBundleSize is the largest mapper file LoadFile accepts, uncompressed. A larger file
// is refused before it is read in full.
var MaxBundleSize int64 = 256 << 20

// errTooLarge is returned by capReader once more than MaxBundleSize bytes were read.
var errTooLarge = errors.New("too large")

// capReader fails a read once more than max bytes came through it.
type capReader struct {
	r        io.Reader
	n, max   int64
	exceeded bool
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		c.exceeded = true
		return n, errTooLarge
	}
	return n, err
}

// LoadFile reads a mapper file (JSON or gzip JSON). It streams: the file is never held in
// memory as a whole, only the catalog and database it decodes into.
func LoadFile(path string) (*Data, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mapper: %w", err)
	}
	defer f.Close()
	d, err := LoadReader(f)
	if err != nil {
		return nil, fmt.Errorf("mapper %s: %w", path, err)
	}
	return d, nil
}

// LoadReader reads a mapper bundle from r, gzip or not, refusing one larger than
// MaxBundleSize uncompressed.
func LoadReader(r io.Reader) (*Data, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var src io.Reader = br
	if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		src = zr
	}
	cr := &capReader{r: src, max: MaxBundleSize}
	d, hasCatalog, hasVulns, fb, err := decodeBundle(json.NewDecoder(cr))
	if cr.exceeded {
		return nil, fmt.Errorf("bundle is larger than %d MB uncompressed; refused", MaxBundleSize>>20)
	}
	if err != nil {
		return nil, err
	}
	if !hasCatalog || !hasVulns {
		return nil, fmt.Errorf("catalog and vulns are required")
	}
	if err := d.compile(); err != nil {
		return nil, err
	}
	if fb != nil {
		d.fb = newFallback(*fb)
		return d, nil
	}
	bi, err := Builtin()
	if err != nil {
		return nil, err
	}
	d.fb = bi.fb
	return d, nil
}

// decodeBundle decodes a Bundle token by token: the catalog one entry at a time and the
// databases one product at a time, so no part of the file is buffered whole.
func decodeBundle(dec *json.Decoder) (d *Data, hasCatalog, hasVulns bool, fb *DB, err error) {
	d = &Data{}
	format := ""
	err = decodeObject(dec, func(key string) error {
		switch key {
		case "format":
			if err := dec.Decode(&format); err != nil {
				return err
			}
			if format != BundleFormat {
				return fmt.Errorf("format %q, want %q", format, BundleFormat)
			}
			return nil
		case "version":
			return dec.Decode(&d.Version)
		case "catalog":
			hasCatalog = true
			return decodeArray(dec, func() error {
				var p Product
				if err := dec.Decode(&p); err != nil {
					return fmt.Errorf("catalog: %w", err)
				}
				d.Catalog = append(d.Catalog, p)
				return nil
			})
		case "vulns":
			hasVulns = true
			if err := decodeDB(dec, &d.DB); err != nil {
				return fmt.Errorf("vulnerability db: %w", err)
			}
			return nil
		case "fallback":
			fb = &DB{}
			if err := decodeDB(dec, fb); err != nil {
				return fmt.Errorf("fallback db: %w", err)
			}
			return nil
		default:
			var skip json.RawMessage
			return dec.Decode(&skip)
		}
	})
	if err == nil && format != BundleFormat {
		err = fmt.Errorf("format %q, want %q", format, BundleFormat)
	}
	return d, hasCatalog, hasVulns, fb, err
}

// decodeDB decodes a DB with its products and titles streamed one entry at a time.
func decodeDB(dec *json.Decoder, db *DB) error {
	return decodeObject(dec, func(key string) error {
		switch key {
		case "version":
			return dec.Decode(&db.Version)
		case "products":
			db.Products = map[string][]Vuln{}
			return decodeObject(dec, func(k string) error {
				var vs []Vuln
				if err := dec.Decode(&vs); err != nil {
					return err
				}
				db.Products[k] = vs
				return nil
			})
		case "titles":
			db.Titles = map[string]string{}
			return decodeObject(dec, func(k string) error {
				var t string
				if err := dec.Decode(&t); err != nil {
					return err
				}
				db.Titles[k] = t
				return nil
			})
		default:
			var skip json.RawMessage
			return dec.Decode(&skip)
		}
	})
}

// decodeObject reads one JSON object and calls value for each key; value must consume the
// key's value from dec.
func decodeObject(dec *json.Decoder, value func(key string) error) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("unexpected %v", t)
		}
		if err := value(key); err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

// decodeArray reads one JSON array and calls value for each element.
func decodeArray(dec *json.Decoder, value func() error) error {
	if err := expectDelim(dec, '['); err != nil {
		return err
	}
	for dec.More() {
		if err := value(); err != nil {
			return err
		}
	}
	return expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, found %v", want, t)
	}
	return nil
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

// BundleMeta describes a mapper file that feed sync (or rules import) put in place. It is
// written next to the file as <file>.meta.json.
type BundleMeta struct {
	Source       string    `json:"source"`
	SourceURL    string    `json:"source_url"`
	DownloadedAt time.Time `json:"downloaded_at"`
	SHA256       string    `json:"sha256"`
	SizeBytes    int64     `json:"size_bytes"`
	Format       string    `json:"format"`
	Version      string    `json:"version"`
}

// MetaPath is where the metadata of the mapper file at path is kept.
func MetaPath(path string) string { return path + ".meta.json" }

// ReadMeta reads the metadata of the mapper file at path; ok is false when it has none.
func ReadMeta(path string) (BundleMeta, bool) {
	var m BundleMeta
	raw, err := os.ReadFile(MetaPath(path))
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return BundleMeta{}, false
	}
	return m, true
}
