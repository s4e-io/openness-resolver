package appvuln

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// AdvisoriesFormat is the format of the advisories file the Openness backend publishes
// in its data mirror (source "advisories"): security advisories written by Openness for
// products of the application catalog, used while the NVD has not analyzed their CVEs.
const AdvisoriesFormat = "openness-advisories/1"

// Advisory states. Only active advisories produce findings; a withdrawn one is kept in the
// file so a consumer can tell it apart from one it never saw.
const (
	AdvisoryActive    = "active"
	AdvisoryWithdrawn = "withdrawn"
)

// MaxAdvisoriesSize bounds the advisories file, uncompressed.
const MaxAdvisoriesSize = 16 << 20

// Advisory is one Openness advisory: the CVEs of one catalog product with their affected
// version ranges, in the mapper's range form.
type Advisory struct {
	// ID is the advisory's address on the website ("7-zip-before-26-06").
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
	ProductID string `json:"product_id"`
	Status    string `json:"status"`
	// Vulns are the CVEs with their ranges; Severity is the advisory's rating of each.
	Vulns     []Vuln `json:"vulns"`
	Published string `json:"published_at,omitempty"`
	Updated   string `json:"updated_at,omitempty"`
}

// Advisories is the advisories file.
type Advisories struct {
	Format     string     `json:"format"`
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
}

// LoadAdvisoriesFile reads an advisories file (JSON or gzip JSON).
func LoadAdvisoriesFile(path string) (*Advisories, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("advisories: %w", err)
	}
	defer f.Close()
	a, err := LoadAdvisories(f)
	if err != nil {
		return nil, fmt.Errorf("advisories %s: %w", path, err)
	}
	return a, nil
}

// LoadAdvisories reads an advisories file from r and checks it: the format, and that every
// advisory names a product and has CVEs with at least one bounded range.
func LoadAdvisories(r io.Reader) (*Advisories, error) {
	br := bufio.NewReader(r)
	var src io.Reader = br
	if head, _ := br.Peek(2); len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		src = zr
	}
	cr := &capReader{r: src, max: MaxAdvisoriesSize}
	var a Advisories
	err := json.NewDecoder(cr).Decode(&a)
	if cr.exceeded {
		return nil, fmt.Errorf("larger than %d MB uncompressed; refused", MaxAdvisoriesSize>>20)
	}
	if err != nil {
		return nil, err
	}
	if a.Format != AdvisoriesFormat {
		return nil, fmt.Errorf("format %q, want %q", a.Format, AdvisoriesFormat)
	}
	for i := range a.Advisories {
		adv := &a.Advisories[i]
		if strings.TrimSpace(adv.ID) == "" || strings.TrimSpace(adv.ProductID) == "" {
			return nil, fmt.Errorf("advisory %d: id and product_id are required", i)
		}
		if adv.Status == "" {
			adv.Status = AdvisoryActive
		}
	}
	return &a, nil
}

// SetAdvisories attaches the advisories to the mapper data: their CVEs are reported for the
// catalog products they name, unless the NVD data already reports the same CVE for that
// application (the NVD then covers it). Nil removes them.
func (d *Data) SetAdvisories(a *Advisories) {
	d.advisories = map[string][]*Advisory{}
	d.AdvisoriesVersion = ""
	if a == nil {
		return
	}
	d.AdvisoriesVersion = a.Version
	for i := range a.Advisories {
		adv := &a.Advisories[i]
		if adv.Status != AdvisoryActive {
			continue
		}
		d.advisories[adv.ProductID] = append(d.advisories[adv.ProductID], adv)
	}
}

// advisoryVulns adds the findings of the active advisories of entry p at version ver, for
// the CVEs the NVD did not report (seen). It returns the CVEs it added.
func (d *Data) advisoryVulns(p *Product, ver, scope string, seen map[string]bool, out *[]Finding) (cves []string, worst, fixed string) {
	for _, adv := range d.advisories[p.ID] {
		for _, v := range adv.Vulns {
			if seen[v.CVE] {
				continue
			}
			fix, hit := affected(ver, v.Ranges, false)
			if !hit {
				continue
			}
			seen[v.CVE] = true
			sev := strings.ToLower(v.Severity)
			if sev == "" {
				sev = "unknown"
			}
			f := Finding{
				FindingID: "app:" + p.ID + ":" + ver + ":" + v.CVE, Scope: scope, State: "vulnerable", Severity: sev,
				CVEID: v.CVE, AdvisoryIDs: []string{adv.ID}, BinaryPackage: p.Name, SourcePackage: p.ID,
				InstalledVersion: ver, FixedVersion: fix, Verified: p.Verified,
				Advisory: adv.ID, AdvisoryURL: adv.URL,
				Reasons: []string{fmt.Sprintf("%s %s is in an affected range of Openness advisory %s; the NVD has not listed this version yet", p.Name, ver, adv.ID)},
			}
			if v.CVSS > 0 {
				score := v.CVSS
				f.CVSSScore = &score
			}
			if !p.Verified {
				f.Reasons = append(f.Reasons, "application matched to the catalog automatically, not reviewed yet")
			}
			*out = append(*out, f)
			cves = append(cves, v.CVE)
			if sevRank[sev] > sevRank[worst] {
				worst = sev
			}
			if fix != "" && Compare(fix, fixed) > 0 {
				fixed = fix
			}
		}
	}
	return cves, worst, fixed
}
