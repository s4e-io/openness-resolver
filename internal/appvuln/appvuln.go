// Package appvuln finds the known vulnerabilities of third-party applications on Windows
// (Firefox, 7-Zip, Node.js and the like): what the OS feeds do not cover.
//
// Two data files drive it, both made by the desktop's cmd/cpegen: a catalog that ties how an
// application shows in Add/Remove Programs (name, publisher) to its NVD CPE product and
// says where its version is, and a vulnerability database with the CVEs and affected
// version ranges of those products, taken from the NVD. The package itself knows no
// application.
package appvuln

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/catalog.json data/vulns.json.gz data/fallback.json.gz
var dataFiles embed.FS

// Product is one catalog entry.
type Product struct {
	// ID is stable ("mozilla.firefox-esr"), the winget id when there is one.
	ID string `json:"id"`
	// Name is how findings and update cards name it.
	Name string `json:"name"`
	// Kind is "application" (the default when empty) or "device", a network device matched
	// against SNMP data (device.go). Entries of any other kind are ignored, so an older
	// build can read a newer catalog.
	Kind string `json:"kind,omitempty"`
	// Match selects Add/Remove Programs entries: Name (and Publisher, when set) are
	// case-insensitive regular expressions on the product name and the publisher; an entry
	// matching NotName is left out (Firefox ESR is not Firefox).
	Match struct {
		Name      string `json:"name,omitempty"`
		Publisher string `json:"publisher,omitempty"`
		NotName   string `json:"not_name,omitempty"`
		// A device entry matches the SNMP fields instead (case-insensitive regular
		// expressions; every one given must match): sysObjectID, sysDescr, the model
		// (entPhysicalModelName) and the vendor.
		SysObjectID string `json:"sys_object_id,omitempty"`
		SysDescr    string `json:"sys_descr,omitempty"`
		Model       string `json:"model,omitempty"`
		Vendor      string `json:"vendor,omitempty"`
	} `json:"match"`
	// Version says where the version is: "display_version" (default) or "product_name",
	// for a device "sys_descr" (default), "software_rev" or "firmware_rev",
	// optionally the first submatch of Regex, or Format filled from Regex's submatches
	// ("1.$3.0.$4" makes "Java 8 Update 401" the NVD form "1.8.0.401"), cut to Parts
	// dotted parts (0 keeps all).
	Version struct {
		From   string `json:"from,omitempty"`
		Regex  string `json:"regex,omitempty"`
		Format string `json:"format,omitempty"`
		Parts  int    `json:"parts,omitempty"`
	} `json:"version"`
	// CPE are the NVD products ("vendor:product") whose CVEs apply.
	CPE []string `json:"cpe"`
	// Update is the command hint of the update card ("winget upgrade --id Mozilla.Firefox.ESR").
	Update string `json:"update,omitempty"`
	// ExactUpTo: the vendor's CVEs name only the releases it still supported (Oracle's
	// Critical Patch Updates list "8u391, 8u401"), so an older release of the same line
	// (all parts but the last) is affected too.
	ExactUpTo bool `json:"exact_up_to,omitempty"`
	// SameBranch: the product keeps several release lines side by side (Firefox ESR 115,
	// 128 and 140) and the NVD does not say which line a range is for, so "< 128.4" would
	// reach 115.3 although only the 128 line had the bug. A range then counts only when its
	// upper bound is on the installed version's line (same first part).
	SameBranch bool `json:"same_branch,omitempty"`
	// Verify confirms a name match with a product-specific sign (verify.go); without it
	// the name and publisher decide alone.
	Verify *Verify `json:"verify,omitempty"`
	// Verified is a mapping a person checked; the others were matched by cpegen.
	Verified bool `json:"verified"`

	name, publisher, notName, version *regexp.Regexp
	device                            []deviceMatch
}

// Catalog entry kinds.
const (
	KindApplication = "application"
	KindDevice      = "device"
)

func (p *Product) isApp() bool    { return p.Kind == "" || p.Kind == KindApplication }
func (p *Product) isDevice() bool { return p.Kind == KindDevice }

// Range is one affected version range of a CPE in a CVE (NVD cpeMatch); an empty bound is
// open. Exact is a single affected version.
type Range struct {
	Exact     string `json:"v,omitempty"`
	StartIncl string `json:"si,omitempty"`
	StartExcl string `json:"se,omitempty"`
	EndIncl   string `json:"ei,omitempty"`
	EndExcl   string `json:"ee,omitempty"`
}

// Vuln is one CVE of a product.
type Vuln struct {
	CVE      string  `json:"cve"`
	CVSS     float64 `json:"cvss,omitempty"`
	Severity string  `json:"sev"`
	Ranges   []Range `json:"r"`
}

// DB holds the vulnerabilities of the catalog's products, by "vendor:product".
type DB struct {
	Version  string            `json:"version"`
	Products map[string][]Vuln `json:"products"`
	// Titles are the NVD product names, in the fallback database only.
	Titles map[string]string `json:"titles,omitempty"`
}

// Data is a loaded catalog and database, and the fallback database when there is one.
type Data struct {
	Catalog []Product
	DB      DB
	// Version names the data: the mapper file's version, or the database's.
	Version string
	fb      *fallback
}

var (
	builtinOnce sync.Once
	builtin     *Data
	builtinErr  error
)

// Builtin returns the catalog and database compiled into this build.
func Builtin() (*Data, error) {
	builtinOnce.Do(func() {
		cat, err := dataFiles.ReadFile("data/catalog.json")
		if err != nil {
			builtinErr = err
			return
		}
		db, err := readGz("data/vulns.json.gz")
		if err != nil {
			builtinErr = err
			return
		}
		if builtin, builtinErr = Load(cat, db); builtinErr != nil {
			return
		}
		builtin.Version = builtin.DB.Version
		fb, err := readGz("data/fallback.json.gz")
		if err != nil {
			builtinErr = err
			return
		}
		builtinErr = builtin.LoadFallback(fb)
	})
	return builtin, builtinErr
}

func readGz(name string) ([]byte, error) {
	return readGzFrom(dataFiles, name)
}

func readGzFrom(fsys embed.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

// LoadFallback parses the fallback database: NVD products outside the catalog, with their
// titles, for applications the catalog does not know.
func (d *Data) LoadFallback(db []byte) error {
	var fb DB
	if err := json.Unmarshal(db, &fb); err != nil {
		return fmt.Errorf("fallback db: %w", err)
	}
	d.fb = newFallback(fb)
	return nil
}

// Load parses a catalog and a database.
func Load(catalog, db []byte) (*Data, error) {
	d := &Data{}
	if err := json.Unmarshal(catalog, &d.Catalog); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := json.Unmarshal(db, &d.DB); err != nil {
		return nil, fmt.Errorf("vulnerability db: %w", err)
	}
	if err := d.compile(); err != nil {
		return nil, err
	}
	return d, nil
}

// compile checks the catalog entries and compiles their regular expressions. Entries of an
// unknown kind are dropped.
func (d *Data) compile() error {
	kept := d.Catalog[:0]
	for i := range d.Catalog {
		p := d.Catalog[i]
		switch {
		case p.isDevice():
			if err := p.compileDevice(); err != nil {
				return err
			}
		case p.isApp():
			if err := p.compileApp(); err != nil {
				return err
			}
		default:
			continue
		}
		kept = append(kept, p)
	}
	d.Catalog = kept
	return nil
}

func (p *Product) compileApp() error {
	{
		var err error
		if p.name, err = regexp.Compile("(?i)" + p.Match.Name); err != nil || p.Match.Name == "" {
			return fmt.Errorf("catalog %s: name: %v", p.ID, err)
		}
		if p.Match.Publisher != "" {
			if p.publisher, err = regexp.Compile("(?i)" + p.Match.Publisher); err != nil {
				return fmt.Errorf("catalog %s: publisher: %v", p.ID, err)
			}
		}
		if p.Match.NotName != "" {
			if p.notName, err = regexp.Compile("(?i)" + p.Match.NotName); err != nil {
				return fmt.Errorf("catalog %s: not_name: %v", p.ID, err)
			}
		}
		if p.Version.Regex != "" {
			if p.version, err = regexp.Compile(p.Version.Regex); err != nil {
				return fmt.Errorf("catalog %s: version: %v", p.ID, err)
			}
		} else if p.Version.Format != "" {
			return fmt.Errorf("catalog %s: version format without a regex", p.ID)
		}
	}
	return nil
}

// app is one installed application as the collector saw it.
type app struct {
	ProductName    string      `json:"product_name"`
	DisplayVersion string      `json:"display_version"`
	Publisher      string      `json:"publisher"`
	InstallPath    string      `json:"install_location"`
	Architecture   string      `json:"architecture"`
	InstallScope   string      `json:"install_scope"`
	ProductCode    string      `json:"product_code"`
	Key            string      `json:"key"`
	View           string      `json:"view"`
	DisplayIcon    string      `json:"display_icon"`
	FileChecks     []fileCheck `json:"file_checks"`
}

// Result is what one evidence document gave: the findings and an update card per
// application version.
type Result struct {
	Findings     []Finding
	Remediations []Remediation
	// Matched is how many installed applications the catalog knew; Guessed how many more
	// the fallback matched to an NVD product by name.
	Matched, Guessed int
	// Applications lists every application of the evidence with what the matcher made of it.
	Applications []Application
}

// Options say which matches count besides the verified catalog entries.
type Options struct {
	// Unverified uses the catalog entries no person checked.
	Unverified bool
	// Fallback guesses the NVD product of applications the catalog does not know; its
	// findings are potentially_vulnerable.
	Fallback bool
}

// Evaluate finds the vulnerable applications of one Windows evidence document.
func (d *Data) Evaluate(evidence []byte, opt Options) Result {
	var doc struct {
		OS struct {
			DistributionID string `json:"distribution_id"`
		} `json:"operating_system"`
		Applications []struct {
			Value json.RawMessage `json:"value"`
		} `json:"applications"`
	}
	if json.Unmarshal(evidence, &doc) != nil || !strings.EqualFold(doc.OS.DistributionID, "windows") {
		return Result{}
	}
	apps := make([]json.RawMessage, len(doc.Applications))
	for i, a := range doc.Applications {
		apps[i] = a.Value
	}
	return d.EvaluateApps(apps, opt)
}

// EvaluateApps finds the vulnerable applications among the collector's application
// records (their "value" objects) of one Windows host.
func (d *Data) EvaluateApps(values []json.RawMessage, opt Options) Result {
	var res Result
	list := make([]app, 0, len(values))
	for _, v := range values {
		var a app
		if json.Unmarshal(v, &a) == nil && strings.TrimSpace(a.ProductName) != "" {
			list = append(list, a)
		}
	}
	seen := map[string]bool{}
	// what the catalog reported, by "cpe|version", so a guess never repeats it (the parts
	// of a product, like Python's "Core Interpreter", carry the product's version)
	reported := map[string]bool{}
	type pending struct {
		a   app
		row int // position in res.Applications
	}
	var unknown []pending
	for _, a := range list {
		row := Application{Name: strings.TrimSpace(a.ProductName), Publisher: strings.TrimSpace(a.Publisher),
			Version: strings.TrimSpace(a.DisplayVersion), Architecture: a.Architecture, InstallScope: a.InstallScope,
			ProductCode: a.ProductCode, Key: a.Key, View: a.View, InstallPath: a.InstallPath, Status: AppUnmatched}
		p := d.match(a, opt.Unverified)
		if p == nil {
			if !opt.Unverified && d.match(a, true) != nil {
				row.Status = AppSkipped
			}
			res.Applications = append(res.Applications, row)
			if row.Status == AppUnmatched {
				unknown = append(unknown, pending{a, len(res.Applications) - 1})
			}
			continue
		}
		row.ProductID, row.CPE = p.ID, p.CPE
		strength, fileVer, note := verify(p, a)
		if strength == "" {
			row.Status, row.VerifyReason = AppVerifyFailed, note
			res.Applications = append(res.Applications, row)
			continue
		}
		row.MatchStrength, row.VerifyReason = strength, note
		ver := p.versionOf(a)
		if fileVer != "" {
			ver = p.cut(fileVer)
		}
		if ver == "" {
			row.Status = AppNoVersion
			res.Applications = append(res.Applications, row)
			continue
		}
		row.Status, row.MatchedVersion = AppMatched, ver
		key := p.ID + "|" + ver
		if !seen[key] {
			seen[key] = true
			res.Matched++
			before := len(res.Findings)
			d.vulns(p, ver, "host", &res.Findings, &res.Remediations)
			row.CVEs = len(res.Findings) - before
			for i := before; i < len(res.Findings); i++ {
				f := &res.Findings[i]
				f.MatchStrength = strength
				switch strength {
				case StrengthSignature:
					f.Reasons = append(f.Reasons, fmt.Sprintf("match confirmed by the product's file signed by %s", p.Verify.File.Signer))
				case StrengthProductCode:
					f.Reasons = append(f.Reasons, "match confirmed by the product's uninstall key")
				}
				if fileVer != "" {
					f.Reasons = append(f.Reasons, "version read from the product's file: "+fileVer)
				}
				if note != "" {
					f.Reasons = append(f.Reasons, "matched by name only, "+note)
				}
			}
			for _, c := range p.CPE {
				reported[c+"|"+ver] = true
			}
		}
		res.Applications = append(res.Applications, row)
	}
	if opt.Fallback && d.fb != nil {
		for _, u := range unknown {
			p := d.fb.match(u.a)
			if p == nil {
				continue
			}
			row := &res.Applications[u.row]
			ver := fallbackVersion(u.a)
			row.Status, row.ProductID, row.CPE, row.MatchedVersion = AppGuessed, p.key, []string{p.key}, ver
			key := p.key + "|" + ver
			if ver == "" || reported[key] || seen[key] {
				continue
			}
			seen[key] = true
			if f := d.fb.findings(p, u.a, ver); len(f) > 0 {
				res.Guessed++
				row.CVEs = len(f)
				res.Findings = append(res.Findings, f...)
			}
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].FindingID < res.Findings[j].FindingID })
	return res
}

func (d *Data) match(a app, unverified bool) *Product {
	if a.ProductName == "" {
		return nil
	}
	for i := range d.Catalog {
		p := &d.Catalog[i]
		if !p.isApp() || !p.Verified && !unverified {
			continue
		}
		if !p.name.MatchString(a.ProductName) {
			continue
		}
		if p.notName != nil && p.notName.MatchString(a.ProductName) {
			continue
		}
		if p.publisher != nil && !p.publisher.MatchString(a.Publisher) {
			continue
		}
		return p
	}
	return nil
}

func (p *Product) versionOf(a app) string {
	v := a.DisplayVersion
	if p.Version.From == "product_name" {
		v = a.ProductName
	}
	if p.version != nil {
		m := p.version.FindStringSubmatchIndex(v)
		if m == nil {
			return ""
		}
		switch {
		case p.Version.Format != "":
			v = string(p.version.ExpandString(nil, p.Version.Format, v, m))
		case len(m) > 2:
			if m[2] < 0 {
				return "" // the version group did not take part in the match
			}
			v = v[m[2]:m[3]]
		default:
			v = v[m[0]:m[1]]
		}
	}
	return p.cut(v)
}

// cut keeps the version's first Version.Parts dotted parts (0 keeps all).
func (p *Product) cut(v string) string {
	v = strings.TrimSpace(v)
	if p.Version.Parts > 0 {
		parts := strings.Split(v, ".")
		if len(parts) > p.Version.Parts {
			v = strings.Join(parts[:p.Version.Parts], ".")
		}
	}
	return v
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// vulns adds the findings of entry p at version ver, and its update card, for scope
// ("host" for an application, "network_device" for a device).
func (d *Data) vulns(p *Product, ver, scope string, out *[]Finding, cards *[]Remediation) {
	prefix, what := "app:", "application"
	if p.isDevice() {
		prefix, what = "device:", "device"
	}
	var cves []string
	worst, fixed := "", ""
	seen := map[string]bool{} // a CVE filed under two of the product's CPEs is one finding
	for _, cpe := range p.CPE {
		for _, v := range d.DB.Products[cpe] {
			rs := v.Ranges
			if p.SameBranch {
				rs = onBranch(ver, rs)
			}
			fix, hit := affected(ver, rs, p.ExactUpTo)
			if !hit || seen[v.CVE] {
				continue
			}
			seen[v.CVE] = true
			sev := strings.ToLower(v.Severity)
			if sev == "" {
				sev = "unknown"
			}
			f := Finding{
				FindingID: prefix + p.ID + ":" + ver + ":" + v.CVE, Scope: scope, State: "vulnerable", Severity: sev,
				CVEID: v.CVE, AdvisoryIDs: []string{}, BinaryPackage: p.Name, SourcePackage: p.ID,
				InstalledVersion: ver, FixedVersion: fix, CPE: cpe, Verified: p.Verified,
				Reasons: []string{fmt.Sprintf("%s %s is in an affected range of NVD cpe %s", p.Name, ver, cpe)},
			}
			if v.CVSS > 0 {
				score := v.CVSS
				f.CVSSScore = &score
			}
			if !p.Verified {
				f.Reasons = append(f.Reasons, what+" matched to the CPE automatically, not reviewed yet")
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
	if len(cves) == 0 {
		return
	}
	ids := make([]string, 0, len(cves))
	for _, f := range (*out)[len(*out)-len(cves):] {
		ids = append(ids, f.FindingID)
	}
	sort.Strings(ids)
	sort.Strings(cves)
	action := "Update " + p.Name
	if fixed != "" {
		action += " to " + fixed + " or later"
	}
	*cards = append(*cards, Remediation{
		GroupID: prefix + p.ID + ":" + ver, Action: action, Scope: scope, SourcePackage: p.ID,
		TargetsSummary: p.Name + " " + ver, ClosesCount: len(cves), CVEIDs: cves, AdvisoryIDs: []string{},
		Availability: "available", CommandHint: p.Update, MaxSeverity: worst,
		FindingIDs: ids, ProductName: p.Name, InstalledVersion: ver, FixedVersion: fixed,
	})
}

// onBranch keeps the ranges whose upper bound is on version v's line (its first part); a
// range without an upper bound, and an exact version, stay.
func onBranch(v string, rs []Range) []Range {
	line := firstPart(v)
	out := rs[:0:0]
	for _, r := range rs {
		end := r.EndExcl
		if end == "" {
			end = r.EndIncl
		}
		if r.Exact != "" || end == "" || firstPart(end) == line {
			out = append(out, r)
		}
	}
	return out
}

func firstPart(v string) string {
	if p := splitVer.FindString(v); p != "" {
		return strings.TrimLeft(p, "0")
	}
	return ""
}

// affected says whether version v falls in one of the ranges, and the version that fixes
// it (the excluded end of the range it is in) when the range has one. With upTo, an exact
// version also covers the older releases of its line.
func affected(v string, rs []Range, upTo bool) (string, bool) {
	for _, r := range rs {
		if r.Exact != "" {
			if Compare(v, r.Exact) == 0 || upTo && sameLine(v, r.Exact) && Compare(v, r.Exact) < 0 {
				return "", true
			}
			continue
		}
		if r.StartIncl != "" && Compare(v, r.StartIncl) < 0 {
			continue
		}
		if r.StartExcl != "" && Compare(v, r.StartExcl) <= 0 {
			continue
		}
		if r.EndIncl != "" && Compare(v, r.EndIncl) > 0 {
			continue
		}
		if r.EndExcl != "" && Compare(v, r.EndExcl) >= 0 {
			continue
		}
		if r.StartIncl == "" && r.StartExcl == "" && r.EndIncl == "" && r.EndExcl == "" {
			// "every version": too broad to report from one version string
			continue
		}
		return r.EndExcl, true
	}
	return "", false
}

// sameLine says whether two versions share all parts but the last: "1.8.0.202" and
// "1.8.0.401", "17.0.8" and "17.0.12".
func sameLine(a, b string) bool {
	pa, pb := splitVer.FindAllString(a, -1), splitVer.FindAllString(b, -1)
	if len(pb) < 2 || len(pa) < len(pb) {
		return false
	}
	for i := 0; i < len(pb)-1; i++ {
		if Compare(pa[i], pb[i]) != 0 {
			return false
		}
	}
	return true
}

var splitVer = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

// Compare orders two application versions: numeric parts as numbers, letters as text,
// missing parts as zero ("24.08" equals "24.08.00.0"). An empty version is the lowest.
func Compare(a, b string) int {
	if a == b {
		return 0
	}
	if b == "" {
		return 1
	}
	if a == "" {
		return -1
	}
	pa, pb := splitVer.FindAllString(a, -1), splitVer.FindAllString(b, -1)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		case ex == nil:
			return 1 // 1.0 > 1.0beta
		case ey == nil:
			return -1
		default:
			if c := strings.Compare(strings.ToLower(x), strings.ToLower(y)); c != 0 {
				return c
			}
		}
	}
	return 0
}
