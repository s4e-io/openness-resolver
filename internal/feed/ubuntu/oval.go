// Package ubuntu parses Canonical's machine-readable OVAL security data
// (https://security-metadata.canonical.com/oval/) into normalized package
// rules. This is the priority-1 source for Ubuntu package decisions; NVD is
// never used as the primary Ubuntu source.
//
// OVAL structure handled here:
//
//	definition (class=patch)
//	  -> criterion(test_ref)               ["src package in pocket/release ..."]
//	       -> dpkginfo_test(object,state)
//	            object -> variable         [binary package names]
//	            state  -> debian_evr       [fixed version, operation]
//
// Raw vendor wording (criterion comments, statuses, notes) is preserved on
// every rule. Records that cannot be interpreted are rejected with a reason
// and counted — never silently skipped.
package ubuntu

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/rules"
)

// ParserVersion is recorded in feed metadata for traceability.
const ParserVersion = "ubuntu-oval/1.1.0" // 1.1.0: kernel-flavour rules (T06)

// --- XML models (subset of OVAL we consume) ---

type ovalDefinition struct {
	ID       string `xml:"id,attr"`
	Class    string `xml:"class,attr"`
	Metadata struct {
		Title       string `xml:"title"`
		Description string `xml:"description"`
		References  []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
			RefURL string `xml:"ref_url,attr"`
		} `xml:"reference"`
		Advisory struct {
			Severity string `xml:"severity"`
			Issued   struct {
				Date string `xml:"date,attr"`
			} `xml:"issued"`
			CVEs []struct {
				Text     string `xml:",chardata"`
				Priority string `xml:"priority,attr"`
				USNs     string `xml:"usns,attr"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}

type ovalCriteria struct {
	Operator   string          `xml:"operator,attr"`
	Criteria   []ovalCriteria  `xml:"criteria"`
	Criterions []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

func (c ovalCriteria) flatten() []ovalCriterion {
	out := append([]ovalCriterion{}, c.Criterions...)
	for _, sub := range c.Criteria {
		out = append(out, sub.flatten()...)
	}
	return out
}

type dpkgTest struct {
	ID        string `xml:"id,attr"`
	ObjectRef struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	StateRef struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type dpkgObject struct {
	ID   string `xml:"id,attr"`
	Name struct {
		VarRef string `xml:"var_ref,attr"`
		Value  string `xml:",chardata"`
	} `xml:"name"`
}

type dpkgState struct {
	ID  string `xml:"id,attr"`
	EVR struct {
		Operation string `xml:"operation,attr"`
		DataType  string `xml:"datatype,attr"`
		Value     string `xml:",chardata"`
	} `xml:"evr"`
}

type constantVariable struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

// ParseResult carries normalized rules plus ingestion metrics.
type ParseResult struct {
	Rules   []rules.PackageVulnerabilityRule
	Metrics feed.Metrics
	// Unsupported lists distinct unsupported structures encountered
	// (e.g. kernel uname tests) for reporting.
	Unsupported []string
}

// criterion comment: "<src> [source ]package in [tier/]<release>[,] <status text> [(note: '<version>')]"
var commentRe = regexp.MustCompile(`^(\S+)\s+(?:source\s+)?package\s+in\s+(\S+?)[,\s]\s*(.+?)\.?$`)

// kernel criterion comment: "'linux-gcp' kernel in jammy was vulnerable but
// has been fixed (note: '...')". These become IsKernel rules keyed by the
// kernel source family; the engine evaluates them against the running
// kernel (T06), never against ordinary installed packages.
var kernelCommentRe = regexp.MustCompile(`^'([^']+)'\s+kernel\s+in\s+(\S+?)[,\s]\s*(.+?)\.?$`)
var noteRe = regexp.MustCompile(`\(note:\s*'([^']*)'\)`)

// normalizeStatus maps Canonical status wording to normalized statuses.
// The raw wording is preserved separately on the rule.
func normalizeStatus(text string) string {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "has been fixed"):
		return rules.StatusReleased
	case strings.Contains(t, "needs fixing"), strings.Contains(t, "is needed"):
		return rules.StatusNeeded
	case strings.Contains(t, "defer"):
		return rules.StatusDeferred
	case strings.Contains(t, "not affected"), strings.Contains(t, "not vulnerable"):
		return rules.StatusNotAffected
	case strings.Contains(t, "does not exist"):
		return rules.StatusDoesNotExist
	case strings.Contains(t, "ignored"), strings.Contains(t, "end of standard support"), strings.Contains(t, "out of standard support"):
		return rules.StatusIgnored
	default:
		return rules.StatusUnknown
	}
}

// releaseAndTier splits "esm-apps/jammy" into ("jammy", "esm-apps").
func releaseAndTier(s string) (release, tier string) {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:], s[:i]
	}
	return s, ""
}

// ParseFile parses a (possibly bz2-compressed) Ubuntu OVAL file.
func ParseFile(path string, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".bz2") {
		r = bzip2.NewReader(f)
	}
	return Parse(r, meta)
}

// Parse consumes an OVAL XML stream and produces normalized rules.
func Parse(r io.Reader, meta rules.FeedSourceMetadata) (*ParseResult, error) {
	res := &ParseResult{}
	dec := xml.NewDecoder(r)

	var definitions []ovalDefinition
	tests := map[string]dpkgTest{}
	objects := map[string]dpkgObject{}
	states := map[string]dpkgState{}
	variables := map[string][]string{}
	unsupportedTests := map[string]string{} // test id -> element name

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("oval xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "definition":
			var d ovalDefinition
			if err := dec.DecodeElement(&d, &se); err != nil {
				res.Metrics.Reject("definition_decode_error")
				continue
			}
			if d.Class == "patch" {
				definitions = append(definitions, d)
				res.Metrics.RecordsDownloaded++
			}
		case "dpkginfo_test":
			var t dpkgTest
			if err := dec.DecodeElement(&t, &se); err != nil {
				res.Metrics.Reject("test_decode_error")
				continue
			}
			tests[t.ID] = t
		case "dpkginfo_object":
			var o dpkgObject
			if err := dec.DecodeElement(&o, &se); err != nil {
				res.Metrics.Reject("object_decode_error")
				continue
			}
			objects[o.ID] = o
		case "dpkginfo_state":
			var s dpkgState
			if err := dec.DecodeElement(&s, &se); err != nil {
				res.Metrics.Reject("state_decode_error")
				continue
			}
			states[s.ID] = s
		case "constant_variable":
			var v constantVariable
			if err := dec.DecodeElement(&v, &se); err != nil {
				res.Metrics.Reject("variable_decode_error")
				continue
			}
			variables[v.ID] = v.Values
		case "uname_test", "textfilecontent54_test", "family_test", "variable_test":
			// Non-dpkg test types (kernel uname checks etc.). Record the id
			// so criteria referencing them are rejected with a clear reason.
			var generic struct {
				ID string `xml:"id,attr"`
			}
			if err := dec.DecodeElement(&generic, &se); err == nil {
				unsupportedTests[generic.ID] = se.Name.Local
			}
		}
	}

	releasesSeen := map[string]bool{}
	packagesSeen := map[string]bool{}
	cvesSeen := map[string]bool{}
	unsupportedSet := map[string]bool{}

	for _, def := range definitions {
		res.Metrics.RecordsParsed++

		var usnIDs []string
		for _, ref := range def.Metadata.References {
			if ref.Source == "USN" {
				usnIDs = append(usnIDs, ref.RefID)
			}
		}
		var cveIDs []string
		urgencyByCVE := map[string]string{}
		for _, c := range def.Metadata.Advisory.CVEs {
			id := strings.TrimSpace(c.Text)
			if id == "" {
				continue
			}
			cveIDs = append(cveIDs, id)
			urgencyByCVE[id] = c.Priority
		}
		// Some notices carry their CVEs only in the CVE references or the
		// description text, not in <cve> elements (e.g. USN-8779-1). Take them
		// from there, so the finding names its CVEs. Regression notices repeat
		// the CVEs of the notice they correct and stay advisory-only.
		if len(cveIDs) == 0 && !isRegression(def.Metadata.Title) {
			cveIDs = cvesOutsideAdvisory(def)
		}
		// A regression notice can list a CVE whose patch it took out again
		// (USN-8018-2: "upstream chose to avoid by not backporting them"). Its
		// version does not fix that CVE, so no fixed rule is made for it.
		if isRegression(def.Metadata.Title) {
			reverted := revertedCVEs(def.Metadata.Description)
			kept := cveIDs[:0]
			for _, id := range cveIDs {
				if reverted[id] {
					res.Metrics.Reject("regression_reverted_cve")
					continue
				}
				kept = append(kept, id)
			}
			cveIDs = kept
		}
		// Some USNs (e.g. non-CVE regressions) have no CVE references; keep
		// them as advisory-only rules so nothing is dropped silently.
		if len(cveIDs) == 0 {
			if len(usnIDs) == 0 {
				res.Metrics.Reject("definition_without_cve_or_usn")
				continue
			}
			cveIDs = []string{""}
		}
		var published time.Time
		if d := def.Metadata.Advisory.Issued.Date; d != "" {
			published, _ = time.Parse(time.RFC3339, d)
			if published.IsZero() {
				published, _ = time.Parse("2006-01-02", d)
			}
		}

		for _, crit := range def.Criteria.flatten() {
			// Skip the release-applicability inventory criterion.
			if strings.Contains(crit.Comment, "is installed") && strings.Contains(crit.Comment, "Ubuntu") {
				continue
			}
			m := commentRe.FindStringSubmatch(crit.Comment)
			if m == nil {
				if km := kernelCommentRe.FindStringSubmatch(crit.Comment); km != nil {
					flavour, pocket, statusText := km[1], km[2], km[3]
					release, tier := releaseAndTier(pocket)
					status := normalizeStatus(statusText)
					var fixedVersion string
					if n := noteRe.FindStringSubmatch(crit.Comment); n != nil {
						fixedVersion = n[1]
					}
					if status == rules.StatusReleased && fixedVersion == "" {
						res.Metrics.Reject("kernel_released_without_fixed_version")
						continue
					}
					releasesSeen[release] = true
					packagesSeen[flavour] = true
					for _, cve := range cveIDs {
						cvesSeen[cve] = true
						rule := rules.PackageVulnerabilityRule{
							RuleID:           fmt.Sprintf("ubuntu:%s:%s:%s:kernel:%s", release, strings.Join(usnIDs, "+"), cve, flavour),
							Ecosystem:        "dpkg",
							Vendor:           "ubuntu",
							Distribution:     "ubuntu",
							Release:          release,
							SourcePackage:    flavour,
							Status:           status,
							RawStatus:        statusText,
							FixedVersion:     fixedVersion,
							Comparator:       "dpkg",
							CVEID:            cve,
							AdvisoryIDs:      usnIDs,
							Urgency:          firstNonEmpty(urgencyByCVE[cve], def.Metadata.Advisory.Severity),
							SupportTier:      tier,
							VendorNotes:      crit.Comment,
							SourcePriority:   1,
							SourceSnapshotID: meta.RawObjectID,
							RawObjectID:      def.ID,
							SourceURL:        meta.SourceURL,
							IsKernel:         true,
						}
						if !published.IsZero() {
							p := published
							rule.PublishedAt = &p
						}
						res.Rules = append(res.Rules, rule)
						res.Metrics.RulesGenerated++
					}
					res.Metrics.RecordsNormalized++
					continue
				}
				res.Metrics.Reject("criterion_comment_unparsable")
				unsupportedSet["comment: "+truncate(crit.Comment, 100)] = true
				continue
			}
			srcPkg, pocket, statusText := m[1], m[2], m[3]
			release, tier := releaseAndTier(pocket)
			status := normalizeStatus(statusText)
			if status == rules.StatusUnknown {
				// Preserve but flag: unknown status wording is reported.
				unsupportedSet["status: "+truncate(statusText, 80)] = true
			}

			var fixedVersion string
			var binaryPkgs []string
			if t, ok := tests[crit.TestRef]; ok {
				if obj, ok := objects[t.ObjectRef.Ref]; ok {
					if obj.Name.VarRef != "" {
						binaryPkgs = variables[obj.Name.VarRef]
					} else if v := strings.TrimSpace(obj.Name.Value); v != "" {
						binaryPkgs = []string{v}
					}
				}
				if st, ok := states[t.StateRef.Ref]; ok {
					if st.EVR.Operation == "less than" {
						fixedVersion = strings.TrimSpace(st.EVR.Value)
					} else if st.EVR.Value != "" {
						res.Metrics.Reject("unsupported_evr_operation")
						unsupportedSet["evr operation: "+st.EVR.Operation] = true
						continue
					}
				}
			} else if elem, ok := unsupportedTests[crit.TestRef]; ok {
				res.Metrics.Reject("unsupported_test_type_" + elem)
				unsupportedSet["test type: "+elem] = true
				continue
			} else {
				res.Metrics.Reject("test_ref_not_found")
				continue
			}
			// Fallback: fixed version embedded in the comment note.
			if fixedVersion == "" {
				if n := noteRe.FindStringSubmatch(crit.Comment); n != nil {
					fixedVersion = n[1]
				}
			}
			if status == rules.StatusReleased && fixedVersion == "" {
				res.Metrics.Reject("released_without_fixed_version")
				continue
			}

			releasesSeen[release] = true
			packagesSeen[srcPkg] = true

			// One rule per (CVE x binary package). Binary-level rules allow
			// direct lookup by installed binary name; source-level matching
			// uses the SourcePackage field on the same rules.
			targets := binaryPkgs
			if len(targets) == 0 {
				targets = []string{srcPkg}
			}
			for _, cve := range cveIDs {
				cvesSeen[cve] = true
				for _, bin := range targets {
					rule := rules.PackageVulnerabilityRule{
						RuleID:           fmt.Sprintf("ubuntu:%s:%s:%s:%s:%s", release, strings.Join(usnIDs, "+"), cve, srcPkg, bin),
						Ecosystem:        "dpkg",
						Vendor:           "ubuntu",
						Distribution:     "ubuntu",
						Release:          release,
						Architecture:     "", // Ubuntu OVAL dpkg rules apply to all arches
						PackageName:      bin,
						SourcePackage:    srcPkg,
						Status:           status,
						RawStatus:        statusText,
						FixedVersion:     fixedVersion,
						Comparator:       "dpkg",
						CVEID:            cve,
						AdvisoryIDs:      usnIDs,
						Urgency:          firstNonEmpty(urgencyByCVE[cve], def.Metadata.Advisory.Severity),
						SupportTier:      tier,
						VendorNotes:      crit.Comment,
						SourcePriority:   1,
						SourceSnapshotID: meta.RawObjectID,
						RawObjectID:      def.ID,
						SourceURL:        meta.SourceURL,
					}
					if !published.IsZero() {
						p := published
						rule.PublishedAt = &p
					}
					res.Rules = append(res.Rules, rule)
					res.Metrics.RulesGenerated++
				}
			}
			res.Metrics.RecordsNormalized++
		}
	}

	res.Metrics.PackagesSeen = len(packagesSeen)
	res.Metrics.ReleasesSeen = len(releasesSeen)
	res.Metrics.CVEsSeen = len(cvesSeen)
	for k := range unsupportedSet {
		res.Unsupported = append(res.Unsupported, k)
	}
	return res, nil
}

// Sync runs the full pipeline for one Ubuntu OVAL source: download,
// checksum, snapshot, parse, normalize, publish to the rule store.
func Sync(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store) (*ParseResult, rules.FeedSourceMetadata, error) {
	snap, err := dl.Fetch(src)
	if err != nil {
		return nil, rules.FeedSourceMetadata{}, err
	}
	meta := snap.Meta
	meta.ParserVersion = ParserVersion
	res, err := ParseFile(snap.Path, meta)
	if err != nil {
		return nil, meta, fmt.Errorf("parse %s: %w", snap.Path, err)
	}
	// Publish under the release the source covers (from the file name,
	// e.g. com.ubuntu.jammy.usn.oval.xml.bz2).
	release := releaseFromFilename(filepath.Base(snap.Path))
	if release == "" {
		return nil, meta, fmt.Errorf("cannot determine release from %s", snap.Path)
	}
	if err := store.SaveRules("ubuntu", release, res.Rules, meta); err != nil {
		return nil, meta, fmt.Errorf("publish rules: %w", err)
	}
	return res, meta, nil
}

var releaseFileRe = regexp.MustCompile(`com\.ubuntu\.([a-z]+)\.`)

func releaseFromFilename(name string) string {
	if m := releaseFileRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var cveIDRe = regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)

// cvesOutsideAdvisory returns the CVE ids a definition names in its CVE
// references and its description, in that order, without duplicates.
func cvesOutsideAdvisory(def ovalDefinition) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] && cveIDRe.MatchString(id) {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, ref := range def.Metadata.References {
		if ref.Source == "CVE" {
			add(ref.RefID)
		}
	}
	for _, id := range cveIDRe.FindAllString(def.Metadata.Description, -1) {
		add(id)
	}
	return out
}

// revertPhraseRe matches the wording Ubuntu uses when a regression notice
// takes a CVE patch out again.
var revertPhraseRe = regexp.MustCompile(`(?i)not backport|\brevert(ed|s|ing)?\b|backed out|(removed|dropped|disabled) the (patch|fix)|without the (patch|fix)`)

// revertedCVEs returns the CVEs a regression notice says it took out again: those
// named in a sentence of its own text (before "Original advisory details", which
// repeats the earlier notice) that uses revert wording.
func revertedCVEs(description string) map[string]bool {
	own, _, _ := strings.Cut(description, "Original advisory details")
	out := map[string]bool{}
	for _, sentence := range sentenceSplitRe.Split(own, -1) {
		if revertPhraseRe.MatchString(sentence) {
			for _, id := range cveIDRe.FindAllString(sentence, -1) {
				out[id] = true
			}
		}
	}
	return out
}

var sentenceSplitRe = regexp.MustCompile(`\.\s+`)

// isRegression reports a notice that fixes a regression in an earlier one
// ("USN-7626-2 -- Git regression").
func isRegression(title string) bool {
	return strings.Contains(strings.ToLower(title), "regression")
}
