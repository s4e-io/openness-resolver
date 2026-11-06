package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RuleSet is an indexed collection of normalized rules for the resolver.
// Lookups are keyed by ecosystem + distribution + release + package name so
// the engine never scans every rule for every package.
type RuleSet struct {
	Rules []PackageVulnerabilityRule `json:"rules"`
	// Snapshots records the feed snapshots that produced these rules.
	Snapshots []FeedSourceMetadata `json:"snapshots"`

	byPackage map[string][]*PackageVulnerabilityRule `json:"-"`
	bySource  map[string][]*PackageVulnerabilityRule `json:"-"`
	byID      map[string]*PackageVulnerabilityRule   `json:"-"`
}

func ruleKey(eco, distro, release, name string) string {
	return strings.Join([]string{eco, distro, release, name}, "|")
}

// Reindex rebuilds the lookup maps after Rules changes.
func (rs *RuleSet) Reindex() {
	rs.byPackage = map[string][]*PackageVulnerabilityRule{}
	rs.bySource = map[string][]*PackageVulnerabilityRule{}
	rs.byID = map[string]*PackageVulnerabilityRule{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		pk := ruleKey(r.Ecosystem, r.Distribution, r.Release, r.PackageName)
		rs.byPackage[pk] = append(rs.byPackage[pk], r)
		sk := ruleKey(r.Ecosystem, r.Distribution, r.Release, r.SourcePackage)
		rs.bySource[sk] = append(rs.bySource[sk], r)
		rs.byID[r.RuleID] = r
	}
}

// ForBinaryPackage returns rules whose binary package name matches.
func (rs *RuleSet) ForBinaryPackage(eco, distro, release, name string) []*PackageVulnerabilityRule {
	return rs.byPackage[ruleKey(eco, distro, release, name)]
}

// ForSourcePackage returns rules whose source package matches.
func (rs *RuleSet) ForSourcePackage(eco, distro, release, src string) []*PackageVulnerabilityRule {
	return rs.bySource[ruleKey(eco, distro, release, src)]
}

// ByID returns a rule by its RuleID.
func (rs *RuleSet) ByID(id string) (*PackageVulnerabilityRule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

// Stats summarizes the rule set.
type Stats struct {
	TotalRules     int            `json:"total_rules"`
	ByEcosystem    map[string]int `json:"by_ecosystem"`
	ByDistribution map[string]int `json:"by_distribution"`
	ByRelease      map[string]int `json:"by_release"`
	ByStatus       map[string]int `json:"by_status"`
	CVEs           int            `json:"distinct_cves"`
	Packages       int            `json:"distinct_packages"`
	Snapshots      int            `json:"snapshots"`
}

// Stats computes summary statistics.
func (rs *RuleSet) Stats() Stats {
	s := Stats{
		ByEcosystem:    map[string]int{},
		ByDistribution: map[string]int{},
		ByRelease:      map[string]int{},
		ByStatus:       map[string]int{},
		Snapshots:      len(rs.Snapshots),
	}
	cves := map[string]bool{}
	pkgsSeen := map[string]bool{}
	for _, r := range rs.Rules {
		s.TotalRules++
		s.ByEcosystem[r.Ecosystem]++
		s.ByDistribution[r.Distribution]++
		s.ByRelease[r.Distribution+"/"+r.Release]++
		s.ByStatus[r.Status]++
		cves[r.CVEID] = true
		pkgsSeen[r.Ecosystem+"|"+r.Release+"|"+r.PackageName] = true
	}
	s.CVEs = len(cves)
	s.Packages = len(pkgsSeen)
	return s
}

// Store persists normalized rules on the filesystem.
//
// Layout under root:
//
//	normalized/<vendor>/<release>/rules.json
//	normalized/<vendor>/<release>/metadata.json
//
// PostgreSQL DDL for the same models lives in internal/storage/schema.sql;
// the filesystem store is the default backend for the CLI.
type Store struct{ Root string }

// NewStore creates a store rooted at dir.
func NewStore(dir string) *Store { return &Store{Root: dir} }

func (s *Store) ruleDir(vendor, release string) string {
	return filepath.Join(s.Root, "normalized", vendor, release)
}

// LoadRules reads one vendor/release file. A missing file is an empty list.
func (s *Store) LoadRules(vendor, release string) ([]PackageVulnerabilityRule, error) {
	var list []PackageVulnerabilityRule
	err := readJSON(filepath.Join(s.ruleDir(vendor, release), "rules.json"), &list)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return list, err
}

// LoadMetadata reads one vendor/release snapshot. A missing file is a zero value.
func (s *Store) LoadMetadata(vendor, release string) (FeedSourceMetadata, error) {
	var meta FeedSourceMetadata
	err := readJSON(filepath.Join(s.ruleDir(vendor, release), "metadata.json"), &meta)
	if errors.Is(err, os.ErrNotExist) {
		return FeedSourceMetadata{}, nil
	}
	return meta, err
}

// MergePyPI unions a fresh package fetch into the shared PyPI rule file.
// Rules for refreshNames are replaced. Rules for every other package stay.
// A name with no vulnerabilities is kept in the synced-name list so a later
// resolve can tell "fetched, nothing to report" from "never fetched".
func MergePyPI(existing []PackageVulnerabilityRule, existingNames []string, fresh []PackageVulnerabilityRule, refreshNames []string) ([]PackageVulnerabilityRule, []string) {
	refresh := map[string]bool{}
	for _, n := range refreshNames {
		if n != "" {
			refresh[n] = true
		}
	}
	out := make([]PackageVulnerabilityRule, 0, len(existing)+len(fresh))
	for _, r := range existing {
		if refresh[r.PackageName] {
			continue
		}
		out = append(out, r)
	}
	out = append(out, fresh...)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	seen := map[string]bool{}
	var names []string
	for _, n := range append(append([]string{}, existingNames...), refreshNames...) {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	return out, names
}

// SaveRules writes normalized rules and snapshot metadata for one
// vendor/release atomically (write to temp, rename).
func (s *Store) SaveRules(vendor, release string, ruleList []PackageVulnerabilityRule, meta FeedSourceMetadata) error {
	dir := s.ruleDir(vendor, release)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// The same input always gives the same bytes: parsers collect rules in maps, so the
	// order is fixed here (rule id, then the full rule as a tie-break), and so is the
	// metadata's package list. A data mirror that ships these files then sees a change only
	// when the rules changed.
	ruleList = append([]PackageVulnerabilityRule(nil), ruleList...)
	sort.SliceStable(ruleList, func(i, j int) bool {
		if ruleList[i].RuleID != ruleList[j].RuleID {
			return ruleList[i].RuleID < ruleList[j].RuleID
		}
		a, _ := json.Marshal(ruleList[i])
		b, _ := json.Marshal(ruleList[j])
		return string(a) < string(b)
	})
	if len(meta.PackageNames) > 0 {
		meta.PackageNames = append([]string(nil), meta.PackageNames...)
		sort.Strings(meta.PackageNames)
	}
	if err := writeJSONAtomic(filepath.Join(dir, "rules.json"), ruleList); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	if err := writeJSONAtomic(filepath.Join(dir, "metadata.json"), meta); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

// LoadAll loads every normalized rule file under the store root.
func (s *Store) LoadAll() (*RuleSet, error) {
	return s.LoadFiltered(nil)
}

// LoadFiltered loads the normalized rule files for which keep(vendor,
// release) is true; a nil keep loads every file. A data directory shared by
// many assets holds rules for every distribution it ever synced (gigabytes
// of JSON once Debian, the RPM family and openSUSE are present), while one
// asset only needs its own releases.
func (s *Store) LoadFiltered(keep func(vendor, release string) bool) (*RuleSet, error) {
	rs := &RuleSet{}
	base := filepath.Join(s.Root, "normalized")
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		rs.Reindex()
		return rs, nil
	}
	if err != nil {
		return nil, err
	}
	for _, vendor := range entries {
		if !vendor.IsDir() {
			continue
		}
		releases, err := os.ReadDir(filepath.Join(base, vendor.Name()))
		if err != nil {
			return nil, err
		}
		for _, rel := range releases {
			if !rel.IsDir() {
				continue
			}
			if keep != nil && !keep(vendor.Name(), rel.Name()) {
				continue
			}
			dir := filepath.Join(base, vendor.Name(), rel.Name())
			var ruleList []PackageVulnerabilityRule
			rulesPath := filepath.Join(dir, "rules.json")
			if err := readJSON(rulesPath, &ruleList); err != nil {
				return nil, fmt.Errorf("load %s/%s: rules file %s is unreadable or corrupt (run feed sync again): %w", vendor.Name(), rel.Name(), rulesPath, err)
			}
			rs.Rules = append(rs.Rules, ruleList...)
			var meta FeedSourceMetadata
			if err := readJSON(filepath.Join(dir, "metadata.json"), &meta); err == nil {
				meta.Vendor, meta.Release = vendor.Name(), rel.Name()
				rs.Snapshots = append(rs.Snapshots, meta)
			}
		}
	}
	sort.SliceStable(rs.Rules, func(i, j int) bool { return rs.Rules[i].RuleID < rs.Rules[j].RuleID })
	rs.Reindex()
	return rs, nil
}

func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Snapshots reads the metadata of every rule directory without loading the rules, in
// vendor and release order.
func (s *Store) Snapshots() ([]FeedSourceMetadata, error) {
	var out []FeedSourceMetadata
	base := filepath.Join(s.Root, "normalized")
	vendors, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, vendor := range vendors {
		if !vendor.IsDir() {
			continue
		}
		releases, err := os.ReadDir(filepath.Join(base, vendor.Name()))
		if err != nil {
			return nil, err
		}
		for _, rel := range releases {
			var meta FeedSourceMetadata
			if !rel.IsDir() || readJSON(filepath.Join(base, vendor.Name(), rel.Name(), "metadata.json"), &meta) != nil {
				continue
			}
			meta.Vendor, meta.Release = vendor.Name(), rel.Name()
			out = append(out, meta)
		}
	}
	return out, nil
}
