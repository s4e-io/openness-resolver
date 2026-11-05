// openness-resolver is the deterministic vulnerability resolver CLI for Linux
// and Windows evidence (.openness files).
//
// Commands:
//
//	feed sync        download + snapshot + parse + normalize + publish rules
//	feed list        list registered advisory sources and snapshots
//	feed validate    download and parse sources without publishing
//	rules import     normalize rules from a local raw feed file
//	rules stats      statistics over the normalized rule store
//	rules format     which processed rules this build reads
//	resolve          evaluate a .openness evidence file into findings
//	explain          print the full explanation of one finding
//	compare-version  ecosystem-native version comparison
//	compare-nessus   diff findings against a credentialed Nessus report
//	mapper probes    files the application mapper wants the collector to check
//	version          print resolver version
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
	"github.com/s4e-io/openness-resolver/internal/buildinfo"
	"github.com/s4e-io/openness-resolver/internal/compare"
	"github.com/s4e-io/openness-resolver/internal/containers"
	"github.com/s4e-io/openness-resolver/internal/evidence"
	"github.com/s4e-io/openness-resolver/internal/feed"
	"github.com/s4e-io/openness-resolver/internal/feed/alpine"
	"github.com/s4e-io/openness-resolver/internal/feed/amazon"
	"github.com/s4e-io/openness-resolver/internal/feed/appmapper"
	"github.com/s4e-io/openness-resolver/internal/feed/debian"
	"github.com/s4e-io/openness-resolver/internal/feed/msrc"
	"github.com/s4e-io/openness-resolver/internal/feed/osv"
	"github.com/s4e-io/openness-resolver/internal/feed/osvdistro"
	"github.com/s4e-io/openness-resolver/internal/feed/ubuntu"
	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/platform"
	"github.com/s4e-io/openness-resolver/internal/python"
	"github.com/s4e-io/openness-resolver/internal/report"
	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	"github.com/s4e-io/openness-resolver/internal/version"

	// Register native comparators.
	_ "github.com/s4e-io/openness-resolver/internal/version/apk"
	_ "github.com/s4e-io/openness-resolver/internal/version/dpkg"
	_ "github.com/s4e-io/openness-resolver/internal/version/pep440"
	_ "github.com/s4e-io/openness-resolver/internal/version/rpm"
	_ "github.com/s4e-io/openness-resolver/internal/version/winbuild"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "feed":
		err = cmdFeed(os.Args[2:])
	case "rules":
		err = cmdRules(os.Args[2:])
	case "resolve":
		err = cmdResolve(os.Args[2:])
	case "explain":
		err = cmdExplain(os.Args[2:])
	case "compare-version":
		err = cmdCompareVersion(os.Args[2:])
	case "compare-nessus":
		err = cmdCompareNessus(os.Args[2:])
	case "mapper":
		err = cmdMapper(os.Args[2:])
	case "version":
		cmdVersion()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: openness-resolver <command> [flags]

commands:
  feed sync --for <file.openness|device.json>|--source <id>|--vendor <v>|--all [--data-dir data] [--months N] [--pypi-only] [--osv-url <url>] [--mapper-url <url>] [--dry-run]
  feed list [--data-dir data]
  feed validate [--data-dir data] [--mapper-url <url>] [--dry-run]   download every enabled source (or the selected ones) and parse it without publishing
  rules import --source <id> --file <raw feed file> [--source-url <url>] [--fetched-at <rfc3339>] [--data-dir data]
  rules stats [--data-dir data]
  rules format                      which processed rules this build reads (JSON: format, id, parsers)
  resolve --input <file.openness>|--device <device.json> [--output findings.json] [--data-dir data] [--states s1,s2] [--preflight] [--mapper <file>] [--app-unverified] [--app-guess=false]
  explain --finding-id <id> [--findings findings.json]
  compare-version --ecosystem dpkg|apk|rpm|pep440|winbuild --installed <v> --fixed <v>
  mapper probes [--mapper <file>]   files the collector should check (collect --file-probes), as JSON
  compare-nessus --nessus <report.nessus> --findings findings.json [--host <ip>] [--local-only] [--json out.json] [--show N]
  version
`)
}

func cmdVersion() {
	fmt.Printf("openness-resolver %s commit=%s built=%s\n", buildinfo.SemVer(), buildinfo.Commit, buildinfo.Date)
}

// --- feed ---

func cmdFeed(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("feed requires a subcommand: sync | list | validate")
	}
	sub, rest := args[0], args[1:]
	if sub != "sync" && sub != "list" && sub != "validate" {
		return fmt.Errorf("unknown feed subcommand %q", sub)
	}
	// Each subcommand registers only the flags it uses, so -h lists exactly those.
	fs := flag.NewFlagSet("openness-resolver feed "+sub, flag.ExitOnError)
	var (
		dataDir               = new(string)
		sourceID, vendor      = new(string), new(string)
		forEvidence, osvURL   = new(string), new(string)
		all, pypiOnly, dryRun = new(bool), new(bool), new(bool)
		mapperURL             = new(string)
		allowDowngrade        = new(bool)
		staleAfter            = &staleFlag{}
		months                = new(int)
		selecting, syncing    = sub != "list", sub == "sync"
	)
	fs.StringVar(dataDir, "data-dir", "data", "data directory for raw snapshots and normalized rules")
	*months = 24
	if selecting {
		fs.StringVar(sourceID, "source", "", "advisory source id: a registry id (feed list) or a release id such as ubuntu-oval-usn-noble, alpine-secdb-v3.20, msrc-cvrf-2026-Oct")
		fs.StringVar(vendor, "vendor", "", "every enabled source of one vendor (ubuntu|alpine|debian|rocky|almalinux|rhel|opensuse|amazon|microsoft)")
		fs.BoolVar(all, "all", false, "every enabled source")
		fs.StringVar(forEvidence, "for", "", "the sources the asset in this .openness file (or openness-device/1 file) needs (host release, container image releases, app-mapper)")
		fs.IntVar(months, "months", 24, "MSRC: number of monthly CVRF documents, newest first (vendor microsoft / Windows evidence)")
		fs.BoolVar(dryRun, "dry-run", false, "print the sources that would be downloaded (id and URL) and download nothing")
		fs.StringVar(mapperURL, "mapper-url", "", "where the app-mapper source downloads the mapper bundle from (SHA256SUMS must sit next to it); default: the latest S4E catalog release on GitHub")
	}
	if sub == "list" {
		fs.Var(staleAfter, "stale-after", staleAfterUsage)
	}
	if syncing {
		fs.BoolVar(allowDowngrade, "allow-downgrade", false, "let the app-mapper source replace the mapper with an older version, or install one older than the built-in mapper")
		fs.BoolVar(pypiOnly, "pypi-only", false, "with --for: only query the PyPI packages, download no advisory source (the advisory rules come from rules import)")
		fs.StringVar(osvURL, "osv-url", "", "OSV query endpoint for PyPI packages, a mirror of api.osv.dev/v1/query (default: OPENNESS_OSV_URL, else api.osv.dev); OPENNESS_OSV_HEADERS adds request headers, one \"Name: value\" per line")
	}
	fs.Parse(rest)
	setOSVEndpoint(*osvURL)
	if *months < 1 {
		return fmt.Errorf("--months must be at least 1, got %d", *months)
	}
	if *vendor != "" && !knownVendor(*vendor) {
		return fmt.Errorf("unknown vendor %q (one of: %s)", *vendor, strings.Join(knownVendors(), ", "))
	}

	dl := feed.NewDownloader(*dataDir)
	store := rules.NewStore(*dataDir)

	switch sub {
	case "list":
		fmt.Printf("%-32s %-6s %-8s %-4s %s\n", "ID", "ECO", "VENDOR", "PRI", "ENABLED")
		for _, s := range rules.Registry() {
			fmt.Printf("%-32s %-6s %-8s %-4d %v\n", s.ID, s.Ecosystem, s.Vendor, s.Priority, s.Enabled)
		}
		if err := printDataAges(store, *dataDir, staleAfter.value()); err != nil {
			return err
		}
		for _, v := range []string{"ubuntu", "alpine", "microsoft", "debian", "rocky", "almalinux", "rhel", "opensuse", "amazon"} {
			snaps, _ := dl.Snapshots(v)
			for _, s := range snaps {
				fmt.Printf("snapshot %s\n", s)
			}
		}
		return nil
	case "sync", "validate":
		var selected []rules.AdvisorySource
		if *sourceID != "" {
			// Registry ids and release-derived ones (ubuntu-oval-usn-<codename>,
			// alpine-secdb-<branch>, msrc-cvrf-<YYYY-Mon>) alike.
			src, ok := rules.ImportSource(*sourceID, "")
			if !ok {
				return fmt.Errorf("unknown source id %q (see `feed list`; release ids look like ubuntu-oval-usn-jammy, alpine-secdb-v3.20, msrc-cvrf-2026-Oct)", *sourceID)
			}
			selected = append(selected, src)
		}
		for _, s := range rules.Registry() {
			switch {
			case *vendor != "" && s.Vendor == *vendor && s.Enabled:
				selected = append(selected, s)
			case *all && s.Enabled:
				selected = append(selected, s)
			}
		}
		validateOnly := sub == "validate"
		if *vendor == "microsoft" {
			selected = append(selected, rules.MSRCSources(*months, time.Now())...)
		}
		if *pypiOnly && *forEvidence == "" {
			return fmt.Errorf("--pypi-only needs --for")
		}
		if *forEvidence != "" && !*pypiOnly {
			srcs, notes, err := sourcesForEvidence(*forEvidence, *months)
			if err != nil {
				return err
			}
			for _, n := range notes {
				fmt.Println(n)
			}
			selected = append(selected, srcs...)
		}
		if len(selected) == 0 && validateOnly && *sourceID == "" && *vendor == "" && *forEvidence == "" && !*all {
			for _, s := range rules.Registry() {
				if s.Enabled {
					selected = append(selected, s)
				}
			}
		}
		// A 404 of the mapper (not published yet) fails the run only when it was asked
		// for by name.
		mapperStrict = *sourceID == appmapper.ID
		mapperAllowDowngrade = *allowDowngrade
		for i := range selected {
			if selected[i].ID == appmapper.ID && *mapperURL != "" {
				selected[i].URL = *mapperURL
			}
		}
		isDevice := *forEvidence != "" && appvuln.IsDeviceFile(*forEvidence)
		if *dryRun {
			evForPyPI := *forEvidence
			if isDevice {
				evForPyPI = ""
			}
			return printDryRun(dedupeSources(selected), evForPyPI, validateOnly)
		}
		var syncErr error
		if len(selected) > 0 {
			syncErr = syncSources(dedupeSources(selected), dl, store, validateOnly)
		}
		pypiRan := false
		if *forEvidence != "" && !validateOnly && !isDevice {
			var pypiErr error
			pypiRan, pypiErr = syncPyPIEvidence(*dataDir, *forEvidence)
			if pypiErr != nil {
				fmt.Printf("    FAILED: %v\n", pypiErr)
				if syncErr == nil {
					syncErr = pypiErr
				}
			}
		}
		if *pypiOnly && !pypiRan {
			fmt.Println("no PyPI packages in the evidence")
			return syncErr
		}
		if len(selected) == 0 && !pypiRan && syncErr == nil {
			return fmt.Errorf("no sources selected (use --for, --source, --vendor or --all; see `feed list`)")
		}
		return syncErr
	default:
		return fmt.Errorf("unknown feed subcommand %q", sub)
	}
}

// knownVendors are the values --vendor accepts: every vendor with an enabled
// registry source, plus microsoft (MSRC months are derived, not registered).
func knownVendors() []string {
	seen := map[string]bool{"microsoft": true}
	for _, s := range rules.Registry() {
		if s.Enabled {
			seen[s.Vendor] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func knownVendor(v string) bool {
	for _, k := range knownVendors() {
		if k == v {
			return true
		}
	}
	return false
}

// printDryRun lists what `feed sync` or `feed validate` would download, one
// "<source id> <url>" line per source, and the OSV PyPI query when the evidence
// names PyPI packages. Nothing is downloaded or written.
func printDryRun(selected []rules.AdvisorySource, forEvidence string, validateOnly bool) error {
	for _, s := range selected {
		fmt.Printf("source %s %s\n", s.ID, s.URL)
	}
	pypi := 0
	if forEvidence != "" && !validateOnly {
		lr, err := evidence.Load(forEvidence)
		if err != nil {
			return err
		}
		pypi = len(python.PyPINames(python.BuildInventory(lr.LanguageDepRecords())))
		if pypi > 0 {
			fmt.Printf("source osv-pypi %s (%d packages)\n", osv.Endpoint, pypi)
		}
	}
	if len(selected) == 0 && pypi == 0 {
		return fmt.Errorf("no sources selected (use --for, --source, --vendor or --all; see `feed list`)")
	}
	return nil
}

// sourcesForEvidence derives the advisory sources one asset needs from its own
// evidence: the host release plus every container image release it carries.
func sourcesForEvidence(path string, months int) ([]rules.AdvisorySource, []string, error) {
	mapperSrc, _ := rules.SourceByID(appmapper.ID)
	if appvuln.IsDeviceFile(path) {
		if _, err := appvuln.ReadDeviceFile(path); err != nil {
			return nil, nil, err
		}
		return []rules.AdvisorySource{mapperSrc}, []string{"network device -> app-mapper"}, nil
	}
	lr, err := evidence.Load(path)
	if err != nil {
		return nil, nil, err
	}
	var out []rules.AdvisorySource
	var notes []string

	plat := platform.FromOS(lr.Doc.OperatingSystem, lr.Doc.Kernel)
	if plat.DistributionID == "" {
		notes = append(notes, "host: distribution could not be determined from evidence")
	} else if plat.DistributionID == "windows" {
		if plat.Codename == "" {
			notes = append(notes, "host: windows product could not be mapped; MSRC documents are still synced (all products share one document)")
		}
		srcs := rules.MSRCSources(months, time.Now())
		notes = append(notes, fmt.Sprintf("host: windows %s build %s -> MSRC CVRF, last %d months", plat.Codename, plat.WindowsBuild, len(srcs)))
		out = append(out, srcs...)
		out = append(out, mapperSrc)
		notes = append(notes, "host: windows applications -> app-mapper")
	} else if srcs, err := rules.HostSources(plat.DistributionID, plat.RuleRelease()); err != nil {
		notes = append(notes, "host: "+err.Error())
	} else {
		out = append(out, srcs...)
		notes = append(notes, fmt.Sprintf("host %s %s (release key %s)", plat.DistributionID, plat.DistributionVersion, plat.RuleRelease()))
		if state, reason := plat.Support(); state != platform.Supported {
			notes = append(notes, fmt.Sprintf("host: %s; rules are synced for the supported releases only", reason))
		}
	}

	if plat.DistributionID != "windows" && len(lr.Doc.Applications) > 0 {
		out = append(out, mapperSrc)
		notes = append(notes, fmt.Sprintf("host: %d applications -> app-mapper", len(lr.Doc.Applications)))
	}
	for _, g := range containers.BuildInventory(lr.ContainerRecords()).Groups {
		digest := short(g.ImageDigest, 20)
		if g.Distro == "" || g.Branch == "" {
			notes = append(notes, fmt.Sprintf("image %s: release could not be inferred; no source selected", digest))
			continue
		}
		srcs, err := rules.ReleaseSources(g.Distro, g.Branch)
		if err != nil {
			notes = append(notes, fmt.Sprintf("image %s: %v", digest, err))
			continue
		}
		out = append(out, srcs...)
		notes = append(notes, fmt.Sprintf("image %s %s %s", digest, g.Distro, g.Branch))
	}
	return out, notes, nil
}

// syncPyPIEvidence downloads OSV rules for PyPI names in the evidence file
// and merges them into the shared pypi/pypi rule file. A second asset does
// not erase the first asset's packages. resolve never calls this.
// The bool is true when the file named at least one PyPI distribution.
func syncPyPIEvidence(dataDir, path string) (bool, error) {
	lr, err := evidence.Load(path)
	if err != nil {
		return false, err
	}
	names := python.PyPINames(python.BuildInventory(lr.LanguageDepRecords()))
	if len(names) == 0 {
		return false, nil
	}
	fmt.Printf("==> pypi (%d packages named in evidence)\n", len(names))
	meta, fresh, err := osv.SyncPackages(dataDir, names)
	if err != nil {
		return true, fmt.Errorf("osv pypi sync: %w", err)
	}
	store := rules.NewStore(dataDir)
	existing, err := store.LoadRules("pypi", "pypi")
	if err != nil {
		return true, err
	}
	oldMeta, err := store.LoadMetadata("pypi", "pypi")
	if err != nil {
		return true, err
	}
	merged, synced := rules.MergePyPI(existing, oldMeta.PackageNames, fresh, names)
	meta.PackageNames = synced
	if err := store.SaveRules("pypi", "pypi", merged, meta); err != nil {
		return true, err
	}
	return true, nil
}

func dedupeSources(srcs []rules.AdvisorySource) []rules.AdvisorySource {
	seen := map[string]bool{}
	out := make([]rules.AdvisorySource, 0, len(srcs))
	for _, s := range srcs {
		if seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out
}

func syncSources(selected []rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, validateOnly bool) error {
	// Alpine branches merge main+community into one rule file, so existing
	// rules are loaded first.
	existingByBranch := map[string][]rules.PackageVulnerabilityRule{}
	var firstErr error
	for _, src := range selected {
		fmt.Printf("==> %s (%s)\n", src.ID, src.URL)
		start := time.Now()
		syncSource(src, dl, store, validateOnly, existingByBranch, &firstErr)
		fmt.Printf("    took %s\n", time.Since(start).Round(time.Millisecond))
	}
	return firstErr
}

// syncSource downloads, parses and (unless validateOnly) publishes one source. A
// failure is printed and kept in firstErr when it is the first one.
func syncSource(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, validateOnly bool,
	existingByBranch map[string][]rules.PackageVulnerabilityRule, firstErr *error) {
	switch src.Parser {
	case "ubuntu-oval":
		res, meta, err := syncUbuntu(src, dl, store, validateOnly)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		printFeedMetrics(res.Metrics, meta)
		if len(res.Unsupported) > 0 {
			fmt.Printf("    unsupported structures (%d kinds):\n", len(res.Unsupported))
			for i, u := range res.Unsupported {
				if i >= 8 {
					fmt.Printf("      ... and %d more\n", len(res.Unsupported)-8)
					break
				}
				fmt.Printf("      - %s\n", u)
			}
		}
	case "alpine-secdb":
		snap, err := dl.Fetch(src)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		meta := snap.Meta
		meta.ParserVersion = alpine.ParserVersion
		res, err := alpine.ParseFile(snap.Path, meta)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		if !validateOnly {
			merged := mergeAlpine(existingByBranch, res.Branch, res.Rules, store)
			if err := store.SaveRules("alpine", res.Branch, merged, meta); err != nil {
				fmt.Printf("    FAILED: %v\n", err)
				if *firstErr == nil {
					*firstErr = err
				}
				return
			}
			existingByBranch[res.Branch] = merged
		}
		printFeedMetrics(res.Metrics, meta)
	case "debian-tracker":
		res, meta, err := debian.Sync(src, dl, store, wantedReleases("debian"), validateOnly)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		printFeedMetrics(res.Metrics, meta)
		fmt.Printf("    releases: %v\n", res.Releases)
	case "osv-distro":
		res, meta, err := osvdistro.Sync(src, dl, store, wantedReleases(src.Vendor), validateOnly)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		printFeedMetrics(res.Metrics, meta)
		fmt.Printf("    releases: %v\n", res.Releases)
	case "amazon-updateinfo":
		res, meta, err := amazon.Sync(src, dl, store, validateOnly)
		if err != nil {
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		printFeedMetrics(res.Metrics, meta)
	case "msrc-cvrf":
		res, meta, err := msrc.Sync(src, dl, store, validateOnly)
		if err != nil {
			if strings.Contains(err.Error(), "http 404") {
				// A month without a published document (future month, or
				// before the product existed) is not a failure.
				fmt.Printf("    no document for this month (404), skipped\n")
				return
			}
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		printFeedMetrics(res.Metrics, meta)
		fmt.Printf("    windows products: %d, skipped remediations: %v\n", len(res.Products), res.Skipped)
	case "app-mapper":
		meta, err := appmapper.Sync(src.URL, dl.DataDir, !validateOnly, mapperAllowDowngrade, time.Now())
		if err != nil {
			if errors.Is(err, appmapper.ErrNotPublished) && !mapperStrict {
				fmt.Printf("    %v; skipped\n", err)
				return
			}
			if errors.Is(err, appmapper.ErrOlder) {
				// Never a silent downgrade, and never a failure: the current mapper stays.
				fmt.Printf("    %v\n", err)
				return
			}
			fmt.Printf("    FAILED: %v\n", err)
			if *firstErr == nil {
				*firstErr = err
			}
			return
		}
		fmt.Printf("    sha256=%s size=%dB parser=%s\n", short(meta.SHA256, 16), meta.SizeBytes, meta.Format)
		fmt.Printf("    mapper version=%s\n", meta.Version)
	default:
		fmt.Printf("    SKIPPED: parser %q not implemented yet\n", src.Parser)
	}
}

// mapperStrict makes a 404 of the app-mapper source a failure (feed sync --source app-mapper);
// mapperAllowDowngrade lets it install an older mapper (feed sync --allow-downgrade).
var mapperStrict, mapperAllowDowngrade bool

const staleAfterUsage = "age after which a source's data counts as old, for every source (a duration such as 36h or 10d; 0 turns the check off); default: 2d for distribution feeds, 35d for MSRC, 7d for app-mapper, never for PyPI"

// staleFlag is --stale-after: unset keeps the per-source defaults.
type staleFlag struct {
	set bool
	d   time.Duration
}

func (f *staleFlag) String() string {
	if f == nil || !f.set {
		return ""
	}
	return f.d.String()
}

// Set takes a Go duration or a number of days ("10d").
func (f *staleFlag) Set(v string) error {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("want a duration such as 36h or 10d")
		}
		f.set, f.d = true, time.Duration(n*24*float64(time.Hour))
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return fmt.Errorf("want a duration such as 36h or 10d")
	}
	f.set, f.d = true, d
	return nil
}

func (f *staleFlag) value() *time.Duration {
	if !f.set {
		return nil
	}
	return &f.d
}

// printDataAges lists the data in the data directory (rule directories and the synced
// mapper) with its age and whether it counts as old.
func printDataAges(store *rules.Store, dataDir string, override *time.Duration) error {
	snaps, err := store.Snapshots()
	if err != nil {
		return err
	}
	cov := resolver.RuleCoverage{}
	for _, m := range snaps {
		c := resolver.CoverageSource{Release: m.Vendor + "/" + m.Release, Source: m.SourceName}
		if !m.DownloadedAt.IsZero() {
			t := m.DownloadedAt
			c.DownloadedAt = &t
		}
		cov.Sources = append(cov.Sources, c)
	}
	if m, ok := appvuln.ReadMeta(appmapper.Path(dataDir)); ok {
		t := m.DownloadedAt
		cov.Sources = append(cov.Sources, resolver.CoverageSource{Release: "mapper", Source: appmapper.ID, Version: m.Version, DownloadedAt: &t})
	}
	resolver.MarkStale(&cov, time.Now(), override)
	for _, c := range cov.Sources {
		line := fmt.Sprintf("data %s %s", c.Release, c.Source)
		if c.Version != "" {
			line += " version=" + c.Version
		}
		if c.DownloadedAt == nil {
			fmt.Println(line + " downloaded_at=unknown")
			continue
		}
		fmt.Printf("%s downloaded_at=%s age_days=%d stale=%v\n", line, c.DownloadedAt.UTC().Format(time.RFC3339), *c.AgeDays, *c.Stale)
	}
	return nil
}

// wantedReleases is the set of release keys a vendor-wide feed is stored
// for: the production supported releases of that distribution, written the
// way rules are keyed (Debian codenames, RPM major versions, Leap versions).
func wantedReleases(distribution string) map[string]bool {
	out := map[string]bool{}
	for _, v := range platform.SupportedReleases(distribution) {
		if distribution == "debian" {
			if cn, ok := platform.DebianCodename(v); ok {
				out[cn] = true
			}
			continue
		}
		out[v] = true
	}
	return out
}

func syncUbuntu(src rules.AdvisorySource, dl *feed.Downloader, store *rules.Store, validateOnly bool) (*ubuntu.ParseResult, rules.FeedSourceMetadata, error) {
	if validateOnly {
		snap, err := dl.Fetch(src)
		if err != nil {
			return nil, rules.FeedSourceMetadata{}, err
		}
		meta := snap.Meta
		meta.ParserVersion = ubuntu.ParserVersion
		res, err := ubuntu.ParseFile(snap.Path, meta)
		return res, meta, err
	}
	return ubuntu.Sync(src, dl, store)
}

func mergeAlpine(cache map[string][]rules.PackageVulnerabilityRule, branch string, newRules []rules.PackageVulnerabilityRule, store *rules.Store) []rules.PackageVulnerabilityRule {
	existing, ok := cache[branch]
	if !ok {
		// Load previously published rules for the branch, if any.
		rs, err := store.LoadAll()
		if err == nil {
			for _, r := range rs.Rules {
				if r.Vendor == "alpine" && r.Release == branch {
					existing = append(existing, r)
				}
			}
		}
	}
	byID := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range existing {
		byID[r.RuleID] = r
	}
	for _, r := range newRules {
		byID[r.RuleID] = r
	}
	out := make([]rules.PackageVulnerabilityRule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	return out
}

func printFeedMetrics(m feed.Metrics, meta rules.FeedSourceMetadata) {
	fmt.Printf("    sha256=%s size=%dB parser=%s\n", short(meta.SHA256, 16), meta.SizeBytes, meta.ParserVersion)
	fmt.Printf("    downloaded=%d parsed=%d normalized=%d rejected=%d rules=%d packages=%d releases=%d cves=%d\n",
		m.RecordsDownloaded, m.RecordsParsed, m.RecordsNormalized, m.RecordsRejected,
		m.RulesGenerated, m.PackagesSeen, m.ReleasesSeen, m.CVEsSeen)
	if len(m.RejectionReasons) > 0 {
		fmt.Printf("    rejection reasons: %v\n", m.RejectionReasons)
	}
}

// --- rules ---

func cmdRules(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("rules requires a subcommand: import | stats | format")
	}
	sub, rest := args[0], args[1:]
	if sub != "import" && sub != "stats" && sub != "format" {
		return fmt.Errorf("unknown rules subcommand %q", sub)
	}
	// Each subcommand registers only the flags it uses, so -h lists exactly those.
	fs := flag.NewFlagSet("openness-resolver rules "+sub, flag.ExitOnError)
	dataDir := new(string)
	sourceID, file, sourceURL, fetchedAt := new(string), new(string), new(string), new(string)
	if sub != "format" {
		fs.StringVar(dataDir, "data-dir", "data", "data directory for normalized rules")
	}
	if sub == "import" {
		fs.StringVar(sourceID, "source", "", "advisory source id: a registry id, a release id (ubuntu-oval-usn-jammy, alpine-secdb-v3.20, msrc-cvrf-2026-Oct) or a data mirror id")
		fs.StringVar(file, "file", "", "local raw feed file, as the publisher serves it")
		fs.StringVar(sourceURL, "source-url", "", "where the file was published (default: the source's URL)")
		fs.StringVar(fetchedAt, "fetched-at", "", "RFC 3339 time the file was fetched from its publisher (default: now)")
	}
	fs.Parse(rest)

	store := rules.NewStore(*dataDir)
	switch sub {
	case "format":
		// Which processed rules this build reads: a data mirror ships rules built with the
		// same id ready to use (docs: Processed rules).
		data, _ := json.MarshalIndent(rules.Format(parserVersions()), "", "  ")
		fmt.Println(string(data))
		return nil
	case "stats":
		rs, err := store.LoadAll()
		if err != nil {
			return err
		}
		stats := rs.Stats()
		data, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(data))
		return nil
	case "import":
		if *sourceID == "" || *file == "" {
			return fmt.Errorf("rules import requires --source and --file")
		}
		src, ok := rules.ImportSource(*sourceID, filepath.Base(*file))
		if !ok {
			return fmt.Errorf("unknown source %q", *sourceID)
		}
		meta, err := importMeta(src, *file, *sourceURL, *fetchedAt)
		if err != nil {
			return err
		}
		switch src.Parser {
		case "ubuntu-oval":
			meta.ParserVersion = ubuntu.ParserVersion
			res, err := ubuntu.ParseFile(*file, meta)
			if err != nil {
				return err
			}
			release := strings.TrimPrefix(src.ID, "ubuntu-oval-usn-")
			if m := strings.Split(filepath.Base(*file), "."); len(m) > 2 && m[0] == "com" && m[1] == "ubuntu" {
				release = m[2] // com.ubuntu.<release>...
			}
			if err := store.SaveRules("ubuntu", release, res.Rules, meta); err != nil {
				return err
			}
			printFeedMetrics(res.Metrics, meta)
		case "alpine-secdb":
			meta.ParserVersion = alpine.ParserVersion
			res, err := alpine.ParseFile(*file, meta)
			if err != nil {
				return err
			}
			// main and community share the branch's rule file: keep the other document's rules.
			merged := mergeAlpine(map[string][]rules.PackageVulnerabilityRule{}, res.Branch, res.Rules, store)
			if err := store.SaveRules("alpine", res.Branch, merged, meta); err != nil {
				return err
			}
			printFeedMetrics(res.Metrics, meta)
		case "debian-tracker":
			meta.ParserVersion = debian.ParserVersion
			res, err := debian.ParseFile(*file, meta, wantedReleases("debian"))
			if err != nil {
				return err
			}
			if err := debian.Publish(store, res, meta); err != nil {
				return err
			}
			printFeedMetrics(res.Metrics, meta)
		case "osv-distro":
			d, ok := osvdistro.Distros[src.Vendor]
			if !ok {
				return fmt.Errorf("source %s has no OSV distro mapping", src.ID)
			}
			meta.ParserVersion = osvdistro.ParserVersion
			res, err := osvdistro.ParseFile(*file, d, wantedReleases(src.Vendor), meta)
			if err != nil {
				return err
			}
			if err := osvdistro.Publish(store, d, res, meta); err != nil {
				return err
			}
			printFeedMetrics(res.Metrics, meta)
		case "amazon-updateinfo":
			meta.ParserVersion = amazon.ParserVersion
			res, err := amazon.ParseFile(*file, amazon.ReleaseFromSourceID(src.ID), meta)
			if err != nil {
				return err
			}
			if err := store.SaveRules(amazon.Vendor, res.Release, res.Rules, meta); err != nil {
				return err
			}
			printFeedMetrics(res.Metrics, meta)
		case "msrc-cvrf":
			meta.ParserVersion = msrc.ParserVersion
			res, err := msrc.ParseFile(*file, meta)
			if err != nil {
				return err
			}
			byProduct := map[string][]rules.PackageVulnerabilityRule{}
			for _, r := range res.Rules {
				byProduct[r.Release] = append(byProduct[r.Release], r)
			}
			for _, key := range res.Products {
				existing, err := store.LoadRules(msrc.Vendor, key)
				if err != nil {
					return err
				}
				if err := store.SaveRules(msrc.Vendor, key, msrc.MergeRules(existing, byProduct[key]), meta); err != nil {
					return err
				}
			}
			printFeedMetrics(res.Metrics, meta)
			fmt.Printf("    month %s, windows products: %d, skipped remediations: %v\n", res.Month, len(res.Products), res.Skipped)
		case "app-mapper":
			d, err := appvuln.LoadFile(*file)
			if err != nil {
				return err
			}
			dst := appmapper.Path(*dataDir)
			if err := installCopy(*file, dst); err != nil {
				return err
			}
			if err := appmapper.WriteMeta(dst, appvuln.BundleMeta{Source: appmapper.ID, SourceURL: meta.SourceURL,
				DownloadedAt: meta.DownloadedAt, SHA256: meta.SHA256, SizeBytes: meta.SizeBytes,
				Format: appvuln.BundleFormat, Version: d.Version}); err != nil {
				return err
			}
			fmt.Printf("    mapper version=%s written to %s\n", d.Version, dst)
		default:
			return fmt.Errorf("parser %q not implemented", src.Parser)
		}
		return nil
	default:
		return fmt.Errorf("unknown rules subcommand %q", sub)
	}
}

// parserVersions are the feed parsers of this build, the input of `rules format`.
func parserVersions() map[string]string {
	return map[string]string{
		"ubuntu-oval":       ubuntu.ParserVersion,
		"alpine-secdb":      alpine.ParserVersion,
		"debian-tracker":    debian.ParserVersion,
		"osv-distro":        osvdistro.ParserVersion,
		"amazon-updateinfo": amazon.ParserVersion,
		"msrc-cvrf":         msrc.ParserVersion,
		"osv-pypi":          osv.ParserVersion,
	}
}

// importMeta describes a local file for `rules import`: its checksum and size, and where
// and when it was published when the caller (the data mirror) knows.
func importMeta(src rules.AdvisorySource, file, sourceURL, fetchedAt string) (rules.FeedSourceMetadata, error) {
	f, err := os.Open(file)
	if err != nil {
		return rules.FeedSourceMetadata{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return rules.FeedSourceMetadata{}, err
	}
	meta := rules.FeedSourceMetadata{
		SourceName: src.ID, SourceURL: src.URL, DownloadedAt: time.Now().UTC(),
		SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n,
		RawObjectID: "local:" + filepath.Base(file),
	}
	if sourceURL != "" {
		meta.SourceURL = sourceURL
	}
	if fetchedAt != "" {
		t, err := time.Parse(time.RFC3339, fetchedAt)
		if err != nil {
			return meta, fmt.Errorf("--fetched-at: %w", err)
		}
		meta.DownloadedAt = t.UTC()
	}
	return meta, nil
}

// setOSVEndpoint points PyPI queries at flag, else OPENNESS_OSV_URL, else api.osv.dev, and
// adds the OPENNESS_OSV_HEADERS headers.
func setOSVEndpoint(flag string) {
	if flag == "" {
		flag = os.Getenv("OPENNESS_OSV_URL")
	}
	if flag != "" {
		osv.Endpoint = flag
	}
	osv.Headers = osv.ParseHeaders(os.Getenv("OPENNESS_OSV_HEADERS"))
}

// --- resolve ---

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("openness-resolver resolve", flag.ExitOnError)
	input := fs.String("input", "", ".openness evidence file")
	device := fs.String("device", "", "network device file (openness-device/1, written from SNMP) to resolve instead of --input")
	output := fs.String("output", "findings.json", "output findings JSON file")
	dataDir := fs.String("data-dir", "data", "data directory with normalized rules")
	statesFilter := fs.String("states", "", "comma-separated states to include in the summary listing")
	preflight := fs.Bool("preflight", false, "enforce strict evidence preflight checks (validation mode)")
	mapper := fs.String("mapper", "", "application mapper file (catalog + NVD data, JSON or gzip) for third-party Windows applications and network devices; default: <data-dir>/mapper/app-mapper.json.gz when synced, else the built-in one")
	appUnverified := fs.Bool("app-unverified", false, "also use the application and device catalog entries no person reviewed")
	appGuess := fs.Bool("app-guess", true, "guess the NVD product of applications the catalog does not know (findings are potentially_vulnerable)")
	staleAfter := &staleFlag{}
	fs.Var(staleAfter, "stale-after", staleAfterUsage)
	fs.Parse(args)
	if *input != "" && *device != "" {
		return fmt.Errorf("resolve takes --input or --device, not both")
	}
	if *device != "" {
		return resolveDevice(*device, *output, *dataDir, *mapper, *statesFilter, staleAfter.value(), appvuln.Options{Unverified: *appUnverified})
	}
	if *input == "" {
		return fmt.Errorf("resolve requires --input <file.openness> or --device <device.json>")
	}

	var lr *evidence.LoadResult
	if *preflight {
		// Strict parse only — no hardcoded lab filename/SHA. Optional pin via
		// PreflightExpectations fields when calling evidence.RunPreflight from tests.
		doc, _, err := evidence.RunPreflight(*input, evidence.PreflightExpectations{})
		if err != nil {
			return err
		}
		if doc.SchemaVersion == "" || doc.Asset.AssetID == "" {
			return fmt.Errorf("preflight: schema_version and asset.asset_id are required")
		}
		lr = &evidence.LoadResult{Doc: doc}
	} else {
		var err error
		lr, err = evidence.Load(*input)
		if err != nil {
			return err
		}
	}

	rs, err := rules.NewStore(*dataDir).LoadFiltered(ruleFilesFor(lr))
	if err != nil {
		return err
	}
	if len(rs.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "warning: rule store is empty; run `openness-resolver feed sync --for <evidence.openness>` first")
	}

	engine := resolver.NewEngine(rs)
	// The mapper is read when it can be used (a Windows host) or was named.
	if *mapper != "" || platform.FromOS(lr.Doc.OperatingSystem, lr.Doc.Kernel).DistributionID == "windows" {
		if engine.Apps, engine.AppSource, err = selectMapper(*mapper, *dataDir); err != nil {
			return err
		}
	}
	engine.AppOptions = appvuln.Options{Unverified: *appUnverified, Fallback: *appGuess}
	res, err := engine.Resolve(lr)
	if err != nil {
		return err
	}
	if err := writeResult(res, *output, *statesFilter, staleAfter.value()); err != nil {
		return err
	}
	if err := res.RuleCoverage.EvaluationError(*input); err != nil {
		return err
	}
	return nil
}

// resolveDevice is resolve --device: a network device against the device catalog.
func resolveDevice(path, output, dataDir, mapperFile, statesFilter string, staleAfter *time.Duration, opt appvuln.Options) error {
	dev, err := appvuln.ReadDeviceFile(path)
	if err != nil {
		return err
	}
	engine := resolver.NewEngine(&rules.RuleSet{})
	if engine.Apps, engine.AppSource, err = selectMapper(mapperFile, dataDir); err != nil {
		return err
	}
	engine.AppOptions = opt
	return writeResult(engine.ResolveDevice(dev), output, statesFilter, staleAfter)
}

// writeResult marks old data, writes the findings, prints the summary and lists the
// findings of the requested states. Old data is a warning and a note, never an error.
func writeResult(res *resolver.RunResult, output, statesFilter string, staleAfter *time.Duration) error {
	if old := resolver.MarkStale(&res.RuleCoverage, time.Now(), staleAfter); len(old) > 0 {
		msg := "old data: " + strings.Join(old, ", ") + "; run `openness-resolver feed sync`"
		res.Notes = append(res.Notes, msg)
		fmt.Fprintln(os.Stderr, "warning: "+msg)
	}
	if err := report.WriteJSON(res, output); err != nil {
		return err
	}
	report.Summary(res, os.Stdout)
	fmt.Printf("\nfindings written to %s\n", output)

	if statesFilter != "" {
		want := map[string]bool{}
		for _, s := range strings.Split(statesFilter, ",") {
			want[strings.TrimSpace(s)] = true
		}
		fmt.Println()
		for _, f := range res.Findings {
			if want[f.State] {
				fmt.Printf("%-22s %-18s %-30s %-24s installed=%s fixed=%s\n",
					f.FindingID, f.State, f.CVEID, f.BinaryPackage, f.InstalledVersion, f.FixedVersion)
			}
		}
	}
	return nil
}

// cmdMapper: `mapper probes` prints the files the application mapper wants the collector
// to check (collect --file-probes) as a JSON array.
func cmdMapper(args []string) error {
	if len(args) == 0 || args[0] != "probes" {
		return fmt.Errorf("usage: mapper probes [--mapper <file>]")
	}
	fs := flag.NewFlagSet("openness-resolver mapper probes", flag.ExitOnError)
	mapper := fs.String("mapper", "", "application mapper file; default: the built-in one")
	fs.Parse(args[1:])
	d, err := loadMapper(*mapper)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(d.Probes())
}

// loadMapper returns the application mapper: the file when one is given, else the built-in.
func loadMapper(path string) (*appvuln.Data, error) {
	if path == "" {
		return appvuln.Builtin()
	}
	return appvuln.LoadFile(path)
}

// selectMapper picks the mapper resolve uses: --mapper when given, else the one feed sync
// put in the data directory, else the built-in one. The source names which, for
// rule_coverage.sources.
func selectMapper(flagPath, dataDir string) (*appvuln.Data, *resolver.CoverageSource, error) {
	src := &resolver.CoverageSource{Release: "mapper", Parser: appvuln.BundleFormat}
	path := flagPath
	if flagPath != "" {
		src.Source = "app-mapper-file"
	} else if _, err := os.Stat(appmapper.Path(dataDir)); err == nil {
		path, src.Source = appmapper.Path(dataDir), appmapper.ID
	}
	if path == "" {
		d, err := appvuln.Builtin()
		if err != nil {
			return nil, nil, err
		}
		src.Source, src.Version = "app-mapper-builtin", d.Version
		return d, src, nil
	}
	d, err := appvuln.LoadFile(path)
	if err != nil {
		return nil, nil, err
	}
	src.Version = d.Version
	if m, ok := appvuln.ReadMeta(path); ok {
		src.URL, src.SHA256 = m.SourceURL, m.SHA256
		if !m.DownloadedAt.IsZero() {
			t := m.DownloadedAt
			src.DownloadedAt = &t
		}
	}
	return d, src, nil
}

// installCopy copies src to dst through a temporary file next to dst.
func installCopy(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".import-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// distributionRuleDirs are the rule store vendor directories keyed by
// distribution and release. Only the releases an asset needs are loaded
// from them; every other directory (PyPI, MSRC) is always loaded.
var distributionRuleDirs = map[string]bool{
	"ubuntu": true, "alpine": true, "debian": true, "rocky": true,
	"almalinux": true, "rhel": true, "opensuse": true, "amazon": true,
}

// ruleFilesFor selects the rule files one asset needs: its host release and
// every release of a distribution found in its container images. Rules are
// matched by distribution and release, so the skipped files can never
// produce a finding for this asset; skipping them keeps resolve time and
// memory proportional to the asset instead of to the shared data directory.
func ruleFilesFor(lr *evidence.LoadResult) func(vendor, release string) bool {
	plat := platform.FromOS(lr.Doc.OperatingSystem, lr.Doc.Kernel)
	host := plat.DistributionID + "/" + plat.RuleRelease()
	imageDistros := map[string]bool{}
	for _, g := range containers.BuildInventory(lr.ContainerRecords()).Groups {
		if g.Distro != "" {
			imageDistros[g.Distro] = true
		}
	}
	return ruleFileFilter(host, imageDistros)
}

func ruleFileFilter(host string, imageDistros map[string]bool) func(vendor, release string) bool {
	return func(vendor, release string) bool {
		if !distributionRuleDirs[vendor] || imageDistros[vendor] {
			return true
		}
		return vendor+"/"+release == host
	}
}

// --- explain ---

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("openness-resolver explain", flag.ExitOnError)
	findingID := fs.String("finding-id", "", "finding id to explain")
	findingsFile := fs.String("findings", "findings.json", "findings JSON produced by resolve")
	fs.Parse(args)
	if *findingID == "" {
		return fmt.Errorf("explain requires --finding-id")
	}
	data, err := os.ReadFile(*findingsFile)
	if err != nil {
		return err
	}
	var res resolver.RunResult
	if err := json.Unmarshal(data, &res); err != nil {
		return err
	}
	for _, f := range res.Findings {
		if f.FindingID == *findingID {
			printExplanation(f)
			return nil
		}
	}
	return fmt.Errorf("finding %q not found in %s", *findingID, *findingsFile)
}

func printExplanation(f findings.Finding) {
	fmt.Printf("finding:          %s\n", f.FindingID)
	fmt.Printf("cve:              %s\n", f.CVEID)
	fmt.Printf("state:            %s (confidence %s)\n", f.State, f.Confidence)
	fmt.Printf("detection method: %s\n", f.DetectionMethod)
	fmt.Printf("\nobserved evidence:\n")
	fmt.Printf("  scope:            %s\n", f.Scope)
	if f.ImageDigest != "" {
		fmt.Printf("  image digest:     %s\n", f.ImageDigest)
		fmt.Printf("  containers:       %s\n", strings.Join(f.ContainerIDs, ", "))
	}
	fmt.Printf("  binary package:   %s\n", f.BinaryPackage)
	fmt.Printf("  source package:   %s (mapping: %s)\n", f.SourcePackage, f.SourceConfidence)
	fmt.Printf("  installed:        %s (%s)\n", f.InstalledVersion, f.Architecture)
	if f.Provenance != "" {
		fmt.Printf("  provenance:       %s", f.Provenance)
		if f.RepositorySuite != "" || f.RepositoryComponent != "" {
			fmt.Printf(" (suite %s, component %s)", f.RepositorySuite, f.RepositoryComponent)
		}
		fmt.Println()
	}
	fmt.Printf("  evidence ids:     %s\n", strings.Join(f.EvidenceIDs, ", "))
	if f.Rule != nil {
		fmt.Printf("\nvendor rule:\n")
		fmt.Printf("  rule id:          %s\n", f.Rule.RuleID)
		fmt.Printf("  source:           %s (%s)\n", f.Rule.Source, f.Rule.SourceURL)
		fmt.Printf("  feed snapshot:    %s\n", f.Rule.SourceSnapshot)
		fmt.Printf("  release:          %s\n", f.Rule.Release)
		fmt.Printf("  vendor status:    %s (raw: %s)\n", f.Rule.VendorStatus, f.Rule.RawStatus)
		if f.Rule.SupportTier != "" {
			fmt.Printf("  support tier:     %s\n", f.Rule.SupportTier)
		}
	}
	if f.Comparison != nil {
		fmt.Printf("\ncomparison:\n")
		fmt.Printf("  comparator:       %s\n", f.Comparison.Comparator)
		fmt.Printf("  expression:       %q with installed=%s fixed=%s\n", f.Comparison.Expression, f.Comparison.Installed, f.Comparison.Fixed)
		fmt.Printf("  result:           %v\n", f.Comparison.Result)
		if f.Comparison.Error != "" {
			fmt.Printf("  error:            %s\n", f.Comparison.Error)
		}
	}
	if f.RuntimeState != "" {
		fmt.Printf("\nruntime:\n")
		fmt.Printf("  state:            %s\n", f.RuntimeState)
		if len(f.RuntimeProcessIDs) > 0 {
			fmt.Printf("  processes:        %s\n", strings.Join(f.RuntimeProcessIDs, ", "))
		}
		if len(f.RuntimeBinaryPaths) > 0 {
			fmt.Printf("  binaries:         %s\n", strings.Join(f.RuntimeBinaryPaths, ", "))
		}
		if len(f.RuntimeServices) > 0 {
			fmt.Printf("  services:         %s\n", strings.Join(f.RuntimeServices, ", "))
		}
	}
	fmt.Printf("\nreasons:\n")
	for _, r := range f.Reasons {
		fmt.Printf("  - %s\n", r)
	}
	if len(f.MissingEvidence) > 0 {
		fmt.Printf("\nmissing evidence:\n")
		for _, m := range f.MissingEvidence {
			fmt.Printf("  - %s\n", m)
		}
	}
	if len(f.Conflicts) > 0 {
		fmt.Printf("\nconflicts:\n")
		for _, c := range f.Conflicts {
			fmt.Printf("  - %s\n", c)
		}
	}
	if len(f.SupersededRules) > 0 {
		fmt.Printf("\nsuperseded rules (older fixed versions):\n")
		for _, r := range f.SupersededRules {
			fmt.Printf("  - %s\n", r)
		}
	}
	fmt.Printf("\nall rule ids: %s\n", strings.Join(f.RuleIDs, ", "))
}

// --- compare-version ---

func cmdCompareVersion(args []string) error {
	fs := flag.NewFlagSet("openness-resolver compare-version", flag.ExitOnError)
	ecos := version.Ecosystems()
	sort.Strings(ecos)
	eco := fs.String("ecosystem", "", strings.Join(ecos, " | "))
	installed := fs.String("installed", "", "installed version")
	fixed := fs.String("fixed", "", "fixed version")
	fs.Parse(args)
	if *eco == "" || *installed == "" || *fixed == "" {
		return fmt.Errorf("compare-version requires --ecosystem, --installed and --fixed")
	}
	cmp, err := version.ForEcosystem(*eco)
	if err != nil {
		return err
	}
	c, err := cmp.Compare(*installed, *fixed)
	if err != nil {
		return err
	}
	rel := map[int]string{-1: "<", 0: "==", 1: ">"}[c]
	fmt.Printf("%s %s %s   (%s semantics)\n", *installed, rel, *fixed, *eco)
	if c < 0 {
		fmt.Println("installed version is OLDER than the fixed version")
	} else if c == 0 {
		fmt.Println("installed version EQUALS the fixed version")
	} else {
		fmt.Println("installed version is NEWER than the fixed version")
	}
	return nil
}

func cmdCompareNessus(args []string) error {
	fs := flag.NewFlagSet("openness-resolver compare-nessus", flag.ExitOnError)
	nessusPath := fs.String("nessus", "", "path to a .nessus (NessusClientData_v2) report")
	findingsPath := fs.String("findings", "build/findings.json", "resolver findings.json")
	host := fs.String("host", "", "target host name/IP in the Nessus report (optional if single host)")
	localOnly := fs.Bool("local-only", true, "compare only CVEs backed by a credentialed local security check")
	jsonOut := fs.String("json", "", "optional path to write the full diff as JSON")
	show := fs.Int("show", 15, "how many CVE ids to list per divergence bucket")
	fs.Parse(args)

	if *nessusPath == "" {
		return fmt.Errorf("compare-nessus requires --nessus <report.nessus>")
	}
	nr, err := compare.ParseNessusFile(*nessusPath, *host)
	if err != nil {
		return err
	}
	rv, err := compare.LoadResolverView(*findingsPath)
	if err != nil {
		return err
	}
	d := compare.Compare(rv, nr, *localOnly)

	if !nr.LocalChecksPresent {
		fmt.Fprintln(os.Stderr, "WARNING: no credentialed local security check plugins found in the Nessus report.")
		fmt.Fprintln(os.Stderr, "         This looks like an uncredentialed scan; package-level CVE comparison is not meaningful.")
	}
	fmt.Printf("resolver asset:   %s\n", d.ResolverAsset)
	fmt.Printf("nessus host:      %s (%s)\n", d.NessusHost, d.NessusOS)
	fmt.Printf("local checks:     present=%v  compared_local_only=%v\n\n", d.NessusLocalChecks, d.ComparedLocalOnly)

	fmt.Printf("host-scope CVE comparison:\n")
	fmt.Printf("  resolver vulnerable:  %d\n", d.Counts["resolver_vulnerable_host"])
	fmt.Printf("  nessus vulnerable:    %d\n", d.Counts["nessus_vulnerable_host"])
	fmt.Printf("  agreement:            %d\n", d.Counts["agreement"])
	fmt.Printf("  only resolver:        %d (of which kernel: %d)\n", d.Counts["only_resolver"], d.Counts["only_resolver_kernel"])
	fmt.Printf("  only nessus:          %d\n", d.Counts["only_nessus"])
	fmt.Printf("    ...resolver said fixed:      %d\n", d.Counts["nessus_flagged_resolver_fixed"])
	fmt.Printf("    ...resolver saw in container: %d\n", d.Counts["nessus_matched_container_only"])
	fmt.Printf("  (container vulnerable, out of host-scan scope: %d)\n\n", d.Counts["resolver_container_vulnerable"])

	printBucket := func(name string, cves []string) {
		fmt.Printf("%s (%d):\n", name, len(cves))
		for i, c := range cves {
			if i >= *show {
				fmt.Printf("  ... and %d more\n", len(cves)-*show)
				break
			}
			fmt.Printf("  %s\n", c)
		}
		fmt.Println()
	}
	printBucket("only nessus (potential resolver gaps)", d.OnlyNessus)
	printBucket("nessus-flagged but resolver decided FIXED (inspect)", d.NessusVsResolverFixed)
	printBucket("only resolver (kernel, Nessus often defers)", d.OnlyResolverKernel)

	if *jsonOut != "" {
		raw, _ := json.MarshalIndent(d, "", "  ")
		if err := os.WriteFile(*jsonOut, append(raw, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("full diff written to %s\n", *jsonOut)
	}
	return nil
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
