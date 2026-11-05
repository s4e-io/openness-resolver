package main

// Table-driven tests of every command and flag of the CLI: valid values,
// defaults, and invalid values with a clear error. Each case runs the real
// binary offline (see cli_helpers_test.go).
//
// Exit codes: 0 success, 1 a command error ("error: ..."), 2 a usage error
// (unknown command, or a flag value the flag parser rejects).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

type flagCase struct {
	name string
	args []string // "{tmp}" is replaced with the case's own empty directory
	env  []string // extra environment variables
	// inTmp runs the binary with the case directory as working directory, to
	// exercise defaults that are relative paths (data, findings.json).
	inTmp     bool
	setup     func(t *testing.T, tmp string)
	code      int
	stdout    []string // substrings stdout must contain
	stderr    []string // substrings stderr must contain
	notStdout []string
	check     func(t *testing.T, tmp string, r cliResult)
}

func runFlagCases(t *testing.T, cases []flagCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, tmp)
			}
			args := make([]string, len(tc.args))
			for i, a := range tc.args {
				args[i] = strings.ReplaceAll(a, "{tmp}", tmp)
			}
			dir := ""
			if tc.inTmp {
				dir = tmp
			}
			r := runCLI(t, dir, offlineEnv(tc.env...), args...)
			if r.Code != tc.code {
				t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.Code, tc.code, r.Stdout, r.Stderr)
			}
			for _, s := range tc.stdout {
				if !strings.Contains(r.Stdout, s) {
					t.Errorf("stdout lacks %q:\n%s", s, r.Stdout)
				}
			}
			for _, s := range tc.notStdout {
				if strings.Contains(r.Stdout, s) {
					t.Errorf("stdout has %q:\n%s", s, r.Stdout)
				}
			}
			for _, s := range tc.stderr {
				if !strings.Contains(r.Stderr, s) {
					t.Errorf("stderr lacks %q:\n%s", s, r.Stderr)
				}
			}
			if tc.check != nil {
				tc.check(t, tmp, r)
			}
		})
	}
}

// shared is a data directory and findings files built once for the cases
// that need existing rules or findings.
type sharedFixture struct {
	dir            string
	data           string // ubuntu jammy (with PyPI) and alpine v3.20 rules
	ubuntuFindings string
	alpineFindings string
}

var (
	sharedOnce sync.Once
	sharedFx   sharedFixture
	sharedErr  string
)

func shared(t *testing.T) sharedFixture {
	t.Helper()
	sharedOnce.Do(func() {
		dir, err := os.MkdirTemp("", "openness-shared-")
		if err != nil {
			sharedErr = err.Error()
			return
		}
		fx := sharedFixture{dir: dir, data: filepath.Join(dir, "data")}
		steps := [][]string{
			{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", fixture("testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml"), "--data-dir", fx.data},
			{"rules", "import", "--source", "alpine-secdb-v3.20", "--file", fixture("testdata/feeds/alpine/v3.20/main.json"), "--data-dir", fx.data},
			{"rules", "import", "--source", "alpine-secdb-v3.20", "--file", fixture("testdata/feeds/alpine/v3.20/community.json"), "--data-dir", fx.data},
		}
		for _, s := range steps {
			if r := run(t, s...); r.Code != 0 {
				sharedErr = strings.Join(s, " ") + ": " + r.Stderr
				return
			}
		}
		pypiZip := packZip(t, fixture("testdata/feeds/osv/pypi"), filepath.Join(dir, "pypi-all.zip"))
		if r := run(t, "rules", "import", "--source", "osv-pypi", "--file", pypiZip, "--data-dir", fx.data); r.Code != 0 {
			sharedErr = "pypi import: " + r.Stdout + r.Stderr
			return
		}
		fx.ubuntuFindings = filepath.Join(dir, "ubuntu-findings.json")
		fx.alpineFindings = filepath.Join(dir, "alpine-findings.json")
		if r := run(t, "resolve", "--input", evidencePath("ubuntu-22.04-jammy"), "--data-dir", fx.data, "--output", fx.ubuntuFindings); r.Code != 0 {
			sharedErr = "resolve ubuntu: " + r.Stderr
			return
		}
		if r := run(t, "resolve", "--input", evidencePath("alpine-3.20"), "--data-dir", fx.data, "--output", fx.alpineFindings); r.Code != 0 {
			sharedErr = "resolve alpine: " + r.Stderr
			return
		}
		sharedFx = fx
	})
	if sharedErr != "" {
		t.Fatal(sharedErr)
	}
	return sharedFx
}

// --- top level ---

func TestFlagsTopLevel(t *testing.T) {
	runFlagCases(t, []flagCase{
		{name: "no command", code: 2, stderr: []string{"usage: openness-resolver <command>"}},
		{name: "help", args: []string{"help"}, stderr: []string{"usage: openness-resolver <command>", "feed sync", "resolve"}},
		{name: "-h", args: []string{"-h"}, stderr: []string{"usage: openness-resolver <command>"}},
		{name: "--help", args: []string{"--help"}, stderr: []string{"usage: openness-resolver <command>"}},
		{name: "unknown command", args: []string{"frobnicate"}, code: 2, stderr: []string{`unknown command "frobnicate"`}},
		{name: "version", args: []string{"version"}, stdout: []string{"openness-resolver ", "commit=", "built="}},
	})
}

// --- feed ---

func countLines(s, prefix string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func TestFlagsFeed(t *testing.T) {
	enabled := 0
	for _, s := range rules.Registry() {
		if s.Enabled {
			enabled++
		}
	}
	ubuntu := evidencePath("ubuntu-22.04-jammy")
	runFlagCases(t, []flagCase{
		{name: "no subcommand", args: []string{"feed"}, code: 1, stderr: []string{"feed requires a subcommand: sync | list | validate"}},
		{name: "unknown subcommand", args: []string{"feed", "pull"}, code: 1, stderr: []string{`unknown feed subcommand "pull"`}},
		{name: "unknown flag", args: []string{"feed", "sync", "--bogus"}, code: 2, stderr: []string{"flag provided but not defined: -bogus"}},

		// feed list, --data-dir default and explicit.
		{name: "list default data dir", args: []string{"feed", "list"}, inTmp: true,
			stdout: []string{"ID", "ubuntu-oval-usn-jammy", "debian-security-tracker", "osv-rocky", "alpine-secdb-v3.20"}},
		{name: "list data-dir", args: []string{"feed", "list", "--data-dir", "{tmp}"}, stdout: []string{"amazon-updateinfo-2023"}},

		// Selection: --source, --vendor, --all, --for, --months. --dry-run downloads nothing.
		{name: "sync nothing selected", args: []string{"feed", "sync", "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{"no sources selected (use --for, --source, --vendor or --all"}},
		{name: "source registry id", args: []string{"feed", "sync", "--source", "debian-security-tracker", "--dry-run"},
			stdout: []string{"source debian-security-tracker https://security-tracker.debian.org/tracker/data/json"}},
		{name: "source release id ubuntu", args: []string{"feed", "sync", "--source", "ubuntu-oval-usn-noble", "--dry-run"},
			stdout: []string{"source ubuntu-oval-usn-noble https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2"}},
		{name: "source release id alpine", args: []string{"feed", "sync", "--source", "alpine-secdb-v3.20", "--dry-run"},
			stdout: []string{"source alpine-secdb-v3.20 https://secdb.alpinelinux.org/v3.20/main.json"}},
		{name: "source release id msrc", args: []string{"feed", "sync", "--source", "msrc-cvrf-2026-Oct", "--dry-run"},
			stdout: []string{"source msrc-cvrf-2026-Oct https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"}},
		{name: "source unknown", args: []string{"feed", "sync", "--source", "nvd", "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{`unknown source id "nvd"`}},
		{name: "source bad release", args: []string{"feed", "sync", "--source", "alpine-secdb-3.20", "--dry-run"}, code: 1,
			stderr: []string{"unknown source id"}},
		{name: "vendor debian", args: []string{"feed", "sync", "--vendor", "debian", "--dry-run"},
			stdout: []string{"source debian-security-tracker "}},
		{name: "vendor alpine", args: []string{"feed", "sync", "--vendor", "alpine", "--dry-run"},
			stdout: []string{"source alpine-secdb-v3.14 ", "source alpine-secdb-v3.22-community "}},
		{name: "vendor amazon", args: []string{"feed", "sync", "--vendor", "amazon", "--dry-run"},
			stdout: []string{"source amazon-updateinfo-2 https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list", "source amazon-updateinfo-2023 "}},
		{name: "vendor microsoft default months", args: []string{"feed", "sync", "--vendor", "microsoft", "--dry-run"},
			check: func(t *testing.T, _ string, r cliResult) {
				if n := countLines(r.Stdout, "source msrc-cvrf-"); n != 24 {
					t.Errorf("default --months: %d MSRC months, want 24", n)
				}
			}},
		{name: "vendor microsoft months 3", args: []string{"feed", "sync", "--vendor", "microsoft", "--months", "3", "--dry-run"},
			check: func(t *testing.T, _ string, r cliResult) {
				if n := countLines(r.Stdout, "source msrc-cvrf-"); n != 3 {
					t.Errorf("--months 3: %d MSRC months, want 3", n)
				}
				if want := "source msrc-cvrf-" + time.Now().UTC().Format("2006-Jan"); !strings.Contains(r.Stdout, want) {
					t.Errorf("newest month missing: %s", want)
				}
			}},
		{name: "vendor unknown", args: []string{"feed", "sync", "--vendor", "fedora"}, code: 1,
			stderr: []string{`unknown vendor "fedora" (one of: almalinux, alpine, amazon, debian, microsoft, openness, opensuse, pypi, rhel, rocky, ubuntu)`}},
		{name: "months zero", args: []string{"feed", "sync", "--vendor", "microsoft", "--months", "0"}, code: 1,
			stderr: []string{"--months must be at least 1, got 0"}},
		{name: "months not a number", args: []string{"feed", "sync", "--months", "two"}, code: 2,
			stderr: []string{`invalid value "two" for flag -months`}},
		{name: "all", args: []string{"feed", "sync", "--all", "--dry-run"},
			check: func(t *testing.T, _ string, r cliResult) {
				if n := countLines(r.Stdout, "source "); n != enabled {
					t.Errorf("--all: %d sources, want the %d enabled registry sources", n, enabled)
				}
			}},
		{name: "all not a bool", args: []string{"feed", "sync", "--all=maybe"}, code: 2,
			stderr: []string{`invalid boolean value "maybe" for -all`}},
		{name: "for ubuntu", args: []string{"feed", "sync", "--for", ubuntu, "--dry-run"},
			stdout: []string{"host ubuntu 22.04 (release key jammy)", "source ubuntu-oval-usn-jammy ", "host: 1 PyPI packages -> osv-pypi", "source osv-pypi https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"}},
		{name: "for debian", args: []string{"feed", "sync", "--for", evidencePath("debian-12-bookworm"), "--dry-run"},
			stdout: []string{"source debian-security-tracker "}},
		{name: "for debian unsupported release", args: []string{"feed", "sync", "--for", evidencePath("debian-11-bullseye"), "--dry-run"},
			stdout: []string{"bullseye", "source debian-security-tracker "}},
		{name: "for rocky", args: []string{"feed", "sync", "--for", evidencePath("rocky-9"), "--dry-run"},
			stdout: []string{"source osv-rocky https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip"}},
		{name: "for almalinux", args: []string{"feed", "sync", "--for", evidencePath("almalinux-8"), "--dry-run"},
			stdout: []string{"source osv-almalinux "}},
		{name: "for rhel", args: []string{"feed", "sync", "--for", evidencePath("rhel-9"), "--dry-run"},
			stdout: []string{"source osv-rhel "}},
		{name: "for opensuse", args: []string{"feed", "sync", "--for", evidencePath("opensuse-leap-15.6"), "--dry-run"},
			stdout: []string{"source osv-opensuse "}},
		{name: "for alpine", args: []string{"feed", "sync", "--for", evidencePath("alpine-3.20"), "--dry-run"},
			stdout: []string{"source alpine-secdb-v3.20 ", "source alpine-secdb-v3.20-community "}},
		{name: "for windows with months", args: []string{"feed", "sync", "--for", evidencePath("windows-server-2022"), "--months", "2", "--dry-run"},
			stdout: []string{"host: windows windows_server_2022 build 20348.1000 -> MSRC CVRF, last 2 months"},
			check: func(t *testing.T, _ string, r cliResult) {
				if n := countLines(r.Stdout, "source msrc-cvrf-"); n != 2 {
					t.Errorf("%d MSRC months, want 2", n)
				}
			}},
		{name: "for missing file", args: []string{"feed", "sync", "--for", filepath.Join("{tmp}", "nope.openness")}, code: 1,
			stderr: []string{"nope.openness"}},
		{name: "for and source combined", args: []string{"feed", "sync", "--for", evidencePath("rocky-9"), "--source", "osv-rhel", "--dry-run"},
			stdout: []string{"source osv-rocky ", "source osv-rhel "}},

		// --pypi-only and --osv-url are deprecated: osv-pypi alone, --osv-url ignored, and a
		// failed download is a warning with exit 0.
		{name: "pypi-only needs for", args: []string{"feed", "sync", "--pypi-only"}, code: 1, stderr: []string{"--pypi-only needs --for"}},
		{name: "pypi-only without pypi packages", args: []string{"feed", "sync", "--for", evidencePath("rocky-9"), "--pypi-only", "--data-dir", "{tmp}"},
			stdout: []string{"no PyPI packages in the evidence"}},
		{name: "pypi-only osv-url dry run", args: []string{"feed", "sync", "--for", ubuntu, "--pypi-only", "--osv-url", "http://127.0.0.1:9/v1/query", "--dry-run"},
			stdout: []string{"source osv-pypi https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"}, notStdout: []string{"ubuntu-oval"},
			stderr: []string{"--osv-url is deprecated and ignored", "--pypi-only is deprecated"}},
		{name: "pypi-only unreachable is a warning", args: []string{"feed", "sync", "--for", ubuntu, "--pypi-only", "--data-dir", "{tmp}"},
			stdout: []string{"WARNING: PyPI data could not be synced"}},
		{name: "vendor pypi", args: []string{"feed", "sync", "--vendor", "pypi", "--dry-run"},
			stdout: []string{"source osv-pypi https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"}},

		// feed validate selects every enabled source by default.
		{name: "validate default", args: []string{"feed", "validate", "--dry-run"},
			check: func(t *testing.T, _ string, r cliResult) {
				if n := countLines(r.Stdout, "source "); n != enabled {
					t.Errorf("validate: %d sources, want %d", n, enabled)
				}
			}},
		{name: "validate source", args: []string{"feed", "validate", "--source", "osv-rhel", "--dry-run"},
			stdout: []string{"source osv-rhel "}, notStdout: []string{"source osv-rocky"}},
		{name: "validate unknown source", args: []string{"feed", "validate", "--source", "bogus"}, code: 1, stderr: []string{`unknown source id "bogus"`}},
	})
}

func assertPyPIRules(t *testing.T, dataDir, pkg string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "normalized", "pypi", "pypi", "rules.json"))
	if err != nil {
		t.Fatalf("no PyPI rules written: %v", err)
	}
	if !strings.Contains(string(raw), `"package_name": "`+pkg+`"`) {
		t.Errorf("PyPI rules lack %s", pkg)
	}
}

// --- rules ---

func readMeta(t *testing.T, path string) rules.FeedSourceMetadata {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m rules.FeedSourceMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ruleCount(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("rules file: %v", err)
	}
	var rs []json.RawMessage
	if err := json.Unmarshal(raw, &rs); err != nil {
		var wrapped struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 != nil {
			t.Fatalf("rules file %s: %v", path, err)
		}
		rs = wrapped.Rules
	}
	return len(rs)
}

func TestFlagsRules(t *testing.T) {
	sh := shared(t)
	oval := fixture("testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml")
	importCase := func(name, source, file string, rulesFile ...string) flagCase {
		return flagCase{name: name, args: []string{"rules", "import", "--source", source, "--file", fixture(file), "--data-dir", "{tmp}"},
			stdout: []string{"rules="},
			check: func(t *testing.T, tmp string, _ cliResult) {
				p := filepath.Join(append([]string{tmp, "normalized"}, rulesFile...)...)
				if n := ruleCount(t, filepath.Join(p, "rules.json")); n == 0 {
					t.Errorf("%s: no rules", p)
				}
			}}
	}
	runFlagCases(t, []flagCase{
		{name: "no subcommand", args: []string{"rules"}, code: 1, stderr: []string{"rules requires a subcommand: import | stats | format"}},
		{name: "unknown subcommand", args: []string{"rules", "export"}, code: 1, stderr: []string{`unknown rules subcommand "export"`}},

		// rules format
		{name: "format", args: []string{"rules", "format"}, stdout: []string{`"format"`, `"parsers"`, `"ubuntu-oval"`, `"msrc-cvrf"`, `"osv-pypi"`}},

		// rules stats, --data-dir default and explicit.
		{name: "stats", args: []string{"rules", "stats", "--data-dir", sh.data}, stdout: []string{"{"}},
		{name: "stats default data dir", args: []string{"rules", "stats"}, inTmp: true, stdout: []string{"{"}},

		// rules import: every parser, release-derived and data mirror ids.
		importCase("import ubuntu oval", "ubuntu-oval-usn-jammy", "testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml", "ubuntu", "jammy"),
		importCase("import alpine main", "alpine-secdb-v3.20", "testdata/feeds/alpine/v3.20/main.json", "alpine", "v3.20"),
		importCase("import alpine community by file name", "alpine-secdb-v3.20", "testdata/feeds/alpine/v3.20/community.json", "alpine", "v3.20"),
		importCase("import debian tracker", "debian-security-tracker", "testdata/feeds/debian/tracker-sample.json", "debian", "bookworm"),
		importCase("import debian mirror id", "debian-tracker", "testdata/feeds/debian/tracker-sample.json", "debian", "trixie"),
		importCase("import osv distro single document", "osv-rocky", "testdata/feeds/osv/rocky/RLSA-2024_3501.json", "rocky", "9"),
		importCase("import osv rhel mirror id", "osv-redhat", "testdata/feeds/osv/rhel/RHSA-2024_3501.json", "rhel", "9"),
		importCase("import amazon updateinfo", "amazon-updateinfo-2023", "testdata/feeds/amazon/updateinfo-2023.xml", "amazon", "2023"),
		importCase("import amazon mirror id", "amazon-al2023", "testdata/feeds/amazon/updateinfo-2023.xml", "amazon", "2023"),
		importCase("import msrc", "msrc-cvrf-2026-Oct", "internal/resolver/testdata/msrc/2026-Oct.json", "microsoft", "windows_server_2022"),
		importCase("import msrc mirror id", "msrc-2026-Oct", "internal/resolver/testdata/msrc/2026-Oct.json", "microsoft", "windows_server_2022"),
		{name: "import osv-pypi zip", args: []string{"rules", "import", "--source", "osv-pypi", "--file", "{tmp}/pypi-all.zip", "--fetched-at", "2026-11-05T00:00:00Z", "--data-dir", "{tmp}"},
			setup: func(t *testing.T, tmp string) {
				packZip(t, fixture("testdata/feeds/osv/pypi"), filepath.Join(tmp, "pypi-all.zip"))
			},
			check: func(t *testing.T, tmp string, _ cliResult) {
				assertPyPIRules(t, tmp, "psutil")
				m := readMeta(t, filepath.Join(tmp, "normalized", "pypi", "pypi", "metadata.json"))
				if m.SourceName != "osv-pypi" || len(m.PackageNames) != 0 || m.SHA256 == "" {
					t.Errorf("metadata %+v", m)
				}
			}},
		{name: "import osv distro zip", args: []string{"rules", "import", "--source", "osv-almalinux", "--file", "{tmp}/almalinux-all.zip", "--data-dir", "{tmp}"},
			setup: func(t *testing.T, tmp string) {
				packZip(t, fixture("testdata/feeds/osv/almalinux"), filepath.Join(tmp, "almalinux-all.zip"))
			},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if ruleCount(t, filepath.Join(tmp, "normalized", "almalinux", "8", "rules.json")) == 0 {
					t.Error("no almalinux 8 rules")
				}
			}},
		{name: "import source-url and fetched-at", args: []string{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", oval,
			"--source-url", "https://mirror.example.org/oval/jammy.xml", "--fetched-at", "2026-05-01T12:30:00+02:00", "--data-dir", "{tmp}"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				m := readMeta(t, filepath.Join(tmp, "normalized", "ubuntu", "jammy", "metadata.json"))
				if m.SourceURL != "https://mirror.example.org/oval/jammy.xml" {
					t.Errorf("source_url=%s", m.SourceURL)
				}
				if !m.DownloadedAt.Equal(time.Date(2026, 5, 1, 10, 30, 0, 0, time.UTC)) {
					t.Errorf("downloaded_at=%s", m.DownloadedAt)
				}
			}},
		{name: "import defaults", args: []string{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", oval}, inTmp: true,
			check: func(t *testing.T, tmp string, _ cliResult) {
				// --data-dir defaults to ./data, --source-url to the publisher URL, --fetched-at to now.
				m := readMeta(t, filepath.Join(tmp, "data", "normalized", "ubuntu", "jammy", "metadata.json"))
				if m.SourceURL != "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2" {
					t.Errorf("source_url=%s", m.SourceURL)
				}
				if time.Since(m.DownloadedAt) > time.Hour || m.DownloadedAt.After(time.Now().Add(time.Minute)) {
					t.Errorf("downloaded_at=%s, want now", m.DownloadedAt)
				}
			}},
		{name: "import missing flags", args: []string{"rules", "import", "--source", "ubuntu-oval-usn-jammy"}, code: 1,
			stderr: []string{"rules import requires --source and --file"}},
		{name: "import missing source", args: []string{"rules", "import", "--file", oval}, code: 1,
			stderr: []string{"rules import requires --source and --file"}},
		{name: "import unknown source", args: []string{"rules", "import", "--source", "nvd", "--file", oval, "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{`unknown source "nvd"`}},
		{name: "import missing file", args: []string{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", filepath.Join("{tmp}", "none.xml"), "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{"none.xml"}},
		{name: "import bad fetched-at", args: []string{"rules", "import", "--source", "ubuntu-oval-usn-jammy", "--file", oval, "--fetched-at", "yesterday", "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{"--fetched-at: parsing time"}},
		{name: "import malformed file", args: []string{"rules", "import", "--source", "msrc-cvrf-2026-Oct", "--file", oval, "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{"decode cvrf json"}},
		{name: "import parser of a disabled source", args: []string{"rules", "import", "--source", "osv", "--file", oval, "--data-dir", "{tmp}"}, code: 1,
			stderr: []string{`parser "osv" not implemented`}},
	})
}

// --- resolve ---

func writeEvidence(t *testing.T, dst, name string, edit func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(evidencePath(name))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// windowsApps writes Windows evidence with three applications and a mapper
// file: Firefox ESR (a reviewed catalog entry), "Auto Tool" (an entry no person
// reviewed) and KeePass (unknown to the catalog, guessed from NVD names).
func windowsApps(t *testing.T, tmp string) {
	t.Helper()
	writeEvidence(t, filepath.Join(tmp, "apps.openness"), "windows-server-2022", func(doc map[string]any) {
		var apps []any
		for i, a := range []map[string]any{
			{"product_name": "Mozilla Firefox ESR (x64 en-US)", "display_version": "115.3.1", "publisher": "Mozilla"},
			{"product_name": "Auto Tool", "display_version": "1.0"},
			{"product_name": "KeePass Password Safe 2.40", "display_version": "2.40", "publisher": "Dominik Reichl"},
		} {
			apps = append(apps, map[string]any{"evidence_id": "ev-app-" + string(rune('0'+i)), "source": "native",
				"source_module": "applications", "observed_at": "2026-10-30T10:00:00Z", "collection_status": "observed", "value": a})
		}
		doc["applications"] = apps
	})
	bundle := map[string]any{
		"format": "openness-app-mapper/1", "version": "test-mapper-1",
		"catalog": []any{
			map[string]any{"id": "Mozilla.Firefox.ESR", "name": "Mozilla Firefox ESR", "match": map[string]any{"name": `^Mozilla Firefox.*\bESR\b`, "publisher": "Mozilla"},
				"version": map[string]any{}, "cpe": []string{"mozilla:firefox_esr"}, "update": "winget upgrade --id Mozilla.Firefox.ESR", "verified": true},
			map[string]any{"id": "Auto.Tool", "name": "Auto Tool", "match": map[string]any{"name": "^Auto Tool"},
				"version": map[string]any{}, "cpe": []string{"auto:tool"}, "verified": false},
		},
		"vulns": map[string]any{"version": "t", "products": map[string]any{
			"mozilla:firefox_esr": []any{map[string]any{"cve": "CVE-2099-0001", "cvss": 9.8, "sev": "critical", "r": []any{map[string]any{"si": "115.0", "ee": "115.10"}}}},
			"auto:tool":           []any{map[string]any{"cve": "CVE-2099-0005", "sev": "low", "r": []any{map[string]any{"ee": "9"}}}},
		}},
	}
	raw, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(tmp, "mapper.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

type appState struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func readApps(t *testing.T, path string) (map[string]string, string, []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Applications      []appState `json:"applications"`
		ApplicationMapper string     `json:"application_mapper"`
		Findings          []struct {
			CVEID string `json:"cve_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, a := range doc.Applications {
		out[a.Name] = a.Status
	}
	var cves []string
	for _, f := range doc.Findings {
		cves = append(cves, f.CVEID)
	}
	return out, doc.ApplicationMapper, cves
}

func TestFlagsResolve(t *testing.T) {
	sh := shared(t)
	ubuntu := evidencePath("ubuntu-22.04-jammy")
	alpine := evidencePath("alpine-3.20")
	out := filepath.Join("{tmp}", "out.json")
	runFlagCases(t, []flagCase{
		{name: "missing input", args: []string{"resolve"}, code: 1, stderr: []string{"resolve requires --input <file.openness>"}},
		{name: "input not found", args: []string{"resolve", "--input", filepath.Join("{tmp}", "none.openness"), "--output", out}, code: 1,
			stderr: []string{"none.openness"}},
		{name: "input not evidence", args: []string{"resolve", "--input", fixture("testdata/feeds/alpine/v3.20/main.json"), "--data-dir", sh.data, "--output", out}, code: 1},
		{name: "input data-dir output", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out},
			stdout: []string{"rule coverage: ", "findings written to "},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if _, err := os.Stat(filepath.Join(tmp, "out.json")); err != nil {
					t.Error(err)
				}
			}},
		{name: "defaults output and data-dir", args: []string{"resolve", "--input", alpine}, inTmp: true,
			setup: func(t *testing.T, tmp string) {
				for _, f := range []string{"main.json", "community.json"} {
					r := runCLI(t, tmp, offlineEnv(), "rules", "import", "--source", "alpine-secdb-v3.20", "--file", mustAbs(t, fixture("testdata/feeds/alpine/v3.20/"+f)))
					if r.Code != 0 {
						t.Fatal(r.Stderr)
					}
				}
			},
			stdout: []string{"findings written to findings.json"},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if _, err := os.Stat(filepath.Join(tmp, "findings.json")); err != nil {
					t.Error(err)
				}
			}},
		{name: "empty data dir exits 1", args: []string{"resolve", "--input", alpine, "--data-dir", "{tmp}", "--output", out}, code: 1,
			stderr: []string{"warning: rule store is empty", "error: finding counts are not an all-clear: no rules loaded for alpine/v3.20"}},
		{name: "states filter", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out, "--states", "fixed"},
			stdout: []string{"CVE-2022-37434"}, notStdout: []string{"CVE-2024-4603"}},
		{name: "states two", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out, "--states", "vulnerable, not_applicable"},
			stdout: []string{"CVE-2024-4603", "CVE-2022-30065"}, notStdout: []string{"CVE-2022-37434"}},
		{name: "states unknown value lists nothing", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out, "--states", "bogus"},
			notStdout: []string{"finding-"}},
		{name: "preflight valid", args: []string{"resolve", "--input", ubuntu, "--data-dir", sh.data, "--output", out, "--preflight"}},
		{name: "preflight rejects evidence without asset id", args: []string{"resolve", "--input", filepath.Join("{tmp}", "noid.openness"), "--data-dir", sh.data, "--output", out, "--preflight"},
			setup: func(t *testing.T, tmp string) {
				writeEvidence(t, filepath.Join(tmp, "noid.openness"), "alpine-3.20", func(doc map[string]any) {
					doc["asset"].(map[string]any)["asset_id"] = ""
				})
			},
			code: 1, stderr: []string{"preflight: schema_version and asset.asset_id are required"}},
		{name: "preflight not a bool", args: []string{"resolve", "--input", alpine, "--preflight=sure"}, code: 2,
			stderr: []string{`invalid boolean value "sure" for -preflight`}},
		{name: "mapper file", args: []string{"resolve", "--input", filepath.Join("{tmp}", "apps.openness"), "--data-dir", "{tmp}", "--output", out, "--mapper", filepath.Join("{tmp}", "mapper.json")},
			setup: windowsApps, code: 1, // no MSRC rules in the data dir: not an all-clear
			check: func(t *testing.T, tmp string, _ cliResult) {
				apps, version, cves := readApps(t, filepath.Join(tmp, "out.json"))
				if version != "test-mapper-1" {
					t.Errorf("application_mapper=%q", version)
				}
				if apps["Mozilla Firefox ESR (x64 en-US)"] != "matched" || apps["Auto Tool"] != "unverified" {
					t.Errorf("applications %v", apps)
				}
				if strings.Join(cves, " ") != "CVE-2099-0001" {
					t.Errorf("findings %v", cves)
				}
			}},
		{name: "mapper default is built in", args: []string{"resolve", "--input", filepath.Join("{tmp}", "apps.openness"), "--data-dir", "{tmp}", "--output", out},
			setup: windowsApps, code: 1,
			check: func(t *testing.T, tmp string, _ cliResult) {
				_, version, _ := readApps(t, filepath.Join(tmp, "out.json"))
				if version == "" || version == "test-mapper-1" {
					t.Errorf("application_mapper=%q, want the built-in version", version)
				}
			}},
		{name: "mapper not found", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out, "--mapper", filepath.Join("{tmp}", "none.json")}, code: 1,
			stderr: []string{"mapper: "}},
		{name: "mapper wrong format", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", out, "--mapper", fixture("testdata/feeds/alpine/v3.20/main.json")}, code: 1,
			stderr: []string{`want "openness-app-mapper/1"`}},
		{name: "app-unverified", args: []string{"resolve", "--input", filepath.Join("{tmp}", "apps.openness"), "--data-dir", "{tmp}", "--output", out, "--mapper", filepath.Join("{tmp}", "mapper.json"), "--app-unverified"},
			setup: windowsApps, code: 1,
			check: func(t *testing.T, tmp string, _ cliResult) {
				apps, _, cves := readApps(t, filepath.Join(tmp, "out.json"))
				if apps["Auto Tool"] != "matched" || !strings.Contains(strings.Join(cves, " "), "CVE-2099-0005") {
					t.Errorf("applications %v findings %v", apps, cves)
				}
			}},
		{name: "app-guess default on", args: []string{"resolve", "--input", filepath.Join("{tmp}", "apps.openness"), "--data-dir", "{tmp}", "--output", out, "--mapper", filepath.Join("{tmp}", "mapper.json")},
			setup: windowsApps, code: 1,
			check: func(t *testing.T, tmp string, _ cliResult) {
				if apps, _, _ := readApps(t, filepath.Join(tmp, "out.json")); apps["KeePass Password Safe 2.40"] != "guessed" {
					t.Errorf("applications %v", apps)
				}
			}},
		{name: "app-guess false", args: []string{"resolve", "--input", filepath.Join("{tmp}", "apps.openness"), "--data-dir", "{tmp}", "--output", out, "--mapper", filepath.Join("{tmp}", "mapper.json"), "--app-guess=false"},
			setup: windowsApps, code: 1,
			check: func(t *testing.T, tmp string, _ cliResult) {
				if apps, _, _ := readApps(t, filepath.Join(tmp, "out.json")); apps["KeePass Password Safe 2.40"] != "unmatched" {
					t.Errorf("applications %v", apps)
				}
			}},
		{name: "app-guess not a bool", args: []string{"resolve", "--input", alpine, "--app-guess=perhaps"}, code: 2,
			stderr: []string{`invalid boolean value "perhaps" for -app-guess`}},
		{name: "output dir is created", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", filepath.Join("{tmp}", "new", "dir", "f.json")},
			check: func(t *testing.T, tmp string, _ cliResult) {
				if _, err := os.Stat(filepath.Join(tmp, "new", "dir", "f.json")); err != nil {
					t.Error(err)
				}
			}},
		{name: "output is a directory", args: []string{"resolve", "--input", alpine, "--data-dir", sh.data, "--output", "{tmp}"}, code: 1},
	})
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// --- explain ---

// firstFindingID returns the first vulnerable finding of a findings file.
func firstFindingID(t *testing.T, path string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			ID    string `json:"finding_id"`
			CVEID string `json:"cve_id"`
			State string `json:"state"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("findings %s: %v", path, err)
	}
	for _, f := range doc.Findings {
		if f.State == "vulnerable" {
			return f.ID, f.CVEID
		}
	}
	t.Fatalf("no vulnerable finding in %s", path)
	return "", ""
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFlagsExplain(t *testing.T) {
	sh := shared(t)
	id, cve := firstFindingID(t, sh.alpineFindings)
	runFlagCases(t, []flagCase{
		{name: "missing finding-id", args: []string{"explain"}, code: 1, stderr: []string{"explain requires --finding-id"}},
		{name: "finding-id and findings", args: []string{"explain", "--finding-id", id, "--findings", sh.alpineFindings},
			stdout: []string{"finding:          " + id, "cve:              " + cve, "vendor rule:", "comparison:", "reasons:"}},
		{name: "findings default", args: []string{"explain", "--finding-id", id}, inTmp: true,
			setup: func(t *testing.T, tmp string) {
				copyFile(t, sh.alpineFindings, filepath.Join(tmp, "findings.json"))
			},
			stdout: []string{"finding:          " + id}},
		{name: "unknown finding", args: []string{"explain", "--finding-id", "finding-0000", "--findings", sh.alpineFindings}, code: 1,
			stderr: []string{`finding "finding-0000" not found in`}},
		{name: "findings not found", args: []string{"explain", "--finding-id", id, "--findings", filepath.Join("{tmp}", "none.json")}, code: 1,
			stderr: []string{"none.json"}},
		{name: "findings not json", args: []string{"explain", "--finding-id", id, "--findings", fixture("testdata/feeds/ubuntu/com.ubuntu.jammy.usn.oval.xml")}, code: 1},
	})
}

// --- compare-version ---

func TestFlagsCompareVersion(t *testing.T) {
	cv := func(eco, a, b string) []string {
		return []string{"compare-version", "--ecosystem", eco, "--installed", a, "--fixed", b}
	}
	runFlagCases(t, []flagCase{
		{name: "dpkg older", args: cv("dpkg", "1:8.9p1-3ubuntu0.1", "1:8.9p1-3ubuntu0.10"),
			stdout: []string{"1:8.9p1-3ubuntu0.1 < 1:8.9p1-3ubuntu0.10   (dpkg semantics)", "installed version is OLDER than the fixed version"}},
		{name: "dpkg tilde", args: cv("dpkg", "3.0.13-1~deb12u1", "3.0.13-1"), stdout: []string{"OLDER"}},
		{name: "dpkg epoch", args: cv("dpkg", "1:1.0", "2.0"), stdout: []string{"NEWER"}},
		{name: "apk older", args: cv("apk", "3.3.0-r0", "3.3.0-r2"), stdout: []string{"OLDER"}},
		{name: "apk equal", args: cv("apk", "1.36.1-r29", "1.36.1-r29"), stdout: []string{"EQUALS"}},
		{name: "rpm older", args: cv("rpm", "1:3.0.7-24.el9", "1:3.0.7-27.el9"), stdout: []string{"OLDER"}},
		{name: "rpm newer", args: cv("rpm", "32:9.16.23-15.el9_4.1", "32:9.16.23-15.el9"), stdout: []string{"NEWER"}},
		{name: "pep440 older", args: cv("pep440", "5.6.0", "5.6.6"), stdout: []string{"OLDER"}},
		{name: "pep440 prerelease", args: cv("pep440", "2.0.0rc1", "2.0.0"), stdout: []string{"OLDER"}},
		{name: "winbuild older", args: cv("winbuild", "20348.1000", "20348.2700"), stdout: []string{"OLDER"}},
		{name: "winbuild equal", args: cv("winbuild", "10.0.20348.2700", "20348.2700"), stdout: []string{"EQUALS"}},
		{name: "missing installed", args: []string{"compare-version", "--ecosystem", "dpkg", "--fixed", "1.0"}, code: 1,
			stderr: []string{"compare-version requires --ecosystem, --installed and --fixed"}},
		{name: "missing ecosystem", args: []string{"compare-version", "--installed", "1.0", "--fixed", "1.0"}, code: 1,
			stderr: []string{"compare-version requires --ecosystem, --installed and --fixed"}},
		{name: "unknown ecosystem", args: cv("npm", "1.0.0", "1.0.1"), code: 1, stderr: []string{"npm"}},
		{name: "invalid dpkg version", args: cv("dpkg", "not a version", "1.0"), code: 1, stderr: []string{"invalid character"}},
		{name: "invalid apk version", args: cv("apk", "not a version", "1.0"), code: 1, stderr: []string{"must start with a digit"}},
		{name: "invalid rpm version", args: cv("rpm", "1.0:x", "1.0"), code: 1, stderr: []string{"non-numeric epoch"}},
		{name: "invalid winbuild version", args: cv("winbuild", "20348", "20348.1"), code: 1, stderr: []string{"winbuild:"}},
	})
}

// --- compare-nessus ---

func TestFlagsCompareNessus(t *testing.T) {
	sh := shared(t)
	nessus := fixture("testdata/compare/ubuntu-sample.nessus.xml")
	runFlagCases(t, []flagCase{
		{name: "missing nessus", args: []string{"compare-nessus", "--findings", sh.ubuntuFindings}, code: 1,
			stderr: []string{"compare-nessus requires --nessus <report.nessus>"}},
		{name: "nessus and findings", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings},
			stdout: []string{"resolver asset:   asset-ubuntu2204", "nessus host:      192.0.2.10", "agreement:            1", "only nessus (potential resolver gaps)"}},
		{name: "findings default", args: []string{"compare-nessus", "--nessus", nessus}, inTmp: true,
			setup: func(t *testing.T, tmp string) {
				if err := os.MkdirAll(filepath.Join(tmp, "build"), 0o755); err != nil {
					t.Fatal(err)
				}
				copyFile(t, sh.ubuntuFindings, filepath.Join(tmp, "build", "findings.json"))
			},
			stdout: []string{"resolver asset:   asset-ubuntu2204"}},
		{name: "findings default missing", args: []string{"compare-nessus", "--nessus", nessus}, inTmp: true, code: 1,
			stderr: []string{"findings.json"}},
		{name: "host", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings, "--host", "192.0.2.10"},
			stdout: []string{"nessus host:      192.0.2.10"}},
		{name: "host not in report", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings, "--host", "198.51.100.7"}, code: 1,
			stderr: []string{"198.51.100.7"}},
		{name: "local-only default true", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings},
			stdout: []string{"compared_local_only=true"}},
		{name: "local-only false", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings, "--local-only=false"},
			stdout: []string{"compared_local_only=false"}},
		{name: "local-only not a bool", args: []string{"compare-nessus", "--nessus", nessus, "--local-only=often"}, code: 2,
			stderr: []string{`invalid boolean value "often" for -local-only`}},
		{name: "json", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings, "--json", filepath.Join("{tmp}", "diff.json")},
			stdout: []string{"full diff written to "},
			check: func(t *testing.T, tmp string, _ cliResult) {
				raw, err := os.ReadFile(filepath.Join(tmp, "diff.json"))
				if err != nil || !json.Valid(raw) {
					t.Errorf("diff.json: %v", err)
				}
			}},
		{name: "show 0", args: []string{"compare-nessus", "--nessus", nessus, "--findings", sh.ubuntuFindings, "--show", "0", "--local-only=false"},
			stdout: []string{"... and "}},
		{name: "show not a number", args: []string{"compare-nessus", "--nessus", nessus, "--show", "all"}, code: 2,
			stderr: []string{`invalid value "all" for flag -show`}},
		{name: "nessus not found", args: []string{"compare-nessus", "--nessus", filepath.Join("{tmp}", "none.nessus"), "--findings", sh.ubuntuFindings}, code: 1,
			stderr: []string{"none.nessus"}},
	})
}

// --- mapper ---

func TestFlagsMapper(t *testing.T) {
	runFlagCases(t, []flagCase{
		{name: "no subcommand", args: []string{"mapper"}, code: 1, stderr: []string{"usage: mapper probes [--mapper <file>]"}},
		{name: "unknown subcommand", args: []string{"mapper", "list"}, code: 1, stderr: []string{"usage: mapper probes"}},
		{name: "probes built in", args: []string{"mapper", "probes"},
			check: func(t *testing.T, _ string, r cliResult) {
				var probes []json.RawMessage
				if err := json.Unmarshal([]byte(r.Stdout), &probes); err != nil {
					t.Fatalf("probes are not a JSON array: %v", err)
				}
			}},
		{name: "probes mapper file", args: []string{"mapper", "probes", "--mapper", filepath.Join("{tmp}", "mapper.json")}, setup: windowsApps,
			check: func(t *testing.T, _ string, r cliResult) {
				if !json.Valid([]byte(r.Stdout)) {
					t.Errorf("not JSON: %s", r.Stdout)
				}
			}},
		{name: "probes mapper not found", args: []string{"mapper", "probes", "--mapper", filepath.Join("{tmp}", "none.json")}, code: 1,
			stderr: []string{"mapper: "}},
	})
}
