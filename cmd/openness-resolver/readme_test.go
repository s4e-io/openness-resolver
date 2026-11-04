package main

// Doc drift guard: every command and every flag the binary accepts must be
// documented in its own section of README.md, and the flag help must be
// well formed. The flags are read from the binary itself (`<command> -h`), so
// a flag added in code without a README row fails here.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// documentedCommands are the README sections ("### <command>"), in order.
var documentedCommands = []string{
	"feed sync", "feed list", "feed validate",
	"rules import", "rules stats", "rules format",
	"resolve", "explain", "compare-version", "compare-nessus", "mapper probes", "version",
}

var flagLine = regexp.MustCompile(`^  -([a-z0-9-]+)(?: (.+))?$`)

// commandFlags runs `<command> -h` and returns flag name -> value name.
func commandFlags(t *testing.T, command string) map[string]string {
	t.Helper()
	if command == "version" {
		return nil
	}
	r := run(t, append(strings.Fields(command), "-h")...)
	out := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(r.Stderr, "\r\n", "\n"), "\n") {
		if m := flagLine.FindStringSubmatch(l); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

func readmeSections(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(fixture("README.md"))
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]string{}
	var name string
	var body strings.Builder
	flush := func() {
		if name != "" {
			sections[name] = body.String()
		}
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "### ") {
			flush()
			name = strings.TrimSpace(strings.TrimLeft(l, "#"))
			body.Reset()
			continue
		}
		body.WriteString(l)
		body.WriteString("\n")
	}
	flush()
	return sections
}

func TestReadmeDocumentsEveryFlag(t *testing.T) {
	sections := readmeSections(t)
	total := 0
	for _, cmd := range documentedCommands {
		body, ok := sections[cmd]
		if !ok {
			t.Errorf("README has no \"### %s\" section", cmd)
			continue
		}
		for flag := range commandFlags(t, cmd) {
			total++
			if !strings.Contains(body, "| `--"+flag) {
				t.Errorf("README section %q has no table row for --%s", cmd, flag)
			}
		}
	}
	if total < 30 {
		t.Errorf("found only %d flags; `-h` parsing is broken", total)
	}
	if _, ok := sections["Data sources"]; !ok {
		t.Error(`README lost "## Data sources" (other READMEs link to #data-sources)`)
	}
	env := sections["Environment variables"]
	for _, v := range []string{"OPENNESS_OSV_URL", "OPENNESS_OSV_HEADERS"} {
		if !strings.Contains(env, v) {
			t.Errorf("README Environment variables section lacks %s", v)
		}
	}
}

// Flag help names value types only: a backtick in a usage string makes the flag
// package print the quoted word as the value name (`-pypi-only rules import`).
func TestFlagHelpIsWellFormed(t *testing.T) {
	valueNames := map[string]bool{"": true, "string": true, "int": true, "uint": true, "float": true, "duration": true, "value": true}
	for _, cmd := range documentedCommands {
		for flag, value := range commandFlags(t, cmd) {
			if !valueNames[value] {
				t.Errorf("%s -h shows -%s %q: remove backticks from its usage text", cmd, flag, value)
			}
		}
	}
	r := run(t, "help")
	if !strings.Contains(r.Stderr, "usage: openness-resolver <command>") {
		t.Errorf("help does not name the tool openness-resolver:\n%s", r.Stderr)
	}
}

// The usage text lists every documented command.
func TestUsageListsEveryCommand(t *testing.T) {
	r := run(t, "help")
	for _, cmd := range documentedCommands {
		if !strings.Contains(r.Stderr, "  "+cmd) {
			t.Errorf("usage text lacks %q", cmd)
		}
	}
}

// Nothing user-facing uses the em dash character.
func TestNoEmDashInDocs(t *testing.T) {
	for _, f := range []string{"README.md", "docs/internals.md"} {
		raw, err := os.ReadFile(fixture(f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsRune(string(raw), '—') {
			t.Errorf("%s contains an em dash", f)
		}
	}
}
