# Prompts for AI-assisted development

**Project:** [Openness](https://github.com/s4e-io/openness)  
**This repo:** [openness-resolver](https://github.com/s4e-io/openness-resolver)  
**Sibling:** [openness-collector](https://github.com/s4e-io/openness-collector)

We build this project with AI coding assistants (Cursor, Claude, Copilot, etc.).  
This file helps **you** and **the AI** get context fast, so you can discuss ideas and ship useful PRs.

---

## What is Openness? (give this to any AI first)

```
Openness is a two-tool pipeline for local endpoint security evidence:

1. openness-collector (separate repo)
   - Reads the local machine and writes host.openness (JSON evidence)
   - Does NOT decide vulnerability

2. openness-resolver (this repo)
   - Reads .openness + vendor feeds (Ubuntu OVAL/USN, Alpine secdb, OSV/PyPI)
   - Outputs findings.json: one explainable state per package + CVE
   - Deterministic rules + version comparators (dpkg, apk, PEP 440)
   - Does NOT use AI at runtime

License: Apache License 2.0 (open source, developed and maintained by S4E). Org: s4e-io on GitHub.
```

---

## Rules when using AI here

1. **Runtime must stay non-AI**, no LLM in resolve/decision paths.
2. **You own the diff**, read every line; run `go test ./...`.
3. **Deterministic only**, every finding needs traceable rule + comparison + reasons.
4. **Never commit full vendor feeds**, use `data/` locally; CI uses small fixtures under `testdata/`.
5. **Say you used AI** in the PR if it helped (optional but welcome).

---

## Starter prompts (copy-paste)

### Understand the codebase

```
I'm working on github.com/s4e-io/openness-resolver.

Read README.md sections 1–16 (pipeline and invariants).
Explain: feed sync → rules store → resolve engine flow.
Do not change any files yet.
```

### Fix a wrong finding

```
Wrong finding: [CVE, package, expected vs actual state]

Repo: openness-resolver
Evidence: a local `.openness` path you collected (do not commit real-host captures)

Steps:
1. Trace rule lookup and version comparison for this package
2. Add a regression test
3. Fix with minimal diff, preserve vendor raw_status
4. Run go test ./internal/resolver/...

Do not commit data/normalized/ or production evidence.
```

### Add or change resolver behavior

```
I want to change: [describe]

Constraints:
- Deterministic, no LLM
- Binary-specific fixed versions must not bleed across sibling binaries
- Keep vendor raw_status on every rule
- Add tests; update README if pipeline step changes

Show plan first, then implement.
```

### Regenerate CI fixture (maintainers)

```
After changing regression test or ubuntu jammy rules logic:

1. Run openness feed sync --vendor ubuntu locally (data/ is gitignored)
2. Run python3 scripts/extract_regression_rules_fixture.py
3. Run go test ./internal/resolver/ -run TestAfterUpdate
4. Explain what changed in testdata/
```

### Review before PR

```
Review my uncommitted changes in openness-resolver.

Check for:
- non-deterministic logic or hidden heuristics
- missing tests for bug fixes
- accidental commit of data/raw, data/normalized, build/, or secrets
- binary fixed-version isolation preserved

List issues by severity. Do not commit.
```

### Discuss an idea (no code yet)

```
I have an idea for openness-resolver: [idea]

Is it consistent with README invariants (section 16)?
Would it belong in collector instead?
What fixtures or feed sources would we need?

Discussion only, no code changes.
```

---

## Where to talk to humans

- **Bug or feature:** [GitHub Issues](https://github.com/s4e-io/openness-resolver/issues)
- **Security:** [SECURITY.md](../SECURITY.md), no public issues for vulns
- **Evidence collection:** [openness-collector](https://github.com/s4e-io/openness-collector)

---

## Key files (resolver)

| Topic | Path |
|-------|------|
| CLI entry | `cmd/openness-resolver/main.go` |
| Resolve engine | `internal/resolver/engine.go` |
| Rules store | `internal/rules/` |
| Feed sync | `internal/feed/` |
| Version compare | `internal/version/dpkg`, `apk`, `pep440` |
| CI regression fixture | `testdata/`, `cmd/openness-resolver/testdata/` |
| Tests | `go test ./...` |

---

## Related

- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [openness-collector docs/PROMPTS.md](https://github.com/s4e-io/openness-collector/blob/main/docs/PROMPTS.md), collector-specific prompts
