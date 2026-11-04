# Contributing to openness-resolver

Thank you for your interest in contributing.

**Project home:** [github.com/s4e-io/openness](https://github.com/s4e-io/openness)  
**This repository:** [github.com/s4e-io/openness-resolver](https://github.com/s4e-io/openness-resolver)

## How we build this project

We are transparent about tooling:

- **Development:** maintainers and contributors use AI coding assistants (e.g. Cursor, Claude, Copilot) to draft, refactor, and review code.
- **Runtime:** this resolver does **not** use AI. Every finding comes from vendor rules, version comparison, and explicit deterministic logic.

If you use AI while contributing, you remain responsible for the change: read the diff, run tests, and ensure decisions stay deterministic and test-covered.

**Using Cursor / Claude / Copilot?** See [docs/PROMPTS.md](docs/PROMPTS.md) for project context and copy-paste starter prompts.

## Before you start

1. Read [README.md](README.md).
2. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
3. Sync vendor feeds locally: `openness-resolver feed sync --all` (requires network; output under `data/` is gitignored).
4. For security expectations, see [SECURITY.md](SECURITY.md).
5. Third-party notices: [NOTICE](NOTICE).

## Development setup

Requirements: Go 1.25+, network access for feed sync during development.

```bash
go test ./...
bash scripts/build.sh
./bin/openness-resolver version
```

Regression tests use small fixtures under `testdata/` and `cmd/openness-resolver/testdata/`; the end-to-end tests build their rules from them with `rules import`. Full feeds stay gitignored under `data/`; never commit them.

## Pull requests

1. Fork and branch from `dev` (the default branch). Pull requests go to `dev`; `main` holds released versions.
2. Keep changes focused; one logical change per PR.
3. Run `go test ./...` before opening the PR (with feeds synced if you touch resolver logic).
4. Add a **test for every bug fix**.
5. Update README if you add a pipeline step, CLI command, or change behavior.
6. Do **not** commit `data/raw/`, `data/normalized/`, `build/`, or production evidence files.

## Coding principles

1. Keep decisions **deterministic**: no LLM in the decision path.
2. Keep vendor **raw status** on every rule; never discard source wording.
3. Keep **binary-specific** fixed versions; never merge sibling binaries incorrectly.
4. Preserve explainability: every finding should have traceable `rule`, `comparison`, and `reasons`.
5. Version comparators (dpkg, apk, pep440) must have corpus or unit tests.

## Versioning

- Release version lives in `VERSION` and `internal/buildinfo/buildinfo.go` (must stay in sync).
- Use `scripts/version.sh` and `scripts/release.sh` for maintainers cutting releases.
- Record user-visible changes in [CHANGELOG.md](CHANGELOG.md).

## Bug reports

Open a [GitHub issue](https://github.com/s4e-io/openness-resolver/issues) with:

- Evidence file metadata (collector version, schema version, collection ID)
- Resolver version (`openness-resolver version`)
- One example finding with `rule`, `comparison`, and `reasons`
- Expected vs actual state

For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is open source under the [Apache License, Version 2.0](LICENSE).

By contributing, you agree that:

1. your contribution is licensed under the [Apache License, Version 2.0](LICENSE), as described in
   Section 5 of the license (inbound = outbound);
2. you have the right to submit your contribution under these terms.

Contributions of every kind are welcome: bug reports, test environments, validation of
findings, new platforms and feeds.
