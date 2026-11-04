# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report them through one of:

- [GitHub Security Advisories](https://github.com/s4e-io/openness-resolver/security/advisories/new) (preferred)
- Email: **security@s4e.io**

We aim to acknowledge reports within **72 hours** and provide a remediation timeline when possible.

## Sensitive data

Never commit:

- Real `.openness` files from production or customer hosts (use redacted `testdata/` fixtures only)
- Nessus credentials or scan reports with host-identifying data
- API keys or vendor feed credentials
- Machine-specific sync state that exposes internal infrastructure

Any local lab scripts must read credentials from environment variables only — never argv, and never commit secrets or real-host `.openness` / `.nessus` files.

## Scope

In scope:

- Incorrect vulnerability decisions caused by resolver logic bugs (with reproducible evidence + rules)
- Secret leakage in committed files or logs
- Unsafe handling of untrusted evidence input (parser crashes, path traversal, etc.)

Out of scope:

- Upstream vendor feed errors (Ubuntu OVAL, Alpine secdb, OSV) — report to the vendor when appropriate
- Collection issues in [openness-collector](https://github.com/s4e-io/openness-collector) (report there instead)

## Project

Part of the [Openness](https://github.com/s4e-io/openness) project by [S4E IO](https://github.com/s4e-io).
