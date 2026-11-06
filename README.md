# OpenNess Vulnerability Scanner: resolver

`openness-resolver` is the resolver of the OpenNess Vulnerability Scanner. It turns a host
snapshot into an explainable list of vulnerabilities. It reads an `.openness` evidence file
(packages, kernel, containers, Python packages, applications and Windows build of one host,
produced by the [OpenNess collector](https://github.com/s4e-io/openness)), or a network
device file read over SNMP, and the security advisories that the distribution and software
vendors publish, and it decides, for every installed package and CVE, whether the host is
vulnerable, fixed or not affected, and why.

- **Works offline and on its own.** `feed sync` downloads the advisories straight from the
  publishers (Canonical, Debian, Red Hat, Rocky, AlmaLinux, SUSE, Alpine, Amazon, Microsoft,
  OSV), and the application and device mapper from a public GitHub release. No OpenNess or
  S4E account, API key or service is needed. `resolve` never touches the network.
- **Deterministic.** Vendor rules, native version comparison (dpkg, rpm, apk, PEP 440,
  Windows builds) and explicit logic. No AI or machine learning at runtime.
- **Explainable.** Every finding carries the vendor rule, the version comparison, the
  evidence ids and the reasons; `explain` prints them.
- **Platforms.** Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, openSUSE Leap, Amazon Linux,
  Alpine (hosts and container images), Windows (OS build via MSRC, installed applications),
  PyPI packages and network devices (Cisco, Fortinet, Juniper, MikroTik, Palo Alto, Aruba,
  Ubiquiti; matched from SNMP data).

License: [Apache License 2.0](LICENSE). Version: [`VERSION`](VERSION), changes in
[CHANGELOG.md](CHANGELOG.md).

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Reading the output](#reading-the-output)
- [Usage](#usage)
  - [feed sync](#feed-sync), [feed list](#feed-list), [feed validate](#feed-validate)
  - [rules import](#rules-import), [rules stats](#rules-stats), [rules format](#rules-format)
  - [resolve](#resolve), [explain](#explain), [compare-version](#compare-version)
  - [compare-nessus](#compare-nessus), [mapper probes](#mapper-probes), [version](#version)
  - [Environment variables](#environment-variables), [Exit codes](#exit-codes)
- [Data sources](#data-sources)
- [Keeping data current](#keeping-data-current)
- [Testing](#testing)
- [Documentation](#documentation)
- [Contributing, security and license](#contributing-security-and-license)

## Install

**Release binary** (Linux, macOS, Windows; no Go needed). Every
[release](https://github.com/s4e-io/openness-resolver/releases) has
`openness-resolver_<version>_<os>_<arch>` binaries and a `SHA256SUMS` file:

```bash
gh release download -R s4e-io/openness-resolver -p 'openness-resolver_*_linux_amd64' -p SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
install -m 0755 openness-resolver_*_linux_amd64 /usr/local/bin/openness-resolver
openness-resolver version
```

On Windows, download `openness-resolver_<version>_windows_amd64.exe` and rename it to
`openness-resolver.exe`.

**With Go** (1.25 or newer):

```bash
go install github.com/s4e-io/openness-resolver/cmd/openness-resolver@latest
openness-resolver version
```

**From a checkout:**

```bash
go build -o bin/openness-resolver ./cmd/openness-resolver
# or the release-style build with version information:
bash scripts/build.sh            # writes bin/openness-resolver and dist/
```

## Quick start

You need an `.openness` evidence file of the host, written by the collector
(`openness collect --output host.openness` on that host). Then, on any machine:

```bash
# 1. Download the advisories this host needs, straight from the publishers.
openness-resolver feed sync --for host.openness --data-dir data

# 2. Resolve. Offline: reads only host.openness and data/.
openness-resolver resolve --input host.openness --data-dir data --output findings.json

# 3. Read the result.
openness-resolver resolve --input host.openness --data-dir data --states vulnerable
openness-resolver explain --finding-id <finding_id from findings.json> --findings findings.json
```

`feed sync --for` reads the host release (and the release of every container image in the
evidence) from the file and downloads exactly those sources: for example
`ubuntu-oval-usn-jammy` for Ubuntu 22.04, `debian-security-tracker` for Debian, the last 24
MSRC months for Windows, and `osv-pypi` (the OSV PyPI archive) when the file lists PyPI
packages. `resolve` reads only the local data: it makes no network call. Add
`--dry-run` to see what it would download without downloading.

To try it without a host, use the synthetic evidence files in this repository:

```bash
openness-resolver feed sync --for testdata/evidence/synthetic/alpine-3.20.openness --data-dir data
openness-resolver resolve --input testdata/evidence/synthetic/alpine-3.20.openness --data-dir data
```

## Reading the output

`resolve` prints a summary and writes `findings.json`
(contract: [docs/findings-contract.md](docs/findings-contract.md)). The fields you need first:

| Field | Meaning |
|---|---|
| `findings[]` | One decision per scope (host, container, Python environment), package and CVE. |
| `findings[].state` | `vulnerable`, `vulnerable_runtime` (vulnerable and its process runs), `fixed`, `not_applicable` (vendor says not affected), `potentially_vulnerable` (no vendor fix data, or a guessed application), `unknown`, `conflicting_evidence`. |
| `findings[].installed_version`, `fixed_version` | The comparison behind the decision; `comparison` holds the expression and comparator. |
| `findings[].rule` | The vendor rule: source, URL, feed snapshot, raw vendor status. |
| `findings[].reasons[]` | Why, in words. |
| `remediation_groups[]` | Upgrade cards: packages to upgrade, target versions, the CVEs each card closes, a `command_hint` (for example `dnf upgrade openssl openssl-libs`). |
| `rule_coverage` | Which rules were loaded for this asset (`asset_release`, `rules_for_asset`, `sources[]` with URL, SHA-256, download time and, for the application mapper, its `version`) and whether they cover it (`state`: `covered`, `partial`, `missing`, `not_applicable`; for a network device also `not_supported` and `unknown`). `gaps[]` names each hole by `kind`: `missing_rules`, `no_evaluator`, `not_synced`, `no_packages`, `unknown_distribution`, `invalid_package_records` (with `count`), `packages_truncated`. |
| `unknowns[]`, `notes[]` | What was seen but not judged. An empty `findings[]` with a non-empty `unknowns[]` is not a clean host. |

When rules for the asset release are missing, the evidence has no usable package
(`no_packages`) or the distribution is unknown (`unknown_distribution`), `resolve` still
writes the findings but exits with code 1: a host that was not evaluated is never reported
as clean. Skipped malformed package records (`invalid_package_records`) and a package list
the collector cut (`packages_truncated`) make the coverage `partial`; the rest is evaluated
and the exit code is 0.

When the evidence carries `integrity.payload_hash`, `resolve` checks it the way the
collector computed it and stops with exit 1 on a mismatch (no findings are written).
Evidence without a hash is accepted with a note; `asset.evidence_integrity` says which
(`verified` or `not_present`).

## Usage

```
openness-resolver <command> [flags]
```

Flags take one dash or two (`-data-dir` and `--data-dir` are the same). Boolean flags are
set with `--flag` or `--flag=true|false`. `openness-resolver <command> -h` lists the flags of
a command. A relative path is relative to the working directory.

### feed sync

Download advisory sources from their publishers, keep each download as an immutable
snapshot under `<data-dir>/raw/`, parse it and publish normalized rules under
`<data-dir>/normalized/`. Select sources with `--for`, `--source`, `--vendor` or `--all`
(they combine). A source that fails is reported and the others continue; the exit code is 1
when one failed. A download answered with HTTP 408, 429 or 5xx, or cut by a network error,
is tried again (up to 4 tries): after `Retry-After` when the server sends it (seconds or an
HTTP date), else after 2, 4 and 8 seconds. A server that asks to wait more than 60 seconds
(an hourly limit) is not waited for. Other statuses, such as 404, are not retried.

The `app-mapper` source is the application and device mapper (format
`openness-app-mapper/1`: the catalog by S4E plus the NVD data of its products). It is synced
with `--for` when the evidence is Windows, has applications or is a network device file,
with `--source app-mapper` (only it), `--vendor openness` and `--all`. The bundle is checked
against the release's `SHA256SUMS`, loaded once, and stored as
`<data-dir>/mapper/app-mapper.json.gz` with its metadata in
`<data-dir>/mapper/app-mapper.json.gz.meta.json` (`source`, `source_url`, `downloaded_at`,
`sha256`, `size_bytes`, `format`, `version`). When the release location answers 404 the
source prints `not published yet` and is skipped; it is a failure only with
`--source app-mapper`. `resolve` then keeps using the mapper it has. A downloaded mapper
whose `version` is older than the synced one, or than the mapper built into the binary, is
not installed: the source prints why, keeps the current mapper and exits 0.
`--allow-downgrade` installs it anyway.

```bash
openness-resolver feed sync --for host.openness --data-dir data
openness-resolver feed sync --vendor microsoft --months 6
openness-resolver feed sync --source ubuntu-oval-usn-noble --dry-run
openness-resolver feed sync --source app-mapper --data-dir data
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--for <file>` | Sync the sources the asset in this `.openness` file needs: its host release, the release of every container image in it, `osv-pypi` when it lists PyPI packages, and `app-mapper` for Windows or applications. A network device file (`openness-device/1`) selects `app-mapper`. | `--for host.openness` |
| `--source <id>` | Sync one source: a registry id (see `feed list`) or a release id built from the patterns in [Data sources](#data-sources). An unknown id is an error. | `--source alpine-secdb-v3.20` |
| `--vendor <name>` | Sync every enabled source of one vendor: `almalinux`, `alpine`, `amazon`, `debian`, `microsoft`, `openness` (the `app-mapper` source), `opensuse`, `rhel`, `rocky`, `ubuntu`. Any other value is an error. | `--vendor debian` |
| `--all` | Sync every enabled registry source (all vendors, every supported release). Default `false`. | `--all` |

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory for raw snapshots and normalized rules. Default `data`. | `--data-dir /var/lib/openness` |
| `--months <n>` | MSRC: number of monthly CVRF documents, newest first, for `--vendor microsoft` and Windows evidence. Must be at least 1. Default `24`. A month not published yet (HTTP 404) is skipped. | `--months 6` |
| `--pypi-only` | Deprecated. With `--for`: sync only `osv-pypi`, when the evidence lists PyPI packages. A failed download is a warning and exit `0`. `feed sync --for` selects `osv-pypi` itself. Default `false`. | `--for host.openness --pypi-only` |
| `--osv-url <url>` | Deprecated and ignored (a warning on stderr). PyPI data is the `osv-pypi` archive, not per-package OSV queries. | `--osv-url https://osv.example.org/v1/query` |
| `--allow-downgrade` | Let the `app-mapper` source install a mapper older than the synced one or the built-in one. Default `false`. | `--source app-mapper --allow-downgrade` |
| `--mapper-url <url>` | Where the `app-mapper` source downloads `app-mapper.json.gz` from; `SHA256SUMS` must be in the same directory. Default: `https://github.com/s4e-io/openness-catalog/releases/latest/download/app-mapper.json.gz`. | `--mapper-url https://mirror.example.org/catalog/app-mapper.json.gz` |

#### Debug

| Flag | Description | Example |
|---|---|---|
| `--dry-run` | Print the sources that would be downloaded (`source <id> <url>`, one per line) and download nothing. Default `false`. | `--for host.openness --dry-run` |

### feed list

Print the source registry (id, ecosystem, vendor, priority, enabled), the data in the data
directory with its age (`data <release> <source> downloaded_at=... age_days=N stale=true|false`,
one line per rule directory and one for the synced mapper) and the raw snapshots. Release-derived sources (Ubuntu codenames, Alpine branches,
MSRC months) are not all listed; their id patterns are in [Data sources](#data-sources).

```bash
openness-resolver feed list --data-dir data
```

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory whose snapshots are listed. Default `data`. | `--data-dir data` |
| `--stale-after <age>` | Age after which data counts as old, for every source: a duration (`36h`) or days (`10d`); `0` turns the check off. Default: per source, as for `resolve`. | `--stale-after 3d` |

### feed validate

Download the selected sources and parse them without publishing rules: a check that the
publishers and the parsers still agree. Without a selection flag it validates every enabled
registry source.

```bash
openness-resolver feed validate --vendor rocky
openness-resolver feed validate --dry-run
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--for <file>` | Validate the advisory sources this evidence file needs, `osv-pypi` included when it lists PyPI packages. | `--for host.openness` |
| `--source <id>` | Validate one source (registry or release id). | `--source osv-rhel` |
| `--vendor <name>` | Validate every enabled source of one vendor (same values as `feed sync`). | `--vendor alpine` |
| `--all` | Validate every enabled source. Default `false`; no selection flag means the same. | `--all` |

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory for the raw snapshots. Default `data`. | `--data-dir data` |
| `--months <n>` | MSRC months to validate with `--vendor microsoft` or Windows evidence. Must be at least 1. Default `24`. | `--months 2` |
| `--mapper-url <url>` | Where the `app-mapper` source downloads the mapper bundle from (same as `feed sync`). The bundle is checked and discarded. | `--mapper-url https://mirror.example.org/catalog/app-mapper.json.gz` |

#### Debug

| Flag | Description | Example |
|---|---|---|
| `--dry-run` | Print the sources that would be downloaded and download nothing. Default `false`. | `--dry-run` |

### rules import

Normalize a raw feed file you already have (from a mirror, an air-gapped transfer or a
manual download) into the rule store, exactly as `feed sync` would. Every format imports:
Ubuntu OVAL (`.xml` or `.xml.bz2`), Alpine secdb (`main.json`, `community.json`; a file
whose name starts with `community` goes to the `-community` source and keeps the other
document's rules), Debian tracker JSON, vendor OSV `all.zip` or one OSV JSON document,
Amazon `updateinfo.xml` or `.xml.gz`, one MSRC CVRF month JSON, and an application mapper
bundle (`--source app-mapper`, JSON or gzip), which is checked and stored as
`<data-dir>/mapper/app-mapper.json.gz` like `feed sync` does.

```bash
openness-resolver rules import --source ubuntu-oval-usn-jammy --file com.ubuntu.jammy.usn.oval.xml.bz2 \
  --source-url https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2 \
  --fetched-at 2026-11-03T11:40:00Z --data-dir data
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--source <id>` | Required. Source of the file: a registry id, a release id, or a data mirror id (`debian-tracker`, `osv-redhat`, `amazon-al2`, `amazon-al2023`, `msrc-<YYYY-Mon>`). An unknown id is an error. | `--source osv-rocky` |
| `--file <path>` | Required. The raw feed file, as the publisher serves it. | `--file all.zip` |

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory for normalized rules. Default `data`. | `--data-dir data` |
| `--source-url <url>` | Where the file was published, recorded in the rule metadata and shown by `explain`. Default: the source's publisher URL. | `--source-url https://mirror.example.org/jammy.xml.bz2` |
| `--fetched-at <time>` | RFC 3339 time the file was fetched from its publisher, recorded in the metadata. Default: now. A value that is not RFC 3339 is an error. | `--fetched-at 2026-11-03T11:40:00Z` |

### rules stats

Print statistics over the normalized rule store as JSON.

```bash
openness-resolver rules stats --data-dir data
```

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory to read. Default `data`. | `--data-dir data` |

### rules format

Print, as JSON, which processed rules this build reads: `format`, an `id` that changes with
the rule layout or any parser version, and the parser versions. A mirror that ships
processed rules can serve the same rules to every build with the same id. No flags.

```bash
openness-resolver rules format
```

### resolve

Evaluate one `.openness` evidence file, or one network device file, against the rule store
and write the findings. Offline: it reads only the evidence, the data directory and the
application mapper.

The application mapper is picked in this order: `--mapper <file>` when given, else
`<data-dir>/mapper/app-mapper.json.gz` when `feed sync` put one there, else the mapper built
into the binary. `rule_coverage.sources[]` names the one used: `source` is `app-mapper`
(synced), `app-mapper-file` (`--mapper`) or `app-mapper-builtin`, with its `version` and,
when its metadata says so, `url`, `sha256` and `downloaded_at`.

Every source with a `downloaded_at` also gets `age_days` and `stale`. When a source is
older than `--stale-after` allows, `resolve` prints one warning line to stderr
(`` warning: old data: ubuntu-oval-usn-jammy (5 days); run `openness-resolver feed sync` ``)
and adds the same text to `notes[]`. The exit code does not change.

`--device` resolves a network device instead of a host. The device file (format
`openness-device/1`) holds what SNMP tells about the device and nothing that names it:
`{"format":"openness-device/1","sys_descr":"...","sys_object_id":".1.3.6.1.4.1.9.1.2494","model":"C9300-48P","software_rev":"17.9.4a","firmware_rev":"","hardware_rev":"","serial_hint":""}`.
A file with any other field (a host name, an address) is refused. The device entries of the
mapper's catalog match it; the findings have scope `network_device`, the update card action
`update_device`, and `rule_coverage.state` is `covered`, `not_supported` (no device entry
matched; exit 0 with a note) or `unknown` (an entry matched but the version could not be
read; no findings, exit 0 with a note). Only the first `sys_descr` line of a matched device,
with addresses and host names redacted, is copied into the output.

```bash
openness-resolver resolve --input host.openness --data-dir data --output findings.json
openness-resolver resolve --input host.openness --states vulnerable,vulnerable_runtime
openness-resolver resolve --device switch.json --data-dir data --output switch-findings.json
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--input <file>` | The `.openness` evidence file. Required unless `--device` is given; not both. | `--input host.openness` |
| `--device <file>` | A network device file (`openness-device/1`, written by the desktop from SNMP) to resolve instead of `--input`. | `--device switch.json` |
| `--preflight` | Strict evidence check before resolving: `schema_version` and `asset.asset_id` must be present. The payload hash and the coverage rules are the same as without it. Default `false`. | `--preflight` |

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--data-dir <dir>` | Data directory with normalized rules. Only the rule files the asset needs are loaded. Default `data`. | `--data-dir data` |
| `--mapper <file>` | Application mapper for third-party Windows applications and network devices (format `openness-app-mapper/1`: catalog plus NVD data, JSON or gzip, at most 256 MB uncompressed). Default: `<data-dir>/mapper/app-mapper.json.gz` when synced, else the mapper built into the binary. | `--mapper mapper.json.gz` |

#### Output

| Flag | Description | Example |
|---|---|---|
| `--output <file>` | Findings JSON file to write; missing directories are created. Default `findings.json`. | `--output out/host.json` |
| `--stale-after <age>` | Age after which a source's data counts as old, for every source: a duration (`36h`) or days (`10d`); `0` turns the check off. Default: 2 days for distribution feeds and `osv-pypi`, 35 days for `msrc-*`, 7 days for the application mapper. | `--stale-after 3d` |
| `--states <list>` | Comma-separated finding states to list after the summary (finding id, state, CVE, package, versions). A state no finding has lists nothing. Default: no listing. | `--states vulnerable,fixed` |

#### Matching

| Flag | Description | Example |
|---|---|---|
| `--app-unverified` | Also use application and device catalog entries no person has reviewed (the seed device entries are unreviewed). Default `false`. | `--app-unverified` |
| `--app-guess` | Guess the NVD product of Windows applications the catalog does not know; such findings are `potentially_vulnerable`. Default `true`. | `--app-guess=false` |

### explain

Print the full explanation of one finding: evidence, vendor rule, feed snapshot,
comparison, runtime state, reasons, missing evidence and superseded rules.

```bash
openness-resolver explain --finding-id finding-0666efb0c5c81804 --findings findings.json
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--finding-id <id>` | Required. The `finding_id` to explain. | `--finding-id finding-0666efb0c5c81804` |
| `--findings <file>` | Findings JSON written by `resolve`. Default `findings.json`. | `--findings out/host.json` |

### compare-version

Compare two versions with an ecosystem's native rules and print which is newer.

```bash
openness-resolver compare-version --ecosystem dpkg --installed 1:8.9p1-3ubuntu0.1 --fixed 1:8.9p1-3ubuntu0.10
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--ecosystem <name>` | Required. `dpkg` (Debian, Ubuntu), `rpm` (RHEL family, SUSE, Amazon), `apk` (Alpine), `pep440` (Python), `winbuild` (Windows `build.ubr`). Any other value is an error. | `--ecosystem rpm` |
| `--installed <version>` | Required. Installed version. The dpkg, rpm, apk and winbuild comparators reject a version they cannot parse. | `--installed 1:3.0.7-24.el9` |
| `--fixed <version>` | Required. Fixed version. | `--fixed 1:3.0.7-27.el9` |

### compare-nessus

Diff resolver findings against a credentialed Nessus scan of the same host
(`.nessus`, NessusClientData_v2). Bring your own report.

```bash
openness-resolver compare-nessus --nessus scan.nessus --findings findings.json --json diff.json
```

#### Input

| Flag | Description | Example |
|---|---|---|
| `--nessus <file>` | Required. The `.nessus` report. | `--nessus scan.nessus` |
| `--findings <file>` | Resolver findings JSON. Default `build/findings.json`. | `--findings findings.json` |
| `--host <name>` | Host name or IP in the report; optional when the report has one host. A host not in the report is an error. | `--host 192.0.2.10` |

#### Matching

| Flag | Description | Example |
|---|---|---|
| `--local-only` | Compare only CVEs backed by a credentialed local security check. Default `true`. | `--local-only=false` |

#### Output

| Flag | Description | Example |
|---|---|---|
| `--json <file>` | Also write the full diff as JSON. Default: not written. | `--json diff.json` |
| `--show <n>` | How many CVE ids to list per divergence bucket. Default `15`. | `--show 50` |

### mapper probes

Print, as a JSON array, the files the application mapper wants the collector to check
(collector `collect --file-probes`), so application matches can be confirmed by file
signature or version.

```bash
openness-resolver mapper probes > probes.json
```

#### Data and sync

| Flag | Description | Example |
|---|---|---|
| `--mapper <file>` | Application mapper file. Default: the built-in one. | `--mapper mapper.json.gz` |

### version

Print the version, commit and build date
(`openness-resolver <version> commit=<sha> built=<date>`). No flags.

```bash
openness-resolver version
```

### Environment variables

The resolver reads no environment variable of its own (`OPENNESS_OSV_URL` and
`OPENNESS_OSV_HEADERS` went with the per-package OSV queries). The standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables apply to every download.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `resolve`: the rules covered the asset, or the coverage is `partial` (gap kinds `not_synced`, `invalid_package_records`, `packages_truncated`; the rest is evaluated). |
| `1` | An error (`error: ...` on stderr), a failed source in `feed sync`, or `resolve` without rule coverage for the asset (`rule_coverage.state` `missing`, including gap kinds `no_packages` and `unknown_distribution`; the findings are still written). An evidence file whose `integrity.payload_hash` does not match is an error. |
| `2` | Usage error: unknown command or flag, or a flag value that does not parse (for example `--months two`). |

## Data sources

The sources `feed sync` downloads and `rules import` reads. Every URL is the publisher's;
nothing goes through an OpenNess or S4E service. The application mapper is published by S4E
as a release asset of the public GitHub repository `s4e-io/openness-catalog`; downloading it
needs no account or key. `<codename>`, `<branch>` and `<YYYY-Mon>`
come from the asset (`--for`) or from `--source`.

| Vendor | Source id | Publisher URL | Format | Releases | Publisher updates | Data license or terms |
|---|---|---|---|---|---|---|
| Canonical (Ubuntu) | `ubuntu-oval-usn-<codename>` | `https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.usn.oval.xml.bz2` | OVAL XML (bz2), per USN | Supported: focal (20.04), jammy (22.04), noble (24.04); any codename the publisher serves via `--for` | Several times a day, after each USN | No license in the file; Canonical publishes the same notices under CC BY-SA 4.0 in [ubuntu-security-notices](https://github.com/canonical/ubuntu-security-notices); [Ubuntu legal](https://ubuntu.com/legal) |
| Debian | `debian-security-tracker` | `https://security-tracker.debian.org/tracker/data/json` | JSON, every release in one document | bookworm (12), trixie (13) | Continuously, many times a day | No license stated; [Debian Security Tracker](https://security-tracker.debian.org/tracker/) |
| Red Hat | `osv-rhel` | `https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip` | OSV JSON (zip), RHSA | RHEL 8, 9 | Daily or more often (OSV export) | [CC BY 4.0](https://access.redhat.com/security/data) (Red Hat security data) |
| Rocky Linux (RESF) | `osv-rocky` | `https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip` | OSV JSON (zip), RLSA | Rocky 8, 9 | Daily or more often (OSV export) | BSD, per [OSV.dev data sources](https://google.github.io/osv.dev/data/) |
| AlmaLinux | `osv-almalinux` | `https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip` | OSV JSON (zip), ALSA | AlmaLinux 8, 9 | Daily or more often (OSV export) | MIT, [AlmaLinux osv-database](https://github.com/AlmaLinux/osv-database) |
| SUSE (openSUSE) | `osv-opensuse` | `https://osv-vulnerabilities.storage.googleapis.com/openSUSE/all.zip` | OSV JSON (zip), openSUSE-SU and SUSE-SU | Leap 15.5, 15.6, 16.0 | Daily or more often (OSV export) | [CC BY 4.0](https://www.suse.com/support/security/csaf/) (SUSE security data) |
| Alpine | `alpine-secdb-<branch>`, `alpine-secdb-<branch>-community` | `https://secdb.alpinelinux.org/<branch>/main.json`, `https://secdb.alpinelinux.org/<branch>/community.json` | secdb JSON | v3.14 to v3.22 (hosts and container images); any branch via `--for` | When packages get security fixes | No license stated by the publisher; [OSV.dev](https://google.github.io/osv.dev/data/) lists Alpine SecDB as CC BY-SA 4.0 |
| Amazon | `amazon-updateinfo-2`, `amazon-updateinfo-2023` | `https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list`, `https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list`, then the repository's `updateinfo.xml.gz` | yum updateinfo XML (ALAS) | Amazon Linux 2, 2023 | With each ALAS advisory | [AWS Site Terms](https://aws.amazon.com/terms/) |
| Microsoft | `msrc-cvrf-<YYYY-Mon>` | `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>` | CVRF JSON, one document per month | Windows 10, 11, Server 2008 to 2025; the last `--months` (default 24) | Monthly (Patch Tuesday), plus revisions | [Microsoft Terms of Use](https://www.microsoft.com/en-us/legal/terms-of-use) |
| OSV (PyPI) | `osv-pypi` | `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` | OSV JSON (zip), one advisory per file, about 38 MB; rules in `normalized/pypi/pypi` | Every PyPI package; selected by `--for` when the evidence lists PyPI packages | Continuously (OSV export) | Per record; the PyPA advisory database and GitHub advisories are CC BY 4.0 ([OSV.dev data sources](https://google.github.io/osv.dev/data/)) |
| S4E catalog plus NVD (application and device mapper) | `app-mapper` | `https://github.com/s4e-io/openness-catalog/releases/latest/download/app-mapper.json.gz` (and `SHA256SUMS` next to it) | `openness-app-mapper/1` JSON (gzip) | Third-party Windows applications and network devices | Daily | The catalog by S4E; the vulnerability data is derived from the NVD, under the NVD's terms. This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| NVD (built in, not synced) | none | Bundled in the binary (`internal/appvuln/data`) | JSON (gzip) | Third-party Windows applications and network devices, when no `app-mapper` was synced | With each release of this tool | NVD data. This product uses data from the NVD API but is not endorsed or certified by the NVD. |

The registry also lists `ubuntu-oval-usn-focal`, `ubuntu-oval-usn-noble` and
`ubuntu-oval-cve-jammy` as disabled entries; `--for` and `--source` derive the right Ubuntu
source from the codename. Ubuntu ESM rules (`esm-infra`, `esm-apps`) come from the same OVAL
documents.

## Keeping data current

`resolve` never downloads. Re-run `feed sync` as often as you want fresh data, for example
daily from cron:

```bash
0 5 * * * openness-resolver feed sync --for /srv/evidence/host.openness --data-dir /var/lib/openness
```

A file that did not change is not downloaded again (ETag); a changed one becomes a new
snapshot under `<data-dir>/raw/<vendor>/`. Disk: one Ubuntu release's normalized rules are
about 150 MB, Debian about 700 MB, each RPM family 200 to 600 MB. Delete old snapshot
directories when you no longer need them for `explain`.

## Testing

```bash
go test ./...                                                   # unit, integration and offline CLI tests
go test ./cmd/openness-resolver -run TestGolden -update         # rewrite golden files after a reviewed change
OPENNESS_NIGHTLY=1 go test ./cmd/openness-resolver -run TestNightly -v -timeout 60m   # real sync, needs network
```

- **Golden end-to-end tests** (`cmd/openness-resolver/e2e_test.go`): build the binary, run
  `rules import` on small committed feed fixtures (`testdata/feeds`), `resolve` on synthetic
  evidence (`testdata/evidence/synthetic`: Ubuntu 22.04 with a PyPI package, Debian 11, 12
  and 13, RHEL 9, Rocky 9, AlmaLinux 8, openSUSE Leap 15.6, Alpine 3.20, Windows Server 2022)
  and compare the exit code, stderr, findings, remediation groups and `rule_coverage` with
  `cmd/openness-resolver/testdata/golden`. The `device-*` cases run `resolve --device` on the
  synthetic device files of `testdata/devices` with the built-in catalog's device entries
  and a small vulnerability fixture. CI runs them on Linux and on Windows with the same
  golden files.
- **Local PyPI tests** (`pypi_local_test.go`): `resolve` matches Python packages against an
  imported `osv-pypi` archive behind a proxy that fails the test on any request, and without
  the archive gives a partial result with exit 0.
- **Flag tests** (`cli_flags_test.go`): every command with every flag: valid values,
  defaults and invalid values.
- **Independence tests** (`independence_test.go`): every URL in the code is a publisher's
  (on github.com only release downloads of `s4e-io/openness-catalog`), and the code reads
  no environment variable of its own.
- **Doc drift guard** (`readme_test.go`): fails when a command or flag is missing from this
  README.
- **Nightly** (`.github/workflows/nightly.yml`, 02:00 UTC and on demand, Linux and Windows,
  no secrets): `feed sync --for` plus `resolve` for Ubuntu 22.04 and 24.04, Debian 12,
  Rocky 9, Amazon Linux 2023, Alpine 3.20, openSUSE Leap 15.6 and Windows Server 2022
  (exit code 0, coverage `covered`, rules loaded for the release), and `feed validate` of
  every enabled source. Each job writes rules, download size and time per source to its
  step summary; a failed scheduled run opens or updates an issue labelled `nightly`, the
  next passing run closes it.

## Documentation

- [docs/internals.md](docs/internals.md): pipeline, parsers, decision engine, finding fields,
  invariants, project layout and release process.
- [docs/findings-contract.md](docs/findings-contract.md): the `findings.json` contract.
- [testdata/evidence/README.md](testdata/evidence/README.md): the synthetic evidence fixtures.

## Contributing, security and license

Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

Copyright 2026 S4E (Security For Everyone). Licensed under the
[Apache License, Version 2.0](LICENSE); third-party notices in [NOTICE](NOTICE). Advisory
data that `feed sync` downloads stays under its publisher's license or terms (see
[Data sources](#data-sources)).

This product uses data from the NVD API but is not endorsed or certified by the NVD.

Openness is free to run on your own machines. The same collector and resolver power the
Inside depth of [S4E](https://s4e.io), which adds scheduling, history, multi-host views and
remediation tracking.
