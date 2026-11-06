# openness-resolver internals

> This is the design and internals reference that used to be the README. The user-facing README (install, quick start, every command and flag, data sources) is [../README.md](../README.md). Nothing was removed; command examples now use the binary name `openness-resolver`.

**Deterministic Linux vulnerability resolver for Openness evidence files.**

**Openness project:** [github.com/s4e-io/openness](https://github.com/s4e-io/openness)  
**This repo:** [github.com/s4e-io/openness-resolver](https://github.com/s4e-io/openness-resolver)

Version: see [`VERSION`](../VERSION) and [CHANGELOG.md](../CHANGELOG.md); `openness-resolver version` prints the one you run.  
License: [Apache License 2.0](../LICENSE) (open source, developed and maintained by S4E)

This tool reads a host snapshot (`.openness` file) and vendor security feeds.  
It outputs one explainable decision per package and CVE.

**No AI at runtime.** Every result comes from rules, version math, and explicit logic.

**Development note:** we use AI coding assistants (e.g. Cursor, Claude) to help write and review code: not for vulnerability decisions. See [CONTRIBUTING.md](../CONTRIBUTING.md) and [docs/PROMPTS.md](PROMPTS.md).

---

## Table of contents

1. [What this project does](#1-what-this-project-does)
2. [What this project does not do](#2-what-this-project-does-not-do)
3. [Quick start](#3-quick-start)
4. [End-to-end pipeline (all steps)](#4-end-to-end-pipeline-all-steps)
5. [Step A: Collect evidence (outside this repo)](#5-step-a-collect-evidence-outside-this-repo)
6. [Step B: Sync vendor feeds](#6-step-b-sync-vendor-feeds)
7. [Step C: Parse feeds into rules](#7-step-c-parse-feeds-into-rules)
8. [Step D: Load evidence](#8-step-d-load-evidence)
9. [Step E: Resolve host packages (Ubuntu)](#9-step-e-resolve-host-packages-ubuntu)
10. [Step F: Resolve running kernel](#10-step-f-resolve-running-kernel)
11. [Step G: Resolve Python distributions](#11-step-g-resolve-python-distributions)
12. [Step H: Resolve containers (Alpine)](#12-step-h-resolve-containers-alpine)
13. [Step I: Build output and metrics](#13-step-i-build-output-and-metrics)
14. [Finding states and fields](#14-finding-states-and-fields)
15. [Version comparison](#15-version-comparison)
16. [Important invariants](#16-important-invariants)
17. [Validation and analysis scripts](#17-validation-and-analysis-scripts)
18. [Nessus comparison](#18-nessus-comparison-optional)
19. [CLI reference](#19-cli-reference)
20. [Project layout](#20-project-layout)
21. [Testing](#21-testing)
22. [License and contributing](#22-license-and-contributing)

---

## 1. What this project does

- Reads **Openness evidence** (`.openness` JSON) from the Openness collector.
- Loads **vendor rules** from Ubuntu OVAL, Alpine secdb, and OSV (PyPI).
- Compares **installed version** vs **vendor fixed version** using native comparators.
- Produces **findings**: one record per `(asset, scope, package, CVE/advisory)`.
- Records **why** each decision was made (rule, comparison, reasons, evidence IDs).
- Supports **host**, **container**, **kernel**, and **Python environment** scope.

---

## 2. What this project does not do

- It does **not** scan the network or SSH/WinRM into hosts. The collector runs *on* the host and produces a `.openness` file; this resolver only reads that file.
- It does **not** use NVD as the primary source for Ubuntu package fixes.
- It does **not** use machine learning or LLMs at runtime.
- It does **not** modify the target system.

---

## 3. Quick start

**Install a release** (Linux, macOS and Windows builds; no Go needed). Each release has
`openness-resolver_<version>_<os>_<arch>` binaries and `SHA256SUMS`:

```bash
gh release download -R s4e-io/openness-resolver -p 'openness-resolver_*_darwin_arm64' -p SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS
install -m 0755 openness-resolver_*_darwin_arm64 /usr/local/bin/openness-resolver
openness-resolver version
```

Install it as `openness-resolver`: the collector's binary also calls itself `openness`, so
the two would clash on `PATH`. Examples below use `openness-resolver`.

**Or build from source** (Go 1.25+, module path `github.com/s4e-io/openness-resolver`):

```bash
go install github.com/s4e-io/openness-resolver/cmd/openness-resolver@latest   # into $(go env GOPATH)/bin
# or from a checkout:
bash scripts/build.sh            # or: go build -o bin/openness-resolver ./cmd/openness-resolver
./bin/openness-resolver version
```

**Use it** on a `.openness` file from the collector:

# Resolve a collector .openness file (rules: feed sync)
./bin/openness-resolver resolve \
  --input path/to/host.openness \
  --output findings.json \
  --data-dir data

# Optional: strict parse metadata check (no lab filename/SHA lock)
./bin/openness-resolver resolve --preflight --input path/to/host.openness --output findings.json --data-dir data
```

**Full vendor feeds** (your own host or production use):

```bash
./bin/openness-resolver feed sync --for path/to/host.openness --data-dir data
./bin/openness-resolver resolve \
  --input path/to/host.openness \
  --output findings.json \
  --data-dir data
```

---

## 4. End-to-end pipeline (all steps)

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  Collector  │ ──► │  .openness file   │ ──► │  openness    │ ──► │ findings.json│
│  (collector) │     │  (evidence)  │     │  (this repo) │     │  + metrics   │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            ▲                    ▲
                            │                    │
                     host snapshot          vendor feeds
                                          (OVAL, secdb, OSV)
```

| Step | Who | What happens |
|------|-----|--------------|
| A | Collector | Gathers packages, processes, containers, Python deps from the host. |
| B | `feed sync` | Downloads raw Ubuntu OVAL and Alpine secdb snapshots. |
| C | Feed parsers | Convert raw XML/JSON into normalized `PackageVulnerabilityRule` records. |
| D | `resolve` loader | Parses `.openness` into typed records (packages, kernel, language_deps, …). |
| E | Engine | Matches each installed package to rules and runs version comparison. |
| F | Engine | Evaluates kernel CVEs against the **running** kernel only. |
| G | Engine | Evaluates Python distributions (ubuntu_dpkg correlate, pypi separate). |
| H | Engine | Evaluates container packages inside each image digest group. |
| I | Reporter | Writes findings, deduplicated records, reconciliation, and metrics. |

---

## 5. Step A: Collect evidence (outside this repo)

The **Openness collector** (not in this repo) produces a `.openness` file.

The file is JSON. It contains:

| Section | Used for |
|---------|----------|
| `asset` | Host ID, hostname, architecture |
| `operating_system` | Distro ID, version, codename (e.g. ubuntu / jammy) |
| `kernel` | Running kernel string, reboot flag |
| `packages[]` | Installed dpkg/apk packages with versions and source mapping |
| `processes[]` | Running processes |
| `evidence_chains[]` | Links process → binary → package |
| `containers[]` | Container images and their package lists |
| `language_deps[]` | Python environments and distributions |
| `collection` | Collection ID, collector version, schema version |

**Rule:** The resolver never guesses missing data. If evidence is absent, the decision is `unknown` or the case is skipped with a note.

---

## 6. Step B: Sync vendor feeds

```bash
./bin/openness-resolver feed sync --for path/to/host.openness --data-dir data
```

`--for` reads the asset's release from the evidence file and syncs exactly the
sources that asset needs, so any release the vendor publishes is covered without
a registry change. `--all` remains available and syncs the enabled registry
sources only.

What happens:

1. The downloader fetches official feed URLs (with retry, ETag, SHA-256).
2. Each download is stored as an **immutable snapshot** under `data/raw/`.
3. The parser runs on the snapshot.
4. Normalized rules are written to `data/normalized/`.

Reading the output: `downloaded/parsed` count the feed's records, `rejected` the ones that
do not apply (for Ubuntu, `criterion_comment_unparsable` is mostly the kernel and binary
criteria handled elsewhere: it is not an error), `rules` what was written. "unsupported
structures" lists OVAL shapes the parser skips on purpose. A re-sync whose file did not
change prints `size=0B` (not modified, ETag) and keeps the rules.

**Keeping the data current.** `resolve` never downloads: re-run `feed sync --for` (or
`--vendor`, `--all`) as often as you want fresh data, e.g. daily from cron:

```bash
0 5 * * * openness-resolver feed sync --for /srv/evidence/host.openness --data-dir /var/lib/openness >/var/log/openness-sync.log 2>&1
```

Ubuntu publishes several times a day, MSRC monthly (Patch Tuesday). Disk: one Ubuntu
release's normalized rules are about 150 MB, Debian about 700 MB, the RPM families 200 to
600 MB each. Every changed download is kept as a new snapshot under `data/raw/<vendor>/`;
delete old snapshot directories when you no longer need them for `explain`. A prebuilt,
ready-to-use rules source (no download from the publishers) is not public yet; the
`rules import` mirror path below is what OpenNess Desktop uses with its licensed backend.

Feed sources:

| Source | Vendor | Ecosystem | Used for |
|--------|--------|-----------|----------|
| Ubuntu USN OVAL | Canonical | dpkg | Host Ubuntu packages |
| Alpine secdb | Alpine | apk | Alpine hosts (branch from `VERSION_ID`, 3.20.10 is `v3.20`) and container images |
| Amazon Linux updateinfo | Amazon | rpm | Amazon Linux 2 and 2023 hosts (ALAS, core repository `updateinfo.xml.gz`) |
| OSV API | OSV.dev | pypi | PyPI Python packages |
| MSRC CVRF | Microsoft | winbuild | Windows OS builds (monthly documents, `--months`, default 24) |

PyPI rules are fetched by `feed sync --for` from the `language_deps` names in the evidence file, then saved in the rule store. `resolve` only reads that store.

**From a data mirror (no upstream access).** When the raw files come from a mirror that serves them byte for byte (OpenNess Desktop uses its licensed backend; there is no public mirror yet), import each one instead of `feed sync`. `--source-url` and `--fetched-at` are only recorded in the rule metadata (for `explain`); they do not have to match anything:

```bash
openness-resolver rules import --data-dir data --source ubuntu-oval-usn-jammy --file com.ubuntu.jammy.usn.oval.xml.bz2 \
  --source-url https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2 --fetched-at 2026-11-03T11:40:00Z
OPENNESS_OSV_URL=https://mirror.example/data/v1/osv/query \
  openness-resolver feed sync --data-dir data --for host.openness --pypi-only
```

Every kind imports: Ubuntu OVAL (`.xml.bz2`), Alpine secdb (`main.json`, `community.json`; one keeps the other's rules), Debian tracker JSON, vendor OSV `all.zip`, Amazon `updateinfo.xml.gz`, MSRC CVRF month JSON. The mirror's ids (`debian-tracker`, `osv-redhat`, `amazon-al2`, `amazon-al2023`, `msrc-2026-Oct`) are accepted next to the registry ids. `OPENNESS_OSV_HEADERS` adds headers to the OSV queries, one `Name: value` per line.

---

## 7. Step C: Parse feeds into rules

Each normalized rule has this identity:

```
release + source_package + binary_package + CVE/advisory
```

### Ubuntu OVAL parser (`internal/feed/ubuntu`)

1. Read OVAL XML definitions (USN patch advisories).
2. Extract CVE IDs and USN advisory IDs from metadata.
3. Parse criterion comments (e.g. `libssl3 in release jammy was …`).
4. Read fixed version from OVAL state (`less than` EVR) or from the comment note.
5. Emit **one rule per binary package × CVE** (not one rule per source only).
6. Preserve raw vendor status text on every rule.
7. Reject unparsable records with a counted reason (never silent drop).

### Amazon Linux updateinfo parser (`internal/feed/amazon`)

1. Follow the release mirror list on `cdn.amazonlinux.com` to the core repository, then `repodata/repomd.xml` to `updateinfo.xml.gz` (every hop is an https snapshot on the same CDN).
2. Keep `type="security"` updates of the release's own collection that name at least one CVE; count everything else as a rejection.
3. Emit one binary-package rule per CVE with the fixed `[epoch:]version-release`; skip debuginfo and source rpms; one arch-free rule when all architectures share the fixed version.
4. Amazon Linux 2023 remediation hints use `dnf upgrade --releasever=latest`, because the host's repositories are locked to its release version; Amazon Linux 2 uses `yum update`. Amazon Linux 2 extras topics are not covered.

### Alpine secdb parser (`internal/feed/alpine`)

1. Read branch JSON from Alpine security database.
2. Map CVE → package → fixed version for each branch.
3. Emit normalized apk rules.

### OSV PyPI parser (`internal/feed/osv`)

1. Query `https://api.osv.dev/v1/query` per PyPI package name.
2. Extract CVE IDs from OSV ID and aliases.
3. Pick highest PEP 440 fixed version from affected ranges.
4. Store advisory ID (e.g. GHSA-…) separately from `cve_id`.

---

## 8. Step D: Load evidence

Command: `./bin/openness-resolver resolve --input file.openness`

Loader steps (`internal/evidence`):

1. Parse JSON and validate `schema_version`.
2. Decode each record category into typed structs.
3. Skip or report malformed records in `evidence_errors[]`.
4. Build platform context: distro, codename, architecture, support status.
5. Build package index: dedupe by `(name, version, arch, scope)`.
6. Build runtime index: which packages have running processes.
7. Build container inventory: group packages by image digest.
8. Build Python inventory from `language_deps[]`.

Platform support check:

- **supported** → full rule evaluation runs.
- **unsupported** → host rules are skipped; a note explains why.

---

## 9. Step E: Resolve host packages (Ubuntu)

For each installed **dpkg** host package:

### E1: Find candidate rules

Look up rules by:

- **Binary package name** (primary), and
- **Source package name** (secondary index).

Filter out:

- Kernel rules (handled in Step F).
- Rules where `PackageName` ≠ installed binary (prevents cross-binary contamination).

### E2: Group rules by vulnerability

Rules are grouped by CVE or advisory ID.  
They are **not** grouped by `release + source + CVE` alone.

### E3: Apply each rule (applicability gates)

Before version compare, check:

| Gate | Fail result |
|------|-------------|
| Binary package match | `not_applicable` |
| Distribution match (ubuntu) | `not_applicable` |
| Release/codename match (jammy) | `not_applicable` |
| Architecture match | `not_applicable` |
| Vendor status = not_affected | `not_applicable` |

### E4: Version comparison

For `released` rules with a fixed version:

```
installed < fixed  →  vulnerable
installed >= fixed →  fixed
```

Comparator: **dpkg** (pure Go, validated against native dpkg).

### E5: Supersede multiple USNs (same binary only)

If several USN rules fix the same CVE for the **same binary**:

- Pick the rule with the **highest fixed version**.
- Mark older rules as `superseded_rules[]`.

**Important:** Sibling binaries under the same source package never share a fixed version.

Example (bug we fixed):

- `libreoffice-base-core` must use note `1:7.3.6-0ubuntu0.22.04.2`.
- It must **not** use `fonts-opensymbol` fixed version `2:102.12+LibO7.3.6-…`.

### E6: ESM / Ubuntu Pro

If fix is in an ESM pocket and the host has no ESM entitlement:

- State stays `vulnerable`.
- `fix_availability` = `requires_esm`.

### E7: Runtime enrichment

If a fixed package still runs a deleted (pre-update) binary:

- State becomes `vulnerable_runtime`.
- Process IDs and binary paths are attached.

### E8: Provenance (T04)

Package origin is classified:

- `vendor`: from official Ubuntu archives.
- `third_party`: from PPA or external origin.
- `unknown`: version not in current apt indexes (superseded).

Third-party origin may lower confidence to `medium`.

---

## 10. Step F: Resolve running kernel

Kernel CVEs are **not** evaluated on every installed kernel image.

Steps:

1. Map running kernel string → source family (e.g. `linux-hwe-6.8`) + dpkg version.
2. Load kernel rules for that source family and release.
3. Filter rules with `RuleApplicable` (flavour, pocket, tier).
4. Evaluate against the **running** kernel package version only.
5. If a newer fixed kernel is installed but not booted, state may note reboot required.

Detection method: `ubuntu_running_kernel_fixed_version`.

Only Ubuntu's own kernels map to a source family. A host whose running kernel is not one
(Docker Desktop, OrbStack, WSL, a custom build, the host kernel seen from a container) gets
no kernel findings and a note saying the kernel advisories were skipped.

---

## 10a. Step F2: Resolve a Windows host (MSRC)

Windows evidence (collector `os_inventory` 1.2.0+) carries `build_number`, `ubr`, `product_type` and `installation_type`. The resolver turns that into one MSRC product key and one installed build:

1. `platform.ResolveWindowsProduct` maps the build number to the MSRC CPE product (`20348` → `windows_server_2022`, `26100` → `windows_server_2025` on a server SKU or `windows_11_24h2` on a client SKU). Server 2025 and Windows 11 24H2 share build 26100 but are serviced in different UBR streams, so the SKU decides. Unmapped builds are `not_supported` with a reason; nothing is guessed.
2. `feed sync --for host.openness` (or `--vendor microsoft --months N`) downloads the last N monthly CVRF documents from `api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>` (JSON). Only Vendor Fix remediations with a `FixedBuild` on `cpe:2.3:o:microsoft:windows*` products become rules; Office, .NET, Edge remediations are counted as skipped. Rules land in `data/normalized/microsoft/<product>/rules.json`, newer months replacing same-id rules.
3. The OS is modelled as one synthetic package `windows` with version `<build>.<ubr>`. Rules whose `FixedBuild` is on another build number are rejected (another servicing branch, not comparable). The rest go through the generic decision table with the `winbuild` comparator: `installed.ubr < fixed.ubr` → `vulnerable`, else `fixed`.
4. One action card `install_update` names the KB with the highest fixed UBR among vulnerable findings; cumulative servicing means that KB (or any later cumulative update) closes them all. `requires_reboot` comes from the vendor's `RestartRequired`. `command_hint` is empty.

Detection method: `msrc_fixed_build_ubr`. Not covered yet: .NET, Office, Edge, SQL Server, Exchange (products without a `FixedBuild` on the OS), Windows 8.1/7 ESU, Hotpatch baselines.

---

## 11. Step G: Resolve Python distributions

Python data comes from `language_deps[]` in evidence.

Each distribution has:

- `resolver_ecosystem`: `ubuntu_dpkg` or `pypi`
- `runtime_load_status`: `confirmed_loaded` or `installed_not_proven_loaded`
- `environment_id`, package name, version

### G1: ubuntu_dpkg (correlate, do not duplicate)

1. Map Python distribution → OS binary package + dpkg version.
2. Evaluate the same OVAL rules as Step E.
3. **Do not create a second host finding.**
4. Merge Python fields onto the canonical host finding:
   - `python_distribution_entity_ids`
   - `python_environment_ids`
   - `python_runtime_load_status`
   - `python_runtime_process_ids`
   - `python_runtime_evidence_ids`
5. Record the evaluation in `deduplicated_findings[]`.

### G2: pypi (separate finding)

1. Read OSV rules already stored for the normalized PyPI package name. `resolve` does not call the network.
2. Compare with **PEP 440** comparator.
3. Emit a separate finding with:
   - `scope` = `python_environment`
   - `environment_id`
   - `resolver_ecosystem` = `pypi`
   - `comparison.comparator` = `pep440`
   - OSV advisory ID in `advisory_ids[]` (not in `cve_id`)

---

## 12. Step H: Resolve containers (Alpine)

For each container group (by image digest):

1. Infer Alpine branch from image tag or label.
2. Match container packages to Alpine secdb rules.
3. Compare with **apk** comparator.
4. Scope = `container`; include `image_digest` and `container_ids[]`.

Host and container findings never merge, even if package names match.

---

## 13. Step I: Build output and metrics

Output file: `findings.json`

Top-level fields:

| Field | Meaning |
|-------|---------|
| `output_schema_version` | Contract version. `1` added `remediation_groups`; `2` adds `asset`, `software_inventory[]`, `unknowns[]` and guarantees list fields are never `null`. Field reference: [docs/findings-contract.md](findings-contract.md) |
| `asset` | Header for consumers: hostname, platform, collector/schema version, collection id/time/status, privilege level |
| `findings[]` | All serialized decisions |
| `deduplicated_findings[]` | Python ubuntu_dpkg evaluations merged into canonical findings |
| `rule_coverage` | Whether this asset's releases were actually evaluated |
| `remediation_groups[]` | Action cards. No score. See below |
| `reconciliation` | Proves metrics = serialized + deduplicated, and that host vulnerable findings sit in exactly one card |
| `software_inventory[]` | Collector catalog detections (schema 1.5.0+) passed through with `resolution.status`: `no_rules_for_product` or `version_unreadable`. No verdict until a product feed exists. A detection of software the distribution packages (openssl on Ubuntu) also shows up here; its CVEs are already judged through the dpkg package findings |
| `unknowns[]` | Everything seen but not judged: unsupported platform, missing rule coverage, findings in `unknown` / `conflicting_evidence` / `potentially_vulnerable`, software without rules, comparator errors. A consumer renders this list instead of inferring "not evaluated" from absence |
| `metrics` | Counts (packages, rules, findings by state) |
| `notes[]` | Warnings and informational messages |
| `evidence_errors[]` | Records that failed to decode |

Reconciliation invariant:

```
metrics.findings_vulnerable = reconciliation.serialized_vulnerable + reconciliation.deduplicated_vulnerable
metrics.findings_fixed      = reconciliation.serialized_fixed + reconciliation.deduplicated_fixed
reconciliation.balanced     = true
reconciliation.remediation_balanced = true
```

`rule_coverage.state` is `covered`, `missing`, or `not_applicable` (a network device from `resolve --device` uses `covered`, `not_supported` or `unknown`; see [findings-contract.md](findings-contract.md#network-devices-resolve---device)). `asset_release` is only the host release. `rules_for_asset` is the number of loaded rules for that host release and stays put when some other release is missing. Each hole is a `gaps[]` entry: `missing_rules` (feed sync can fetch it), `no_evaluator` (this build does not score that host, so feed sync will not fix it), `no_packages` (no usable host package), `unknown_distribution`, and the partial kinds `not_synced`, `invalid_package_records` and `packages_truncated` (see [findings-contract.md](findings-contract.md#rule_coveragegaps)). When state is `missing`, `resolve` writes `findings.json` and then exits 1. The error names `feed sync --for` only for `missing_rules` gaps.

`rule_coverage.sources[]` names the data behind the loaded rules, one entry per rule directory: `release` (`ubuntu/jammy`), `source` (`ubuntu-oval-usn-jammy`), the publisher `url`, the `sha256` of the file the rules were built from, `downloaded_at` (when that file was downloaded; `rules import --fetched-at` sets it for a mirror copy), `source_updated_at` when the publisher states it, and `parser`. `covered` says rules were loaded; `downloaded_at` says how old they are. A caller that wants fresh data checks it.

`resolve` does not download anything. PyPI names in the evidence file are fetched by `feed sync --for`, which merges them into `normalized/pypi/pypi`. A later asset does not erase an earlier asset's packages. `feed validate` does not call OSV and does not write that file. An OSV failure is reported after the Ubuntu and Alpine sources have been saved.

A PyPI distribution in the evidence is a `missing_rules` gap when that name was never fetched. One gap, `pypi`, covers an empty store. A name that was fetched and had no vulnerabilities is not a gap. The host `asset_release` stays a single release, written `alpine/v3.19` for both a 3.19.1 host and an image branch `v3.19`.

`remediation_balanced` is true when every host finding with `state=vulnerable` is in exactly one group and the sum of `closes.count` equals that number. A finding is never listed twice. `command_hint` is one informational line. The resolver does not run it.

Cards in this version:

| Action | When |
|--------|------|
| `upgrade_packages` | Host dpkg findings for one source package. `targets[]` lists the binaries. Each binary's `target_version` is the highest `fixed_version` among its findings, compared with the dpkg comparator. |
| `requires_entitlement` | The fix is in an ESM pocket, or the collector's `highest_list_origin` marks ESM, and the host has no observed Ubuntu Pro entitlement. `requires_entitlement` is `ubuntu_pro`. |
| `restart_service` | A `vulnerable_runtime` finding names a systemd unit, or a host package has `runtime_stale` and no vulnerable finding but a unit is known. `closes` is empty, so it does not change the vulnerable count. A still-vulnerable package that is also running keeps the upgrade card and lists the unit on `requires_service_restart`. |
| `reboot` | The evidence kernel record has `reboot_required`. Host-level info card, `closes` empty. |

`availability` uses the collector's `highest_list_version` on the package record (highest version in `/var/lib/apt/lists` for name|arch: not apt pin "candidate"). `highest_list >= target` is `available`. A lower list max is `not_yet_in_repo`. Missing field is `unknown`. Legacy `.openness` files that still emit `candidate_version` / `candidate_origin` are accepted as aliases.

A running-kernel finding is its own card with `requires_reboot`. The card reads `fixed_image_installed` on the finding. The hint is `reboot` when that field is set. When the fixed image is not on disk, the hint is `apt-get install linux-image-<new abi>-<flavour>`. It does not upgrade the running ABI package. Each target carries `architecture`, so two copies of the same package name stay distinct.

Groups are ordered by `closes.count` descending, then source package, then action, then `group_id`. Unit tests use synthetic fixtures. A lab capture once produced 4 `requires_entitlement` groups (ffmpeg, zvbi, python-pip, gst-plugins-bad1.0) that closed every host vulnerable finding. That capture is not in this repository, so those counts are not a CI lock. Container rebuilds and PyPI upgrades are not cards yet. If a package or unit name fails the hint token allowlist, it is omitted from `command_hint` and recorded in `notes` as `hint_token_dropped:<name>`.

---

## 14. Finding states and fields

### States

| State | Meaning |
|-------|---------|
| `vulnerable` | Installed version is below vendor fixed version |
| `fixed` | Installed version is at or above vendor fixed version |
| `not_applicable` | Rule does not apply (wrong arch, release, status, …) |
| `potentially_vulnerable` | Vendor status is `ignored` or similar |
| `unknown` | Missing fixed version or comparison error |
| `conflicting_evidence` | Two authoritative rules disagree |
| `vulnerable_runtime` | Fixed on disk but old binary still running |

### Finding types

| Type | Meaning |
|------|---------|
| `cve` | Normal CVE-based finding |
| `advisory_only` | USN with no CVE; `cve_id` is empty, USN in `advisory_ids[]` |
| `python_environment` | PyPI scope finding (may also have a CVE) |

### Key fields on every finding

| Field | Meaning |
|-------|---------|
| `finding_id` | Stable hash of asset + scope + package + vulnerability |
| `scope` | `host`, `container`, or `python_environment` |
| `binary_package` | Installed binary package name |
| `source_package` | Upstream source package name |
| `installed_version` | Version from evidence |
| `fixed_version` | Version from the matched vendor rule |
| `cve_id` | CVE identifier (empty for advisory-only) |
| `advisory_ids[]` | USN, GHSA, or other advisory IDs |
| `comparison` | Exact comparator expression and result |
| `rule` | Which vendor rule was chosen |
| `urgency` | The vendor's own priority (Ubuntu: negligible, low, medium, high, critical; Amazon: low, medium, important, critical), lower case; absent when the vendor did not rate it |
| `reasons[]` | Human-readable decision trail. "source package mapping is inferred from the binary name" means the evidence had no source package field, so the binary name was used; harmless when they are the same |
| `evidence_ids[]` | Links back to evidence records |

---

## 15. Version comparison

Native comparators (no shelling out to dpkg/apk at runtime):

| Ecosystem | Comparator | Package |
|-----------|------------|---------|
| Ubuntu / Debian | `dpkg` | `internal/version/dpkg` |
| Alpine | `apk` | `internal/version/apk` |
| PyPI | `pep440` | `internal/version/pep440` |
| Windows OS build | `winbuild` | `internal/version/winbuild` (`<build>.<ubr>`; different builds are not comparable) |

Test corpora in `testdata/` (2,766 dpkg pairs + 2,712 apk pairs) validate against native tools.

CLI test:

```bash
./bin/openness-resolver compare-version --ecosystem dpkg \
  --installed "1:7.3.7-0ubuntu0.22.04.12" \
  --fixed "1:7.3.6-0ubuntu0.22.04.2"
```

---

## 16. Important invariants

These rules protect correctness:

1. **Binary-specific fixed version**  
   `finding.binary_package` must match the binary package on the rule that supplied `fixed_version`.

2. **No cross-binary supersede**  
   Rules for `fonts-opensymbol` must not fix `libreoffice-base-core`.

3. **CVE vs advisory separation**  
   USN IDs go in `advisory_ids[]`, never in `cve_id`.

4. **Python ubuntu_dpkg = correlate**  
   Same `(asset, binary, version, CVE)` → one host finding + deduplicated record.

5. **Python pypi = separate identity**  
   Two environments with the same package name get different `finding_id` values.

6. **Metrics reconciliation**  
   Every counted finding is either in `findings[]` or `deduplicated_findings[]`.

7. **Kernel = running only**  
   Old kernel packages on disk do not produce kernel CVE findings.

8. **No AI**  
   All states come from deterministic code paths.

---

## 17. Validation and analysis scripts

Optional lab helpers live in `scripts/` (`analyze_evidence_run.py`, `python_resolver_validation.py`, `analyze_validation.py`, `pypi_controlled_test.sh`). They expect **your own** local `.openness` / `.nessus` paths: nothing under `testdata/evidence/` is shipped with host inventory.

```bash
python3 scripts/analyze_evidence_run.py /path/to/after.openness /path/to/before.openness
python3 scripts/python_resolver_validation.py /path/to/evidence.openness
```
### `pypi_controlled_test.sh`

Creates two Python venvs on an Ubuntu host for PyPI resolver testing.

---

## 18. Nessus comparison (optional)

`openness-resolver compare-nessus` diffs a credentialed Nessus `.nessus` export against resolver findings. Bring your own report; no scanner driver or sample report is shipped.

```bash
./bin/openness-resolver compare-nessus \
  --nessus /path/to/report.nessus \
  --findings findings.json \
  --host 192.0.2.10 \
  --local-only \
  --json nessus-diff.json
```

What it compares:

- Nessus **credentialed local security check** plugins only.
- CVE-level sets at **host scope**.
- Container and PyPI environment findings are excluded from host comparison.

Output buckets: `agreement`, `only_resolver`, `only_nessus`, `nessus_flagged_resolver_fixed`.

A difference does not always mean the resolver is wrong (scope mismatches, stale plugins, Python/container-only findings).
---

## 19. CLI reference

```bash
# Feeds
openness-resolver feed sync --for host.openness --data-dir data
openness-resolver feed sync --all --data-dir data
openness-resolver feed sync --source ubuntu-oval-usn-jammy --data-dir data   # registry or release ids: alpine-secdb-v3.20, msrc-cvrf-2026-Oct
openness-resolver feed sync --vendor microsoft --months 24 --data-dir data
openness-resolver feed list --data-dir data
openness-resolver feed validate --data-dir data   # downloads every enabled source (all vendors) and parses it without publishing

# Rules
openness-resolver rules stats --data-dir data
openness-resolver rules import --source <id> --file <raw> --data-dir data
openness-resolver rules format                     # which processed rules this build reads (format id)

# Resolve
openness-resolver resolve --input file.openness --output findings.json --data-dir data
#   --mapper mapper.json.gz   newer application mapper for Windows applications
#   --app-unverified          also use catalog entries no person reviewed
#   --app-guess=false         do not guess applications the catalog does not know

# Explain
openness-resolver explain --finding-id <id> --findings findings.json

# Version compare
openness-resolver compare-version --ecosystem dpkg|apk|pep440|winbuild \
  --installed <v> --fixed <v>

# Nessus diff
openness-resolver compare-nessus --nessus report.nessus --findings findings.json \
  --host <ip> --local-only --json diff.json

# Version
openness-resolver version
```

---

## 20. Project layout

```
cmd/openness-resolver/         CLI entry point
internal/
  evidence/                .openness loader and schema
  platform/                Distro/release/arch normalization
  pkgs/                    Package identity and source mapping
  version/dpkg|apk|pep440/ Native version comparators
  feed/                    Downloader (retry, ETag, SHA-256)
  feed/ubuntu/             Canonical OVAL parser
  feed/alpine/             Alpine secdb parser
  feed/osv/                OSV PyPI parser
  rules/                   Rule models, registry, filesystem store
  containers/              Container image digest grouping
  runtime/                 Process → package correlation
  kernel/                  Running kernel mapping and applicability
  python/                  language_deps inventory
  resolver/                Decision engine (core logic)
  findings/                Output model
  compare/                 Nessus diff
  report/                  JSON and summary writers
  testfixtures/            Synthetic evidence for unit tests
  buildinfo/                 Release version (ldflags / VERSION file)
scripts/                   Validation, analysis, build, and release helpers
data/
  raw/                     Immutable feed snapshots
  normalized/              Parsed rule JSON per vendor/release
build/                     Generated findings and reports (gitignored in prod)
testdata/                  Comparator validation corpora
docs/                      PROMPTS.md (contributor AI context)
```

---

## 21. Testing

What CI proves without real-host evidence:

- **Unit / synthetic integration** (`go test ./...`): version comparators, rule matching, remediation grouping, hint sanitization, `highest_list_*` field aliasing: via `internal/testfixtures` and small JSON fixtures under `testdata/`.
- **Optional local regression** (`-run AfterUpdate` / large lab captures): skipped when `testdata/evidence/*.openness` is absent (not shipped).

```bash
go test ./...

# Binary fixed-version logic (synthetic)
go test ./internal/resolver/... -run BinaryFixed

# Regenerate comparator corpora (Docker, dev only)
scripts/generate_dpkg_corpus.sh
scripts/generate_apk_corpus.sh
```

Integration scenarios in `internal/resolver/engine_test.go` cover:

- Before / at / after fixed version
- Wrong release, wrong architecture
- Epoch handling, tilde versions
- Container scope separation
- Runtime enrichment (deleted executable)
- ESM fix availability
- USN supersede within same binary
- Sibling binary isolation

---

## 22. License and contributing

This project is open source under the [Apache License, Version 2.0](../LICENSE). Contributions
are welcome; see [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution terms.

Full guidelines: [CONTRIBUTING.md](../CONTRIBUTING.md) · [SECURITY.md](../SECURITY.md) · [CHANGELOG.md](../CHANGELOG.md)

We use AI coding assistants during development; the resolver does **not** use AI at runtime.

### Principles for contributors

1. Keep decisions **deterministic**: no LLM in the decision path.
2. Keep vendor **raw status** on every rule: never discard source wording.
3. Keep **binary-specific** fixed versions: never merge sibling binaries.
4. Add a **test** for every bug fix.
5. Update this README if you add a new pipeline step.

### Report a bug

Include:

- Evidence file metadata (collector version, schema version, collection ID).
- One example finding with `rule`, `comparison`, and `reasons`.
- Expected vs actual state.

### Example output

Regression fixtures and sample outputs live under `testdata/` (evidence + normalized rules).  
For local runs after `feed sync`, write outputs to `build/` (gitignored) or any path you choose.

---

## Openness in S4E

Openness is free to run on your own machines. The same collector and resolver power the
Inside depth of [S4E](https://s4e.io), which adds scheduling, history, multi-host views and
remediation tracking on top. Read more at <https://s4e.io/labs/openness>.

---

## License

Copyright 2026 S4E (Security For Everyone)

Licensed under the [Apache License, Version 2.0](../LICENSE). Openness is open source: use it,
modify it and redistribute it, commercially or not, as the license describes. Keep the LICENSE
and NOTICE files with any copy you distribute.

Third-party notices: [NOTICE](../NOTICE). Conduct: [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).

See also: [CONTRIBUTING.md](../CONTRIBUTING.md) · [SECURITY.md](../SECURITY.md) · [CHANGELOG.md](../CHANGELOG.md)

---

## Version source of truth

- Release version: `VERSION` (semver `X.Y.Z`)
- Injected into binaries via `internal/buildinfo` ldflags
- CLI: `./bin/openness-resolver version`

Current value: see `VERSION`.

### Release workflow

Tag must match `VERSION`:

```bash
# runs tests, bumps VERSION, commits, tags, pushes (triggers GitHub Release)
bash scripts/release.sh patch
```

Manual bump only:

```bash
bash scripts/version.sh bump patch
# commit VERSION + internal/buildinfo/buildinfo.go, then tag vX.Y.Z
```

Build release binaries locally:

```bash
bash scripts/build.sh
ls dist/
```
