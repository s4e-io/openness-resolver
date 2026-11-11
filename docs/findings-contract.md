# findings.json contract (output_schema_version 2)

`openness-resolver resolve` writes one JSON document per evidence file. This is the
product contract: S4E or any other consumer renders it; the resolver does not
produce Markdown or HTML itself.

Rules that hold for every version:

- Additive changes bump the minor meaning of the contract; a consumer that
  ignores unknown fields keeps working.
- List fields are always arrays. An empty result is `[]`, never `null`.
- Nothing in this file is a score. Severity, when present, is the vendor's.
- `unknowns[]` is the honesty section: a consumer must show it. An empty
  `findings[]` with a non-empty `unknowns[]` is not a clean host.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `output_schema_version` | string | `"2"` |
| `asset_id` | string | Collector asset id |
| `asset` | object | Header (below) |
| `platform` | object | Normalized distribution, version, codename, architecture |
| `platform_support` | string | `supported` / `not_supported` / `unknown` (evidence lacks the OS identity) |
| `support_reason` | string | Why not supported (omitted when supported) |
| `rule_coverage` | object | `asset_release`, `rules_for_asset`, `loaded_releases[]`, `gaps[]`, `state` (`covered` / `partial` / `missing` / `not_applicable`; for a network device `covered` / `not_supported` / `unknown`), `reason`, `sources[]` (per loaded rule directory: `release`, `source`, `url`, `sha256`, `downloaded_at`, `source_updated_at`, `parser`, and with `downloaded_at` also `age_days` and `stale`: older than `resolve --stale-after`, default 2 days for distribution feeds, 35 for `msrc-*`, 7 for the mapper, never for PyPI; plus one entry for the application mapper when it was used, below) |
| `findings[]` | array | One decision per (scope, package, CVE/advisory). Fields in [internals.md section 14](internals.md#14-finding-states-and-fields) |
| `deduplicated_findings[]` | array | Python evaluations merged into canonical findings (may be omitted) |
| `remediation_groups[]` | array | Action cards (below) |
| `reconciliation` | object | Proves counts add up and each host vulnerable finding sits in one card |
| `software_inventory[]` | array | Catalog detections (below) |
| `applications[]` | array | Windows only: installed applications and what the application mapper made of each (below) |
| `application_mapper` | string | Windows and network devices: version of the application mapper data |
| `unknowns[]` | array | Seen but not judged (below) |
| `metrics` | object | Counts |
| `notes[]` | array | Warnings |
| `evidence_errors[]` | array | Records that failed to decode |
| `generated_at` | string | RFC 3339 UTC |

## `asset`

| Field | Meaning |
|---|---|
| `hostname`, `fqdn`, `machine_id` | From the collector |
| `platform`, `architecture` | GOOS / GOARCH of the collector run |
| `collector_version`, `schema_version` | What produced the evidence |
| `collection_id`, `collected_at`, `collection_status`, `privilege_level` | When and how it was collected; `partial` status means some module failed |
| `evidence_integrity` | `verified` (`integrity.payload_hash` matched) or `not_present` (no hash, older collector; a note says so). A mismatch stops `resolve` with exit 1. |

## `rule_coverage.gaps[]`

One entry per hole: `release` (`ubuntu/jammy`, `pypi`, `unknown` without a distribution), `kind`, and for some kinds `count` and `detail`.

| `kind` | Meaning | `state` | Exit |
|---|---|---|---|
| `missing_rules` | No rules loaded for the release; `feed sync --for` fills it | `missing` | 1 |
| `no_evaluator` | Recognized host this build does not score | `missing` | 1 |
| `not_synced` | PyPI data not in the store; the rest is evaluated | `partial` | 0 |
| `no_packages` | OS present but no usable host package (empty or missing list, every record malformed, packages module `unavailable` / `empty` / failed) | `missing` | 1 |
| `unknown_distribution` | No `distribution_id`, no `operating_system`, or a distribution the resolver does not know | `missing` | 1 |
| `invalid_package_records` | Malformed package records skipped; `count` says how many, each is an `unknowns[]` entry of kind `package_record` | `partial` | 0 |
| `packages_truncated` | The collector cut the package list (`package_limit_truncated`, a packages module timeout or output size cut `output_size_truncated`, `truncated` flag) | `partial` | 0 |
| `container_not_covered` | A container image with packages was not evaluated: no `os_release` in the evidence, a distribution or release outside the support matrix, no rules loaded for its release, or a package database the collector could not read (`packages_error` on the container, or on older evidence a `containers` module error naming the container with a timeout or failure; `detail` then reads `package database could not be read: <reason>`). `release` is `container:<image reference>` (or digest), `count` the number of containers running it, `detail` the image digest and the reason; also an `unknowns[]` entry. An image without packages (scratch) is only a note. | `partial` | 0 |
| `container_not_covered` (release `containers`) | The collector's `containers` module did not finish: a `timeout`, `output_size_truncated` or `record_limit` error, the `truncated` flag without a package cap, or status `error`. Containers may be missing from the evaluation; `detail` names the reason. | `partial` | 0 |
| `os_build_unknown` | Windows host whose build number or UBR could not be read (or whose `operating_system` is missing), so MSRC rules cannot be compared; `detail` is the reason | `missing` | 1 |
| `applications_incomplete` | Windows `applications` module failed, timed out or was cut; installed applications may be missing from the application findings | `partial` | 0 |

The state is `missing` when any gap is one of the `missing` kinds, else `partial`. Windows hosts are evaluated by build number and installed applications: they never get `no_packages`, and get `os_build_unknown` and `applications_incomplete` instead. `findings.json` is written in every case.

## `remediation_groups[]` (action cards)

One card per host source package plus info cards for service restart,
reboot and vulnerable runtime. A finding id appears in exactly one card,
except findings the vendor has not fixed yet (`fix_availability` unavailable
or deferred, such as Debian open and postponed issues): there is nothing to
install, so they are on no card and only listed in `findings[]`.

| Field | Meaning |
|---|---|
| `group_id`, `scope`, `action` | `upgrade_packages`, `install_kernel`, `restart_service`, `reboot`, `requires_entitlement`, `vulnerable_runtime`, `install_update` (Windows cumulative update) |
| `targets[]` | `name`, `architecture`, `installed_version`, `target_version`, `kind` (`binary` / `unit` / `os_build`) |
| `source_package`, `advisory_ids[]` | What the card is about |
| `closes` | `finding_ids[]`, `cve_ids[]`, `count` |
| `requires_reboot`, `requires_service_restart[]`, `requires_entitlement` | Follow-up conditions; entitlement is `ubuntu_pro` or null |
| `availability` | `available`, `not_yet_in_repo`, `unknown` (from the collector's `highest_list_version`) |
| `coverage_note` | `hint_tokens_omitted` when a name failed the hint allowlist |
| `command_hint` | One informational line; never executed by the resolver |

## `software_inventory[]`

Pass-through of the collector's `software_instance` records (schema 1.5.0+)
with the resolver's stance. There is no vendor feed for these products yet,
so no instance gets a vulnerability verdict.

| Field | Meaning |
|---|---|
| `entity_id`, `evidence_id` | Stable id (`sw:<product_key>:<scope>:<hash>`) and the evidence record |
| `product_key`, `vendor`, `product`, `cpe_prefix` | Catalog identity |
| `scope`, `install_path` | Where it was found |
| `version`, `version_source` | What the collector read and from which file/registry key; omitted when unreadable |
| `patch_ids[]` | Vendor patch identifiers (Oracle oneoffs) |
| `running`, `ports[]` | Presence signals |
| `confidence` | `direct` (version read) or `presence_only` |
| `catalog_verified` | `false` means the collector catalog entry was never exercised on a real install; treat the reading as unproven |
| `resolution.status` | `no_rules_for_product` or `version_unreadable` |
| `resolution.reasons[]` | Human-readable reasons, including `catalog_entry_unverified` |

## Third-party Windows applications (application mapper)

On a Windows host the resolver also matches the collector's `applications`
(Add/Remove Programs, AppX) against the application mapper: a catalog that ties
an application's name and publisher to NVD CPE products and says where its
version is, plus the NVD CVEs and affected version ranges of those products.
The mapper is a bundle (JSON or gzip, format `openness-app-mapper/1`:
`{"format", "version", "catalog", "vulns", "fallback"?}`; without `fallback` the
built-in one stays; at most 256 MB uncompressed, read as a stream). `resolve`
takes `--mapper <file>` when given, else `<data-dir>/mapper/app-mapper.json.gz`
(written by `feed sync` from the `app-mapper` source, with its metadata in
`app-mapper.json.gz.meta.json`), else the one built into the binary. The one used
is listed in `rule_coverage.sources[]`:

| Field | Value |
|---|---|
| `release` | `mapper` |
| `source` | `app-mapper` (synced into the data directory), `app-mapper-file` (`--mapper`), `app-mapper-builtin` |
| `version` | The bundle's `version` |
| `url`, `sha256`, `downloaded_at` | From the metadata next to the file (`<file>.meta.json`) when there is one; empty for the built-in mapper |
| `parser` | `openness-app-mapper/1` |

Metadata file (`<data-dir>/mapper/app-mapper.json.gz.meta.json`):
`{"source":"app-mapper","source_url":"https://github.com/s4e-io/openness-app-mapper/releases/latest/download/app-mapper.json.gz","downloaded_at":"2026-11-05T06:00:00Z","sha256":"<hex>","size_bytes":123,"format":"openness-app-mapper/1","version":"<bundle version>"}`.

- Findings: `detection_method` `nvd_cpe_version_range` (catalog match,
  `vulnerable`) or `nvd_cpe_name_guess` (an application the catalog does not
  know whose name looks like an NVD product, `potentially_vulnerable`, only with
  `--app-guess`, on by default). `severity` and `cvss_score` carry the NVD
  rating. `binary_package` is the application name, `source_package` the
  catalog id. Entries no person reviewed count only with `--app-unverified`.
- Confirmation (`verify` on a catalog entry): the name match is only a candidate;
  it stands when the entry's uninstall key or MSI ProductCode is one of
  `verify.product_codes`, or the collector found `verify.file.path` under its base
  (`install_location`, `program_files`, `display_icon_dir`) with a valid
  Authenticode signature whose signer CN is `verify.file.signer`
  (`version_from_file` then takes the version from the file). A check that ran
  and failed refuses the match (`status: verify_failed`, `verify_reason`); a sign
  that could not be checked (collector without `--file-probes`, no install
  location) leaves a name-only match. `match_strength` on findings and
  applications: `signature`, `product_code` or `name`. `openness mapper probes
  [--mapper f]` prints the files for `collect --file-probes`.
- Cards: one `update_application` card per application version, target kind
  `application`, `command_hint` from the catalog (a winget command).

`applications[]`:

| Field | Meaning |
|---|---|
| `name`, `publisher`, `version` | As the collector read them |
| `architecture`, `install_scope`, `product_code` | x64/x86, machine/user, MSI product code |
| `key`, `view`, `install_location` | Uninstall subkey, registry view (`HKLM64`, `HKLM32`, `HKCU`), install folder |
| `status` | `matched`, `guessed`, `unmatched` (nothing known about it), `no_version` (matched, version unreadable), `unverified` (only an unreviewed entry matched and those are off), `verify_failed` (the entry's confirmation was checked and did not hold) |
| `match_strength`, `verify_reason` | How a match was confirmed; why a `verify_failed` one was refused or what could not be confirmed |
| `product_id`, `cpe[]`, `matched_version` | The catalog entry (or guessed NVD product) and the version as it reads it |
| `cves` | Findings it produced |

## Catalog entries

`catalog` is an array of entries. An application entry:

```json
{"id":"mozilla.firefox-esr","name":"Mozilla Firefox ESR","match":{"name":"^Mozilla Firefox.*\\bESR\\b","publisher":"Mozilla"},
 "version":{"from":"display_version","regex":"","format":"","parts":0},"cpe":["mozilla:firefox_esr"],
 "update":"winget upgrade --id Mozilla.Firefox.ESR","same_branch":true,"verified":true}
```

`kind` is `application` (the default when absent) or `device`. An entry of any other
kind is ignored, so an older build reads a newer catalog. A device entry:

```json
{"id":"cisco.ios-xe","name":"Cisco IOS XE","kind":"device",
 "match":{"sys_object_id":"^\\.?1\\.3\\.6\\.1\\.4\\.1\\.9\\.","sys_descr":"Cisco IOS.*Version (1[6-9]|[2-9][0-9])\\.[0-9]+\\.[0-9]+"},
 "version":{"from":"sys_descr","regex":"Version ([0-9]+\\.[0-9]+\\.[0-9]+[a-z]?)","parts":3},
 "cpe":["cisco:ios_xe"],"update":"Upgrade IOS XE to a fixed release (see the Cisco security advisory).","verified":false}
```

| Field | Meaning |
|---|---|
| `match` | Case-insensitive regular expressions; every key given must match, at least one is required. `sys_object_id` (sysObjectID, with or without the leading dot), `sys_descr` (sysDescr), `model` (entPhysicalModelName), `vendor` (matched against sysDescr: SNMP has no vendor field) |
| `version.from` | `sys_descr` (default), `software_rev` or `firmware_rev` |
| `version.regex` | Required, exactly one capture group: the version |
| `version.parts` | Keep the first n dotted parts (0 keeps all) |
| `cpe[]` | NVD products (`vendor:product`) whose CVEs in `vulns` apply, compared exactly as for applications |
| `update` | The update card's `command_hint` |
| `verified` | A person reviewed the entry; unreviewed entries count only with `--app-unverified` |

The first device entry that matches wins.

## Network devices (`resolve --device`)

Input, format `openness-device/1` (written by the desktop from SNMP; a file with any
other field, such as a host name or an address, is refused):

```json
{"format":"openness-device/1","sys_descr":"Cisco IOS Software [Cupertino], ... Version 17.9.4a, RELEASE SOFTWARE (fc5)",
 "sys_object_id":".1.3.6.1.4.1.9.1.2494","model":"C9300-48P","software_rev":"17.9.4a",
 "firmware_rev":"","hardware_rev":"","serial_hint":""}
```

Output, the normal findings document:

- `platform`: `distribution_id` `network_device`, `codename` the matched entry id
  (`codename_source` `device_catalog`), `distribution_version` the version read,
  `raw_distribution_id` the first `sys_descr` line. `asset.platform` is the same line.
  The line is copied only for a matched device, with IP addresses and dotted host names
  replaced by `[redacted]`. Nothing else of the device file is copied.
- `platform_support`: `supported` when an entry matched, else `not_supported` with
  `support_reason`.
- Findings: scope `network_device`, `finding_id` `device:<entry id>:<version>:<CVE>`,
  `detection_method` `nvd_cpe_version_range`, `binary_package` the entry name,
  `source_package` the entry id.
- Cards: one `update_device` card, target kind `device`, `command_hint` from `update`.
- `rule_coverage`: `asset_release` `device/<entry id>`, `rules_for_asset` the CVE records of
  its products; `state` `covered`, `not_supported` (no entry matched: no findings, a
  note, exit 0) or `unknown` (an entry matched, the version could not be read: no
  findings, a note, an `unknowns[]` entry with reason `version_unreadable`, exit 0).

## `unknowns[]`

| Field | Meaning |
|---|---|
| `kind` | `platform`, `rule_coverage`, `finding`, `software`, `comparator`, `package_record` |
| `subject` | Release, package + CVE, product + version, ... |
| `reason` | Why it was not judged (state name, coverage gap kind, support reason) |
| `finding_id`, `entity_id` | Back-references when they exist |

## Versions

| Version | Change |
|---|---|
| 1 | `remediation_groups[]`, `reconciliation` |
| 2 | `asset`, `software_inventory[]`, `unknowns[]`; lists never `null` |
| 2 (additive) | `applications[]`, `application_mapper`, finding `severity` and `cvss_score`, action `update_application` |
| 2 (additive) | catalog `verify`, `match_strength`, `verify_failed`, application `key`, `view`, `install_location`, `mapper probes` |
| 2 (additive) | `resolve --device`, scope `network_device`, action `update_device`, target kind `device`, coverage states `not_supported` and `unknown`, catalog `kind`, `rule_coverage.sources[].version` and the mapper entry |
| 2 (additive) | `asset.evidence_integrity`, coverage state `partial` for package gaps, gap kinds `no_packages`, `unknown_distribution`, `invalid_package_records`, `packages_truncated`, gap `count` and `detail`, unknowns kind `package_record` |
| 2 (additive) | Debian, Ubuntu and RPM-family container findings (scope `container`), gap kind `container_not_covered` |
