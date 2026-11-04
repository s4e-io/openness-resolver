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
| `rule_coverage` | object | `asset_release`, `rules_for_asset`, `loaded_releases[]`, `gaps[]`, `state` (`covered` / `missing` / `not_applicable`), `reason`, `sources[]` (per loaded rule directory: `release`, `source`, `url`, `sha256`, `downloaded_at`, `source_updated_at`, `parser`) |
| `findings[]` | array | One decision per (scope, package, CVE/advisory). Fields in [internals.md section 14](internals.md#14-finding-states-and-fields) |
| `deduplicated_findings[]` | array | Python evaluations merged into canonical findings (may be omitted) |
| `remediation_groups[]` | array | Action cards (below) |
| `reconciliation` | object | Proves counts add up and each host vulnerable finding sits in one card |
| `software_inventory[]` | array | Catalog detections (below) |
| `applications[]` | array | Windows only: installed applications and what the application mapper made of each (below) |
| `application_mapper` | string | Windows only: version of the application mapper data |
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
The mapper is built in; `resolve --mapper <file>` replaces it with a newer one
(JSON or gzip, format `openness-app-mapper/1`: `{"format", "version",
"catalog", "vulns", "fallback"?}`; without `fallback` the built-in one stays).

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

## `unknowns[]`

| Field | Meaning |
|---|---|
| `kind` | `platform`, `rule_coverage`, `finding`, `software`, `comparator` |
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
