# Changelog

All notable changes to this project are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `osv-pypi` feed source: the OSV PyPI archive (`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`) downloaded and normalized into `normalized/pypi/pypi` like the other OSV sources. `feed sync --for` selects it when the evidence lists PyPI packages; `--source osv-pypi`, `--vendor pypi`, `--all` and `rules import --source osv-pypi --file all.zip` too. A damaged archive (zip CRC) publishes nothing.
- Downloads honour `Retry-After` on 429 and 5xx (seconds or an HTTP date, at most 60 s per wait) and no longer retry 404 and other client errors.

- `app-mapper` feed source: the application and device mapper (`openness-app-mapper/1`) from the public release of `s4e-io/openness-catalog`, checked against `SHA256SUMS` and stored as `<data-dir>/mapper/app-mapper.json.gz` with its metadata. `feed sync --for` selects it for Windows, applications and network devices; `--source app-mapper`, `--vendor openness`, `--all` and `rules import --source app-mapper` too. `--mapper-url` points it at a mirror.
- `resolve` takes the mapper from `--mapper`, else the data directory, else the built-in one, and lists it in `rule_coverage.sources[]` with its `version` and `downloaded_at`.
- Old data: `rule_coverage.sources[]` carries `age_days` and `stale`; `resolve` warns on stderr and in `notes[]` when a source is older than its limit (2 days for distribution feeds, 35 for MSRC, 7 for the mapper, `--stale-after` overrides, `0` turns it off). `feed list` shows the age of every source.
- `feed sync` never installs a mapper older than the synced or the built-in one; `--allow-downgrade` forces it.
- Network devices: catalog entries of `kind` `device` matched against SNMP data, `resolve --device <openness-device/1 file>`, findings with scope `network_device`, `update_device` cards, coverage states `not_supported` and `unknown`. Unreviewed seed entries for Cisco IOS XE, IOS, NX-OS, ASA, Fortinet FortiOS, Juniper Junos, MikroTik RouterOS, Palo Alto PAN-OS, Aruba AOS-CX and Ubiquiti EdgeOS.

### Changed

- `resolve` makes no network call for PyPI: Python packages are matched against the local `osv-pypi` data. Without it, `rule_coverage.state` is `partial` with a `not_synced` gap for `pypi` and a note, the rest of the asset is resolved and the exit code is 0 (it was 1).
- `osv-pypi` data counts as old after 2 days, like the distribution feeds (it was never old).
- `feed sync --pypi-only` is deprecated: it syncs only `osv-pypi`, and a failed download is a warning with exit 0. `--osv-url` is deprecated and ignored.

### Removed

- The per-package OSV queries (`api.osv.dev/v1/query` or a mirror) and the `OPENNESS_OSV_URL` and `OPENNESS_OSV_HEADERS` variables.

### Changed (continued)

- Mapper files are read as a stream and refused above 256 MB uncompressed.
- README names the product OpenNess Vulnerability Scanner.

## [0.7.0] - 2026-11-04

### Changed

- The tool is named `openness-resolver` everywhere: `cmd/openness` moved to `cmd/openness-resolver` (`go install github.com/s4e-io/openness-resolver/cmd/openness-resolver@latest`), `scripts/build.sh` writes `bin/openness-resolver`, and the usage text, hints and docs say `openness-resolver`. Release asset names are unchanged.
- `feed list`, `feed validate`, `rules stats` and `rules format` accept only the flags they use, so `-h` lists exactly those; a flag of another subcommand is now a usage error.
- `feed sync --vendor` rejects an unknown vendor and `--months` below 1 (it silently meant 24) with a clear error.
- README rewritten for users (install, quick start, every command and flag, data sources with licenses); the design material moved to `docs/internals.md` unchanged.

### Added

- `rule_coverage.sources[]` in the output: per loaded rule directory the source, publisher URL, sha256 of the file the rules were built from, `downloaded_at`, `source_updated_at` and parser, so rules built from an old download are visible even when coverage is complete.

- `feed sync --dry-run` and `feed validate --dry-run` print the sources that would be downloaded and download nothing.
- Golden end-to-end CLI tests on Linux and Windows, table-driven tests of every flag, publisher-only URL tests, a README drift guard, and a nightly workflow (`nightly.yml`) that syncs from the publishers with no secrets, validates every enabled source, writes a per-source step summary and tracks failures in a `nightly` issue.
- `feed sync` and `feed validate` print how long each source took (`took 1.2s`).

### Fixed

- `feed sync -h` showed `-pypi-only rules import`: a backtick in the usage text was read as the value name.

## [0.6.0] - 2026-11-03

### Fixed

- **`feed sync --source`** accepts release-derived ids (`ubuntu-oval-usn-<codename>`, `alpine-secdb-<branch>`, `msrc-cvrf-<YYYY-Mon>`) and names an unknown id instead of "no sources selected".
- **`urgency`** is written lower case, and not at all for an unrated rule (feeds said `Medium`, `medium` and `None`).
- **`compare-version`** help lists every registered ecosystem (`apk | dpkg | pep440 | rpm | winbuild`).

### Documentation

- README: install from a release (and as `openness-resolver`, so it does not clash with the collector's `openness`), keeping the data current (cron, disk, snapshots), how to read the sync counters, `feed validate` downloads every enabled source, `--source` example fixed, `urgency` documented, kernel checks only for Ubuntu kernels, software_inventory beside package findings; the stale 0.1.0 version lines are gone.

### Added

- **`openness rules format`** prints which processed rules this build reads: `{"format": "openness-rules/1", "id": "<12 hex>", "parsers": {...}}`. The id changes with the rule layout or any parser version, so a data mirror can ship rules built by `rules import` ready to use (as compressed archives) to every build with the same id, and the others import the raw files themselves.

### Fixed

- **The same input gives the same bytes**: `rules.json` is written sorted by rule id (parsers collect rules in maps, so the order changed between runs) and `metadata.json` lists package names sorted. A data mirror's archive then changes only when the rules do, so desktops do not download unchanged data again.

## [0.5.0] - 2026-11-03

### Added

- **Data mirror support**: `rules import` takes the source ids of the openness-backend data mirror as well (`debian-tracker`, `osv-redhat`, `amazon-al2`, `amazon-al2023`, `msrc-<YYYY-Mon>`, and `alpine-secdb-<vX.Y>` with `main.json` or `community.json`), records the file's sha256 and size, and takes `--source-url` and `--fetched-at`. Importing Alpine's community document keeps the branch's main rules (and the other way round), as `feed sync` does. `feed sync --for <file> --pypi-only` queries only the PyPI packages, and `--osv-url` (or `OPENNESS_OSV_URL`) sends those queries to a mirror of `api.osv.dev/v1/query`; `OPENNESS_OSV_HEADERS` adds request headers, one `Name: value` per line. A host whose data comes from a mirror then never reaches the upstream publishers.

### Fixed

- **Firefox ESR coverage**: the application data now also holds NVD ranges by edition (`mozilla:firefox:esr`; the NVD moved ESR into `sw_edition`) and a catalog entry can be `same_branch`, so a range counts only on the installed release line. On a Windows Server 2022 with Firefox ESR 115.3.1, Firefox ESR went from 56 to 298 CVEs, 296 of them also in Nessus's list, with no CVE of another ESR line ("< 128.4") reported for 115. Git also maps `git:git`, which brings CVE-2024-32002.

## [0.4.0] - 2026-11-03

### Added

- **Confirmed application matches**: a catalog entry can carry `verify` (`product_codes`, `file` with `path`, `base`, `signer`, `version_from_file`). The name match is then a candidate that stands only on the product's uninstall key / ProductCode or its signed file (collector `--file-probes`); a check that fails gives `verify_failed` instead of findings, so a program renamed to a product's name raises no false CVEs. Findings and applications carry `match_strength` (`signature`, `product_code`, `name`). `openness mapper probes` prints the files for the collector. Applications also carry `key`, `view` and `install_location`.

## [0.3.0] - 2026-11-03

### Added

- **Third-party Windows applications** (application mapper): a Windows host's installed applications are matched to NVD CPE products by a built-in catalog, and their CVEs come with the NVD severity and CVSS (`nvd_cpe_version_range`), one `update_application` card per application version, and `applications[]` listing every application with its match status (`matched`, `guessed`, `unmatched`, `no_version`, `unverified`). `resolve --mapper <file>` replaces the built-in data at run time (format `openness-app-mapper/1`); `--app-unverified` and `--app-guess` choose which matches count. Moved from OpenNess Desktop; on real Windows Server 2022 evidence the findings are identical.

- **Alpine hosts**: an Alpine host is evaluated against Alpine secdb with the apk comparator. The rule release is the branch derived from `VERSION_ID` (3.20.10 is `v3.20`), so `feed sync --for` no longer fails with `invalid release ""`. secdb rules name origin packages and now match every subpackage built from that origin (libcrypto3 and libssl3 from openssl), on hosts and in images.
- **Amazon Linux 2 and 2023**: new `amazon-updateinfo-<release>` sources read the ALAS advisories from the core repository `updateinfo.xml.gz` (the document `dnf updateinfo` reads). Findings use `rpm_package_fixed_version`; remediation hints are `dnf upgrade --releasever=latest` (2023) and `yum update` (2).
- `testedReleases` now lists alpine 3.20, debian 12, rocky 9, almalinux 8, opensuse 15.6, amazon 2 and amazon 2023, each verified with a real linux/arm64 image scanned by the collector.

### Fixed

- The Alpine secdb registry stopped at v3.19 although v3.14 to v3.22 were listed as supported; `feed sync --vendor alpine` now syncs every supported branch.
- Two feed sources with the same file name fetched within one second (main.json of two Alpine branches) wrote one raw snapshot file; the second is now stored under its source id.
- alpine was marked tested for every branch on the strength of container images; a host is now tested only for the branch verified as a host (3.20).

### Changed

- License changed from the PolyForm Noncommercial License 1.0.0 to the [Apache License, Version 2.0](LICENSE). Openness is open source; COMMERCIAL.md is removed. Releases published before this change keep the license they were published under.

## [0.2.0] - 2026-10-28

### Changed

- License changed from MIT to the [PolyForm Noncommercial License 1.0.0](LICENSE). The project is now source-available: free for non-commercial use, commercial use is reserved to S4E (see [COMMERCIAL.md](COMMERCIAL.md)). Releases published before this change keep the license they were published under.

### Fixed

- `notes[]` and `evidence_errors[]` were `null` or omitted when empty, against the contract; every list field is now always a JSON array.
- A Windows host whose `build_number` or `ubr` is not a number (for example `"-5"`) was reported `supported` with zero findings, which reads as clean. It is now `not_supported` with a reason, so it lands in `unknowns[]`.
- Evidence with a `schema_version` major other than `1` is refused with an error instead of being resolved with possibly changed field meaning.

### Added

- `output_schema_version` **2** (additive): `asset` header, `software_inventory[]` (collector schema 1.5.0 catalog detections passed through with `resolution.status`), `unknowns[]` (seen-but-not-judged list). `findings`, `remediation_groups`, `software_inventory` and `unknowns` are always JSON arrays, never `null`. Contract reference in `docs/findings-contract.md`.
- Evidence loader reads the `software_inventory` section (schema 1.5.0+); older evidence yields an empty list.
- **Windows OS resolution (MSRC)**: `feed sync --vendor microsoft --months N` / `--for <windows.openness>` download monthly CVRF JSON documents; `internal/feed/msrc` normalizes Vendor Fix remediations with a `FixedBuild` on `cpe:2.3:o:microsoft:windows*` products into `winbuild` rules (`fixed_version` = `<build>.<ubr>`, `advisory_ids` = KB, `supersedes`, `restart_required`, MSRC severity as `urgency`). `platform.ResolveWindowsProduct` maps `build_number` + SKU to the MSRC product key; `winbuild` comparator; findings with detection method `msrc_fixed_build_ubr`; one `install_update` action card (`target kind os_build`) per host. Rule coverage reports `windows/<product>`.

### Added

- `remediation_groups` on resolver output (`output_schema_version` 1). Host vulnerable findings for one source package become one action card. The card has no score. `command_hint` is not executed.
- Availability from collector `highest_list_version` / `highest_list_origin` (legacy `candidate_*` accepted), and `requires_entitlement` / `ubuntu_pro` when the fix is only in Ubuntu Pro/ESM.
- Restart and reboot info cards. A finding id stays in at most one card.
- A running kernel is not told to `apt-get install` an image that is already on disk. The card reads `fixed_image_installed`. When the fixed image is absent, the hint installs the new ABI package (`linux-image-<abi>-<flavour>`), not an upgrade of the running ABI package. Targets carry `architecture`.
- CODE_OF_CONDUCT, CODEOWNERS, NOTICE, Dependabot.

### Fixed

- Field name alignment with openness-collector 0.5: `highest_list_*` (not invented apt pin "candidate").
- `command_hint` package/unit tokens sanitized (reject shell metacharacters).
- `--preflight` no longer pins a lab filename/SHA.
- Module path `github.com/s4e-io/openness-resolver` (go install works).
- Removed lab planning docs, `nessus_scan.py`, and real-host evidence captures from git (history purge via filter-repo required before public).
- CI: gofmt/vet, SHA-pinned actions; workflows run on stacked PR bases (`pull_request: branches: ['**']`).
- S4E Code of Conduct (not Contributor Covenant boilerplate).
- `command_hint` drops unsafe tokens into `notes`; ESM origin match tightened; NOTICE includes full Go toolchain BSD text.
- Rule coverage treats an Alpine host, and an Alpine image whose branch has no rules, as not evaluated. `asset_release` stays the host release and `rules_for_asset` is not cleared by another release. Each hole is a `gaps[]` entry: `missing_rules` or `no_evaluator`. An Alpine host exits without telling the operator to run feed sync.
- `resolve` does not download PyPI rules. `feed sync --for` merges them into the shared PyPI rule file, so a second asset does not erase the first. `feed validate --for` does not call OSV. An OSV failure does not discard Ubuntu or Alpine rules already saved. A PyPI distribution that was never fetched is a `missing_rules` gap. An Alpine host release is written `alpine/v<major>.<minor>`, the same form as an image branch.
- A PyPI rule file written before `package_names` existed cannot tell "fetched, no vulnerabilities" from "never fetched". Run `feed sync --for` once on that evidence so the snapshot records the names. Until then, resolve exits 1 for those distributions.
- Availability stays on collector `highest_list_version`: the highest version in the apt lists for that name and architecture, not the apt pin candidate. `candidate_*` is only a legacy alias.
- Dropped unsafe `command_hint` tokens set `coverage_note` to `hint_tokens_omitted` on upgrade and restart cards.
- Lab-only `openness backlog` is not a public command. The 4-group lab measurement is not a CI lock; the capture is not in the tree.
- A PyPI rule file written before `package_names` existed cannot tell "fetched, no vulnerabilities" from "never fetched". Run `feed sync --for` once on that evidence so the snapshot records the names. Until then, resolve exits 1 for those distributions.
- The missing-coverage banner lists `gaps[]`, not the host `asset_release`.
- Lab host captures are not a CI lock. The 4-group measurement was taken on a capture that is not in the repository. Unit tests use synthetic fixtures.

## [0.1.0] - 2026-08-10

### Added

- Initial public release under MIT License
- Deterministic resolver for `.openness` evidence files (no AI at runtime)
- Vendor feed sync and normalization: Ubuntu OVAL/USN, Alpine secdb, OSV (PyPI)
- Host package, kernel, Python distribution, and Alpine container scope resolution
- Explainable findings output (`findings.json`) with rule, comparison, and reasons
- Native version comparators: dpkg, apk, PEP 440
- Regression fixtures under `testdata/evidence/`
- Build scripts and GitHub Actions CI/release (Linux binaries)

### Notes

- Evidence collection is done by [openness-collector](https://github.com/s4e-io/openness-collector).
- Normalized vendor data is produced locally via `openness feed sync --all` and is not shipped in git.
- Project hub: [github.com/s4e-io/openness](https://github.com/s4e-io/openness)

[0.2.0]: https://github.com/s4e-io/openness-resolver/releases/tag/v0.2.0
[0.1.0]: https://github.com/s4e-io/openness-resolver/releases/tag/v0.1.0
