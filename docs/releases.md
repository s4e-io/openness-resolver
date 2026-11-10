# Releases and their data

Which release of each distribution has published security data, which ones the resolver
covers, and what to do when a vendor ships a new release or ends one.

A host on a release outside the support matrix is not checked. Its `support_reason` says
why, in one of three forms (`internal/platform/platform.go`, `releaseOutsideMatrix`):

- the vendor publishes no security data for it (an end-of-life release): upgrade;
- the vendor publishes data, but the release is not covered yet: add it (see below);
- neither is known: the release is not covered.

## Current state

Checked on 10 November 2026 against the publishers (`scripts/check-releases.sh`).

| Distribution | Covered | Data published, not covered | No data published |
|---|---|---|---|
| Ubuntu (USN OVAL) | 20.04, 22.04, 24.04, 26.04, 26.10 | 14.04, 16.04, 18.04 (ESM, fixes need Ubuntu Pro); 24.10, 25.04, 25.10 (end of life, data frozen) | 20.10, 21.04, 21.10, 22.10, 23.04, 23.10 and every interim release up to 19.10 |
| Debian (Security Tracker) | 12, 13 | | 11 and older (the tracker lists bookworm, trixie, forky and sid only) |
| Alpine (secdb) | 3.14 to 3.24 | 3.10 to 3.13 (end of life) | |
| Rocky Linux (OSV) | 8, 9, 10 | | |
| AlmaLinux (OSV) | 8, 9, 10 | | |
| RHEL (OSV) | 8, 9 | 7 (ELS) | 10: not confirmed in OSV yet |
| openSUSE Leap (OSV) | 15.5, 15.6, 16.0 | 15.4 (end of life) | |
| Amazon Linux (updateinfo) | 2, 2023 | | AMI 2018.03 |

Ubuntu releases a vendor still supports: `https://changelogs.ubuntu.com/meta-release`
(`Supported: 1`). Alpine branches and their end of life: `https://alpinelinux.org/releases.json`.

## Where the lists live

A release is added or moved in all of these; a list left behind means the data is not
mirrored or the desktop does not offer it.

| Repository | File | What |
|---|---|---|
| openness-resolver | `internal/platform/platform.go` | `productionSupportedReleases`, `ubuntuCodenames`, `vendorPublishedReleases`, `noVendorData` |
| openness-resolver | `internal/rules/sources.go` | `AlpineBranches` |
| openness-resolver | `README.md` | the Data sources table |
| openness-backend | `internal/mirror/sources.go` | `UbuntuReleases`, `AlpineBranches` (the data mirror) |
| openness-desktop | `internal/engine/feed.go` | `ubuntuReleases` |
| openness-desktop | `cmd/checksgen/lifecycle.go` | the end-of-life dates of the host lifecycle check |

RPM distributions (Rocky, AlmaLinux, RHEL, openSUSE) come from vendor-wide OSV exports:
the mirror keeps the releases in `productionSupportedReleases`, so the resolver list is the
only one to change.

## When to check

- Ubuntu: every April and October (new release), and when an interim release ends (9
  months after its release).
- Alpine: every May and November.
- Debian: a new stable release (about every two years) and the end of LTS of the old one.
- Rocky Linux, AlmaLinux, RHEL: a new major release.
- openSUSE Leap, Amazon Linux: a new release.
- Any time a scan reports "publishes security data for ..., but this release is not
  covered yet".

## Adding a release

1. Run `scripts/check-releases.sh` and confirm the vendor supports the release and its data
   URL answers 200.
2. Add it to every list in [Where the lists live](#where-the-lists-live). Remove it from
   `vendorPublishedReleases` if it was there.
3. Test it on a real host or container of that release, never with unit tests alone:
   collect, `feed sync --for`, `resolve`. `rule_coverage.state` must be `covered`, and the
   vulnerable packages must match what the vendor's own tool reports (`apt list
   --upgradable` with the security pocket, `dnf updateinfo list --security`, `apk
   version`).
4. Update the table above and its date.

## Ending a release

When a vendor ends a release but still publishes its data, it stays in the matrix until the
data goes away, and the lifecycle check reports the end of life. When the data is gone,
move it to `noVendorData` (or out of `vendorPublishedReleases`) so the scan says so.
