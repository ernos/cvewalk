# cvehunt

Host-level CVE scanner for Ubuntu/Debian that reports **which executable file is affected**,
the CVE id, the distro fix status, and references — using backport-aware Ubuntu data instead
of naive upstream-version matching.

> **Design, hurdles and roadmap:** [`DESIGN.md`](DESIGN.md)
> **Research:** [`research/data-sources.md`](research/data-sources.md),
> [`research/tooling-and-binary-id.md`](research/tooling-and-binary-id.md)
> **Example output:** [`example-scan.txt`](example-scan.txt)

## Contents

- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Complete argument reference](#complete-argument-reference)
- [Exit codes](#exit-codes)
- [How a scan works](#how-a-scan-works)
- [Console output](#console-output)
- [JSON report format](#json-report-format)
- [Files, caches and disk usage](#files-caches-and-disk-usage)
- [Network access, privacy and offline use](#network-access-privacy-and-offline-use)
- [Common workflows](#common-workflows)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Data licensing and code license](#data-licensing-and-code-license)

## Why this exists

On a fully-updated Ubuntu 26.04 host, matching *upstream* versions against NVD gives
**38 CVEs for curl 8.18.0** and **46 for openssl 3.5.5**. The distro-aware answer for the
installed revisions is **0** and **5**. Ubuntu backports fixes into the package revision
(`-0ubuntu0.x`) without changing the upstream version. `cvehunt` matches on the dpkg source
package + full Ubuntu version, so it does not report those phantom CVEs, and it attributes
each finding to the executable files that belong to the affected binary packages.

Validation on this project's host (Ubuntu 26.04.1 LTS, kernel 7.0.0-38): 713 packages,
1,222 executable ELF files, 438 source-package queries, **519 CVEs across 87 source
packages, 57 with a fix already available in apt, 1 in CISA KEV**, in roughly 20–35 s on a
warm cache (network-dependent). Every fixable finding was cross-checked against
`apt list --upgradable` (zero discrepancies).

## Requirements

| Requirement | Notes |
|---|---|
| **OS** | Linux with `dpkg` (Ubuntu or Debian). Other distributions with dpkg can work with `--ecosystem`, but are not tested. |
| **Python** | 3.10+ (developed on 3.14). Standard library only — no `pip install` needed. |
| **dpkg tools** | `dpkg-query` on `PATH`; readable `/var/lib/dpkg/info/*.list` and `/var/lib/dpkg/status`. |
| **Privileges** | **Root is not required** for a normal host scan; dpkg metadata is world-readable on stock Ubuntu. Files under directories your user cannot read are skipped. |
| **Network** | `https://api.osv.dev` is required. EPSS (`api.first.org`) and KEV (`www.cisa.gov`) are optional and degrade gracefully. |
| **Disk** | The OSV record cache can grow large (see [caches](#files-caches-and-disk-usage)); point `--cache-dir` at a suitable location. |

## Installation

No packaging, no virtualenv required:

```bash
git clone <this-repo> security-auditor     # or copy the directory
cd security-auditor
python3 scan.py --help
```

Optionally make the entry point executable:

```bash
chmod +x scan.py
./scan.py --help
```

## Quick start

```bash
cd /home/ubuntu/security-auditor

python3 scan.py                          # full scan -> console + report.json
python3 scan.py --limit 10               # shorter console table
python3 scan.py --json out/report.json   # custom JSON location (create out/ first)
python3 scan.py --fail-on kev            # CI-style: exit 1 if a KEV CVE is found
python3 scan.py --no-epss --no-kev       # skip optional enrichment
python3 -m unittest discover -s tests    # run the test suite
```

The console report is printed to stdout; progress lines and errors go to stderr. On a
successful scan a JSON report is written (default `report.json` in the current working
directory).

## Usage

```
usage: scan.py [-h] [--json JSON] [--cache-dir CACHE_DIR]
               [--ecosystem ECOSYSTEM] [--extra-path EXTRA_PATH]
               [--limit LIMIT] [--no-epss] [--no-kev] [--refresh]
               [--fail-on {none,kev,critical,any}] [--quiet]
```

Flags can be combined in any order, e.g.:

```bash
python3 scan.py --json "$ARTIFACTS/report.json" --limit 50 --fail-on critical --quiet
```

## Complete argument reference

### `--json PATH`

- **Default:** `report.json` (relative to the current working directory).
- **Type:** file path.
- **Description:** where to write the full machine-readable report. The parent directory
  must already exist; the file is overwritten if present.
- **Example:** `python3 scan.py --json /var/log/cvehunt/2026-11-13.json`

### `--cache-dir DIR`

- **Default:** `<directory containing scan.py>/.cache/cvehunt` (absolute path).
- **Type:** directory path; created automatically if missing.
- **Description:** location of the OSV record cache, the KEV catalog and the EPSS score cache.
  Safe to share between runs; safe to delete at any time.
- **Example:** `python3 scan.py --cache-dir /var/cache/cvehunt`

### `--ecosystem STRING`

- **Default:** auto-detected from `/etc/os-release`:
  - Ubuntu LTS → `Ubuntu:<VERSION_ID>:LTS` (e.g. `Ubuntu:26.04:LTS`)
  - Ubuntu interim → `Ubuntu:<VERSION_ID>` (e.g. `Ubuntu:25.10`)
  - Debian → `Debian:<major>` (e.g. `Debian:12`)
- **Type:** OSV ecosystem string.
- **Description:** overrides the detected distro ecosystem. Useful in chroots/containers
  whose `/etc/os-release` does not match the dpkg database being scanned. An invalid or
  wrong ecosystem typically yields zero matches rather than an error.
- **Examples:** `--ecosystem Ubuntu:24.04:LTS`, `--ecosystem Ubuntu:25.10`,
  `--ecosystem Debian:12`
- **Caveat:** Ubuntu Pro/ESM fixes are published in a separate namespace
  (`Ubuntu:Pro:<release>:LTS`) which is not merged automatically; see
  [Known limitations](#known-limitations).

### `--extra-path DIR`

- **Default:** none.
- **Type:** directory path; **repeatable**.
- **Description:** additional roots to walk for executables, on top of the default roots
  (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/games`, `/usr/local/bin`,
  `/usr/local/sbin`, `/usr/local/games`, `/snap/bin`, `/opt`, plus dpkg-owned files under
  `/usr/lib`, `/lib`, `/usr/lib64`, `/lib64`, `/usr/libexec`).
  Each extra root is walked recursively two levels deep (four levels for the exact paths
  `/opt`, `/usr/local`, `/snap`). Non-existent paths are silently skipped. Files owned by
  dpkg are still attributed via the package database; unowned ELF files are reported with
  heuristic version hints.
- **Example:** `python3 scan.py --extra-path /srv/app/bin --extra-path /opt/vendor`

### `--limit N`

- **Default:** `25`.
- **Type:** non-negative integer.
- **Description:** number of rows shown in the console findings table. It does **not** affect
  the JSON report, which always contains every finding. The "TOP FINDINGS WITH REFERENCES"
  block shows at most 3 findings (`min(3, N)`).
- **Examples:** `--limit 10`, `--limit 0` (table body empty, JSON unchanged)

### `--no-epss`

- **Default:** EPSS enrichment enabled.
- **Description:** skip FIRST EPSS exploit-likelihood scores. Findings then have `epss: null`,
  ranking falls back to fix status + CVSS, and the `data.epss` block reports
  `"error": "disabled"`. EPSS requires network access to `api.first.org`.

### `--no-kev`

- **Default:** CISA KEV enrichment enabled.
- **Description:** skip the CISA Known Exploited Vulnerabilities catalog. Findings then have
  `kev: null`, no finding can have risk `EXPLOITED`, and `--fail-on kev` can never trigger.
  KEV requires network access to `www.cisa.gov`.

### `--refresh`

- **Default:** off (use caches within their TTL).
- **Description:** ignore the on-disk cache TTLs and refetch:
  - OSV vulnerability records (normal TTL: 12 hours),
  - the CISA KEV catalog (normal TTL: 24 hours).
- **Not affected:** the OSV **package queries themselves are always live** (never cached);
  the EPSS score cache is refreshed only on its 24-hour TTL, because `--refresh` is not
  plumbed into the EPSS fetcher in this version.

### `--fail-on {none,kev,critical,any}`

- **Default:** `none`.
- **Description:** turns findings into a non-zero exit code (useful in CI):
  - `none` — always exit `0` on a successful scan, even with findings.
  - `any` — exit `1` if there is at least one finding.
  - `kev` — exit `1` if any finding appears in CISA KEV (requires KEV enabled).
  - `critical` — exit `1` if any finding has risk `CRITICAL` or `EXPLOITED`.
- **Example:** `python3 scan.py --quiet --fail-on critical --json "$ARTIFACTS/report.json"`

### `--quiet`

- **Default:** off.
- **Description:** suppress the `[1/5] … [5/5]` progress lines and enrichment counters on
  stderr. Warnings/errors still go to stderr, the console report still goes to stdout, and
  the final `JSON report written to …` line is still printed.

### `-h`, `--help`

Print the generated usage/options help and exit `0`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; the `--fail-on` condition (if any) was not met. Findings may still exist. |
| `1` | Scan completed and the `--fail-on` threshold was met (`any`, `kev`, or `critical`). |
| `2` | Scan could not run: unsupported distribution (no `--ecosystem` given), inventory failure (e.g. `dpkg-query` missing/unreadable dpkg DB), or an OSV query/record failure after retries. |

Notes:

- Unexpected exceptions outside these paths (for example an unwritable `--json` path whose
  parent directory does not exist) surface as a Python traceback and exit code `1`; they are
  not part of the designed contract. Check the message; the report is written only after the
  console report is printed.
- With `--fail-on none` a successful scan exit code says nothing about whether CVEs were
  found — inspect `summary.cves` in the JSON or the console header.

## How a scan works

1. **Inventory** — reads installed packages with a single `dpkg-query` call, builds an
   in-memory `path → binary package` index from `/var/lib/dpkg/info/*.list`, then walks the
   default roots plus any `--extra-path` roots. ELF files are classified as executables or
   libraries; dpkg ownership, symlinks and merged-`/usr` paths are resolved via realpaths.
2. **Identity** — every dpkg-owned file is attributed to a binary package and its source
   package/version. Files owned by no package are reported separately with non-executing
   version hints (the scanner never executes scanned binaries).
3. **Distro-aware matching** — queries OSV for each unique `(source package, source version)`
   in the selected ecosystem. OSV's Ubuntu/Debian records encode backported `fixed` Debian
   versions, so `installed < fixed` is the fix signal. OSV's batch endpoint is used for speed,
   with an automatic per-package fallback to the exact single-query endpoint when the batch
   endpoint paginates (a real OSV behaviour for very large packages such as `linux`).
4. **Attribution** — maps the affected binary packages (`ecosystem_specific.binaries[]` from
   OSV) to executable files and shared libraries on disk. Kernel CVEs are reported against
   the kernel image with a reboot note, not against userspace tools such as `/usr/bin/perf`.
5. **Enrichment** — CVE ids are derived from OSV ids/aliases; fix status is computed with
   Debian version comparison; CVSS v3 base scores are computed from vectors; EPSS and CISA
   KEV are fetched when enabled.
6. **Report** — console table + full JSON. Findings are ordered: KEV first, then fix
   available, then EPSS, then CVSS, then CVE id.

## Console output

The console report has these sections:

1. **Header** — tool version, hostname, distro; ecosystem; inventory counts; data sources and
   scan duration.
2. **FINDINGS line** — unique CVE count, source-package count, KEV count, actionable count,
   fixable count, no-fix count, and a risk breakdown.
3. **Findings table** — up to `--limit` rows with columns:
   `RISK`, `CVE`, `CVSS`, `EPSS`, `KEV`, `PACKAGE (installed)`, `FIX`, `EXECUTABLE`.
   `RISK` values: `EXPLOITED` (KEV), `CRITICAL` (CVSS ≥ 9.0 or Ubuntu priority critical),
   `HIGH` (CVSS ≥ 7.0 or priority high), `MEDIUM` (CVSS ≥ 4.0 or priority medium), or `LOW`.
   Kernel findings show `kernel image (reboot required)` in the executable column.
4. **TOP FINDINGS WITH REFERENCES** — the first up to 3 findings with up to 6 reference URLs
   each (the JSON contains all findings and all references).
5. **UNOWNED ELF EXECUTABLES** — only if any belong to no package; up to 10 shown with hints.
6. **WARNINGS** — e.g. running kernel not matching an installed `linux-image`, EPSS/KEV
   unavailable, no-fix findings that may be Ubuntu `deferred`/`ignored` CVEs.

Captured example: [`example-scan.txt`](example-scan.txt).

## JSON report format

Top-level structure:

```jsonc
{
  "tool":       { "name": "cvehunt", "version": "0.1.0" },
  "scan":       { "started", "duration_s", "hostname", "user", "args": { /* parsed CLI */ } },
  "system":     { "distro": { "id", "version", "pretty" }, "ecosystem", "kernel": { ... } },
  "inventory":  { "packages", "source_packages", "files", "executables", "elf_executables", "unowned_elf" },
  "data":       { "osv": { ... }, "epss": { ... }, "kev": { ... } },
  "summary":    { "findings", "cves", "packages_with_findings", "kev", "actionable", "fixable", "unfixed", "by_risk" },
  "findings":   [ /* see below */ ],
  "unowned":    [ { "path", "hints": [ ... ] } ],   // capped at 50 entries
  "warnings":   [ "..." ],
  "limitations":[ "..." ]                            // static caveat list
}
```

`summary.findings` counts finding rows; `summary.cves` counts unique CVE ids (one CVE can
affect more than one source package, so rows ≥ unique CVEs). `inventory.executables` counts
all executable files (ELF and scripts); `inventory.elf_executables` counts ELF only.

### `data` block

| Field | Meaning |
|---|---|
| `data.osv.ok` | `true` when OSV queries completed. |
| `data.osv.ecosystem` | Ecosystem actually used (auto-detected or `--ecosystem`). |
| `data.osv.queries` | Number of unique source-package/version queries. |
| `data.osv.matchers` | Number of vulnerable package/CVE pairs returned. |
| `data.osv.vuln_records` | Number of unique OSV records hydrated. |
| `data.osv.source`, `data.osv.note` | Human-readable provenance/matching note. |
| `data.epss` | `{ ok, hits, error }`; `error` is `"disabled"` with `--no-epss`, else failure text. |
| `data.kev` | `{ ok, entries, error }`; `error` is `"disabled"` with `--no-kev`, else failure text. |

### Finding object

Each element of `findings` has:

| Field | Type | Meaning |
|---|---|---|
| `cve` | string | Primary canonical CVE id (or OSV id if none derivable). |
| `cve_ids` | string[] | All CVE ids for the record (aliases + derived Ubuntu/Debian CVE id). |
| `osv_id` | string | OSV record id, e.g. `UBUNTU-CVE-2026-94300`. |
| `summary` | string | OSV summary/description (may be empty). |
| `package` | string[] | Affected installed dpkg binary package names (may include `:arch`). |
| `source_package` | string | dpkg source package queried. |
| `installed_version` | string | Source package version used for matching (full dpkg version, epoch included). |
| `fixed_version` | string \| null | Smallest fixed version newer than installed, or `null`. |
| `fix_status` | `"fixed"` \| `"unfixed"` \| `"unknown"` | `fixed` = a newer fixed version exists; `unfixed` = no `fixed` event published; `unknown` = no matching affected entry (should be rare). |
| `remediation` | string | Suggested action (e.g. `upgrade bind9 to 1:9.20.24-1ubuntu0.5 or later`). |
| `asset` | `"package"` \| `"kernel"` | Kernel findings use `asset: "kernel"`, empty `executables`/`libraries`, and include a `kernel` object. |
| `ubuntu_priority` | string \| null | Ubuntu tracker priority label from OSV severity (`low`…`critical`). |
| `cvss_vector` | string \| null | CVSS v3 vector when the record carries one. |
| `cvss_score` | number \| null | Base score computed from the vector (not provided by OSV directly). |
| `epss` | number \| null | FIRST EPSS probability, 0–1. |
| `epss_percentile` | number \| null | EPSS percentile, 0–1. |
| `kev` | object \| null | CISA KEV entry (`dateAdded`, `knownRansomwareCampaignUse`, etc.) or `null`. |
| `availability` | string \| null | OSV availability hint (e.g. `"No subscription required"`, Ubuntu Pro strings). |
| `executables` | string[] | Affected executable paths (capped at 20). |
| `libraries` | string[] | Affected shared-library paths (capped at 20). |
| `references` | object[] | `{ type, url }`, including the OSV record, `ubuntu.com/security/CVE-…`, USN advisories, cve.org, upstream commits. |
| `published`, `modified` | string \| null | OSV timestamps. |
| `risk` | string | `EXPLOITED` \| `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` (see risk mapping above). |
| `actionable` | boolean | `true` when a fix version exists or the CVE is KEV-listed. |
| `kernel` | object | Present only when `asset == "kernel"`: `{ running, installed_images[], running_image_installed }`. |

Abridged real example:

```json
{
  "cve": "CVE-2026-94300",
  "cve_ids": ["CVE-2026-94300"],
  "osv_id": "UBUNTU-CVE-2026-94300",
  "package": ["bind9-dnsutils", "bind9-host", "bind9-libs:amd64"],
  "source_package": "bind9",
  "installed_version": "1:9.20.24-1ubuntu0.4",
  "fixed_version": "1:9.20.24-1ubuntu0.5",
  "fix_status": "fixed",
  "remediation": "upgrade bind9 to 1:9.20.24-1ubuntu0.5 or later",
  "asset": "package",
  "ubuntu_priority": "medium",
  "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_score": 8.1,
  "epss": 0.0095,
  "epss_percentile": 0.6182,
  "kev": null,
  "availability": "No subscription required",
  "executables": ["/usr/bin/delv", "/usr/bin/dig", "/usr/bin/host", "/usr/bin/nslookup"],
  "libraries": ["/usr/lib/x86_64-linux-gnu/libdns-9.20.24-1ubuntu0.4-Ubuntu.so"],
  "references": [
    {"type": "OSV", "url": "https://osv.dev/vulnerability/UBUNTU-CVE-2026-94300"},
    {"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2026-94300"}
  ],
  "risk": "HIGH",
  "actionable": true
}
```

## Files, caches and disk usage

| Path | Purpose | TTL / notes |
|---|---|---|
| `report.json` (or `--json PATH`) | Generated report | Overwritten each run; not source. |
| `<cache-dir>/vuln-<sha256>.json` | One cached OSV vulnerability record per id | 12 h; **large** — kernel records embed every shipped version and variant. |
| `<cache-dir>/kev.json` | CISA KEV catalog (~1,800 entries) | 24 h; `--refresh` bypasses. |
| `<cache-dir>/epss.json` | CVE → EPSS score map for the CVEs seen | 24 h; `--refresh` does not bypass. |

The default cache is `<script-dir>/.cache/cvehunt/`. On this project's validation host, a
519-record scan left **~540 MB** of uncompressed OSV JSON, mostly large kernel records. That
is runtime data, not a deliverable: prune it freely, point `--cache-dir` elsewhere, or ship
the compressed Canonical OSV tarball if you build offline support (see `DESIGN.md`).
Caches are safe to delete; deleting them only costs refetch time.

## Network access, privacy and offline use

| Endpoint | Used for | Required? |
|---|---|---|
| `https://api.osv.dev` | package queries + vulnerability records | **Yes** |
| `https://api.first.org/data/v1/epss` | EPSS scores | Optional (`--no-epss`) |
| `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | KEV catalog | Optional (`--no-kev`) |

- Requests use `urllib`, so standard proxy environment variables (`http_proxy`,
  `https_proxy`, `no_proxy`) are honoured.
- **Privacy:** OSV queries disclose installed **source package names and versions** (plus the
  distro ecosystem) to a third party; EPSS lookups disclose CVE ids. The report also records
  hostname and user. Treat reports as potentially sensitive.
- **Offline:** this version needs OSV at scan time. `--no-epss --no-kev` reduces but does not
  remove network requirements. An offline bundle (Canonical OSV tarball + OVAL + EPSS/KEV) is
  roadmap item M3 in `DESIGN.md`.

## Common workflows

**Routine host audit**

```bash
python3 scan.py
less report.json   # or jq '.summary, .findings[:5]' report.json
```

**CI / periodic job with a gate**

```bash
mkdir -p artifacts
python3 scan.py --quiet \
  --json artifacts/cvehunt-report.json \
  --fail-on critical
case $? in
  0) echo "no critical findings";;
  1) echo "critical findings present"; exit 1;;
  2) echo "scan failed to run"; exit 2;;
esac
```

**Fast run without optional enrichment**

```bash
python3 scan.py --no-epss --no-kev --limit 50
```

**Scan binaries outside package-managed paths**

```bash
python3 scan.py --extra-path /srv/app/bin --extra-path /opt/vendor
```

**Explicit ecosystem override (chroot/container/odd `/etc/os-release`)**

```bash
python3 scan.py --ecosystem Ubuntu:24.04:LTS
```

## Security model

- The scanner is **read-only** with respect to the scanned system: it reads dpkg metadata and
  file headers/bytes. It **never executes** scanned binaries (no `--version`, no `ldd`), so it
  cannot be turned into a loader by a malicious or replaced binary.
- A normal scan does not require root. If you run it as root, the report is still just JSON;
  but review it before sharing because it includes hostname, user and installed package
  versions.
- The report is only as trustworthy as the data sources and the local dpkg database; treat
  findings as triage input, not proof of exploitability (EPSS/KEV are likelihood signals).
- Reports can be stale relative to the Ubuntu tracker (OSV ingest lag) and incomplete for
  third-party/static software; see the limitations below.

## Known limitations

- **No Ubuntu tracker-status layer.** OSV does not expose per-release status, so CVEs
  Canonical marked `deferred`/`ignored` appear as "no fix" rather than "will not fix".
  The report flags this in `warnings`; adding `ubuntu-cve-tracker`/OVAL statuses is milestone
  M1 in `DESIGN.md`.
- **Ubuntu Pro/ESM fixes** live in a separate OSV namespace (`Ubuntu:Pro:<release>`) and are
  not merged yet; ESM-only fixes may appear unfixed on a non-entitled host.
- **Unowned/static binaries** are reported with heuristic version hints only; no CVE claim is
  made for them (by design). The `.note.package`/build-id/Go/Rust ladder is roadmap M2.
- **Third-party apt repositories** are not origin-checked; their packages may be compared
  against Ubuntu version ranges.
- **No integrity check** of package files (`*.md5sums` verification) and no hardening audit
  yet.
- **No SBOM/SARIF/VEX output** yet (JSON only); `--json` is the machine interface.
- **Live dpkg database only** — scanning a mounted rootfs or container image is not
  implemented yet.
- **Kernel findings** identify the kernel image and require a reboot; no Livepatch awareness.
- **Cache size** can reach hundreds of MB (large kernel records); see the cache section.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `unsupported distribution: …` (exit 2) | Auto-detection only handles Ubuntu/Debian `/etc/os-release`. Pass `--ecosystem Ubuntu:24.04:LTS` (or appropriate) if the dpkg database is Ubuntu/Debian. |
| `inventory failed: … dpkg-query …` (exit 2) | Not a dpkg-based system, or `dpkg-query` not on `PATH`. |
| `OSV query failed: …` (exit 2) | Network/DNS/proxy problem or OSV outage; the client retries with backoff. Test with `curl -sI https://api.osv.dev`. |
| Traceback writing the JSON report | The `--json` parent directory does not exist or is not writable; create it first. |
| `EPSS unavailable` / `CISA KEV unavailable` (warning) | Optional endpoints unreachable; the scan still finishes and the `data.*.error` fields explain. |
| Cache permission errors | Point `--cache-dir` at a writable directory. |
| `.cache` is hundreds of MB | Expected with large OSV records; delete it or use a dedicated `--cache-dir`. |
| Many "no fix" findings, including ancient CVEs | Expected: OSV cannot distinguish Ubuntu `deferred`/`ignored` from "fix pending". Check `warnings` and verify against ubuntu-cve-tracker/OVAL before acting. |
| `--fail-on kev` never fails | KEV was disabled with `--no-kev`, or no finding is KEV-listed. |
| No findings at all | Wrong `--ecosystem`, packages from third-party repos not in Ubuntu data, or OSV data temporarily unavailable; check the `data` block and `inventory`. |

## Development

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

The suite covers Debian version comparison against `dpkg --compare-versions` (skipped if
`dpkg` is absent), package-variant isolation in fix detection, CVSS v3 score computation, and
CVE-id derivation from OSV records. Add tests next to the logic they cover in
`tests/test_units.py`.

Architecture and extension points are documented in [`DESIGN.md`](DESIGN.md). In short:
`inventory.py` (provenance), `osv.py` (data access), `enrich.py` (fix/CVSS/EPSS/KEV),
`analyze.py` (file↔CVE correlation), `report.py` (rendering).

## Repository layout

```
scan.py                  CLI entry point
cvehunt/
  __init__.py            package metadata
  debver.py              Debian/Ubuntu version comparison (dpkg semantics)
  inventory.py           package/file inventory + non-executing binary fingerprinting
  osv.py                 OSV client (batch + single-query fallback, on-disk cache)
  enrich.py              CVE ids, fix status, CVSS, EPSS, KEV, risk ordering
  analyze.py             file<->CVE correlation, kernel asset handling
  report.py              console + JSON rendering
tests/test_units.py      comparator vs dpkg, fix-status isolation, CVSS, CVE ids
DESIGN.md                architecture, hurdles, decisions, roadmap
README.md                this file
example-scan.txt         captured console output of a real scan
report.json              generated report from the last local run (git-ignored)
research/                supporting research (data sources, tooling/binary identification)
.gitignore               generated/runtime files excluded from version control
```

## Data licensing and code license

- **Ubuntu OSV data** (used via `api.osv.dev`) is **CC-BY-SA-4.0**; attribution and
  share-alike obligations apply if you redistribute or serve the data.
- **Ubuntu OVAL** data has conflicting license statements (CC-BY-SA-4.0 in `LICENSE`, GPLv3 in
  the XML terms) — legal review is needed before redistribution.
- **`ubuntu-cve-tracker`** has no LICENSE file; treat it as a reference/verification source.
- **EPSS** is subject to the FIRST EPSS Usage Agreement (attribution requested).
- **CISA KEV** is a US Government work (public domain).
- The **scanner code in this repository has no declared license yet**; add a `LICENSE` before
  redistributing or accepting contributions.
