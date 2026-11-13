# Designing an Ubuntu CVE scanner with per-executable findings

Status: design + working prototype (`cvewalk`). Validated against a live Ubuntu 26.04.1 LTS
host on 2026-11-13. Research inputs: [`research/data-sources.md`](research/data-sources.md),
[`research/tooling-and-binary-id.md`](research/tooling-and-binary-id.md).

---

## 1. Executive summary

The goal — "for every executable on my system, tell me its version, whether that exact
version is vulnerable, and give me CVE IDs with references" — is achievable, but **the hard
part is not file walking, it is defining what "that version" means**. Ubuntu patches most
CVEs without changing the upstream version; the fix lives in the Debian revision
(`2.4.41-4ubuntu0.1`). Any scanner that compares file versions to upstream/NVD data will
produce a flood of false positives on an up-to-date machine.

**Recommended shape:**

1. **Inventory with provenance, not guesswork.** Attribute every executable to its dpkg
   binary package → source package → installed version. This is authoritative and free
   (`/var/lib/dpkg/info/*.list` + `dpkg-query`). Only fall back to binary introspection for
   files no package owns.
2. **Match against distro-aware data.** Query the **Ubuntu OSV ecosystem** (`Ubuntu:26.04:LTS`)
   by *source package + full dpkg version*; compare installed vs the `fixed` Debian version.
   This is the only layer that is backport-correct. NVD/CPE is a last-resort source for
   unpackaged third-party binaries, never the primary matcher.
3. **Report per file, with evidence and confidence.** The package finding is the truth; the
   file list is the attribution. For unowned/static binaries use a confidence ladder
   (`.note.package` → build-id → Go/Rust metadata → version strings → `unknown`), never a
   bare CVE claim from a regex.
4. **Prioritize, don't just list.** KEV → available fix → EPSS → CVSS, plus exposure context
   (setuid, listening service, systemd unit). A scanner whose top finding is a 2013
   "deferred" kernel CVE gets ignored.
5. **Do not execute scanned binaries** (`--version` is arbitrary code execution as root), and
   do not rely on NVD CPE, which NIST stopped universally enriching in April 2026.

**Build vs buy:** buy inventory (Syft or OSV-Scalibr as a library), buy the vulnerability
data (Ubuntu OSV/OVAL/USN), buy version comparison (`python-debian` / `go-deb-version`).
Build the two things nobody ships: **file→CVE attribution** and the **Ubuntu-aware,
status-aware decision layer** (including "will not fix" vs "fix pending" vs "fixed").

A working prototype of layers 1–4 is included and was validated on this host: 713 packages,
1,222 executable ELF files, 438 source-package queries, **519 CVEs, 57 with a fix already
available in apt, 1 in CISA KEV**, in ~29 s. Detailed results in §9.

---

## 2. The core insight, quantified

### 2.1 Backports produce false positives, and they are not hypothetical

On this fully-updated host (Ubuntu 26.04.1, kernel 7.0.0-38), naive upstream matching
against NVD CPE for the *same upstream versions* gives:

| Package | Installed Ubuntu version | Naive NVD/CPE matches for upstream version | Distro-aware matches for installed revision |
|---|---|---|---|
| curl | `8.18.0-1ubuntu2.8` | **38** (`cpe:2.3:a:haxx:curl:8.18.0`) | **0** |
| openssl | `3.5.5-1ubuntu3.7` | **46** (`cpe:2.3:a:openssl:openssl:3.5.5`) | **5** (all no-fix) |

Sampling the NVD-only hits confirms they are patched by Ubuntu already:

- `CVE-2026-1965` → tracker: `resolute_curl: released (8.18.0-1ubuntu2)` — fixed in a revision
  *older* than the installed `8.18.0-1ubuntu2.8`.
- `CVE-2026-2673`, `CVE-2026-28387` → `resolute_openssl: released (3.5.5-1ubuntu3)`, older than
  installed `3.5.5-1ubuntu3.7`.

So a version-only scanner would have reported ~38 phantom CVEs for curl and ~46 for openssl
on a perfectly patched system. This is the number-one hurdle, and it dictates the data model.

### 2.2 Distro data is authoritative for dpkg-managed software

Ubuntu OSV records encode exactly what a scanner needs:

- ecosystem per release: `Ubuntu:26.04:LTS` (LTS), `Ubuntu:25.10` (interim), and a separate
  `Ubuntu:Pro:<release>:LTS` namespace for ESM/Pro-only pockets (query both and merge);
- affected ranges as Debian versions: `{"introduced": "0"}, {"fixed": "8.18.0-1ubuntu2.1"}` —
  the `fixed` value is the backported Ubuntu package version;
- `ecosystem_specific.binaries[]` = official source→binary package mapping
  (`php8.3` → `php8.3-cli`, `libphp8.3-embed`), plus `availability` flags for Pro-gated fixes;
- references to `ubuntu.com/security/CVE-…`, USN advisories (`USN-…`), cve.org, and upstream
  commits.

Absence of a `fixed` event means "no fixed version published" — it must **not** be inverted
into "not vulnerable."

### 2.3 The gap in existing tooling is narrow and real

Every distro-feed scanner (Trivy, Grype, Vuls, Fleet, oscap + Ubuntu OVAL, osv-scanner) stops
at `(package, version)`. None reports "CVE-2026-X affects `/usr/bin/foo`" for OS packages,
even though the mapping exists in dpkg's file lists. cve-bin-tool does per-file attribution
via string signatures, but explicitly cannot see distro backports. OSV-Scalibr 2026 has the
closest prior art: an *unknown binaries* extractor plus a dpkg annotator that removes
package-owned files — worth studying before building (`ffa/unknownbinariesextr`,
`ffa/unknownbinariesanno`, `vex/no-executable/dpkg`).

---

## 3. Recommended architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. INVENTORY (privilege-light, read-only)                            │
│    dpkg-query → binary pkg, version, arch, source pkg, source version │
│    /var/lib/dpkg/info/*.list → reverse index: path → binary package  │
│    walk bin/lib/opt/snap roots → ELF + script inventory, unowned set │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  (binary pkg → source pkg → dpkg version)
┌───────────────────────────────▼──────────────────────────────────────┐
│ 2. IDENTITY / PROVENANCE                                             │
│    exact-package (dpkg-owned)                                        │
│    exact-build   (.note.package note, build-id)                      │
│    embedded      (Go buildinfo, Rust .dep-v0, asar/deps.json)        │
│    signature     (product-anchored OpenSSL/zlib/curl banners)        │
│    unknown       (report path + sha256; no CVE claim)                │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  (source package, ecosystem, version)
┌───────────────────────────────▼──────────────────────────────────────┐
│ 3. DISTRO-AWARE MATCHING                                             │
│    OSV /v1/query[<batch>] per (source, version)                      │
│    filter affected[] by ecosystem AND package name                   │
│    fix status = min(fixed) > installed (dpkg comparison)             │
│    no fixed event ⇒ "no fix published" (not "safe")                  │
│    Pro namespace merge when ESM entitled                             │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  (CVE candidates + fixed versions)
┌───────────────────────────────▼──────────────────────────────────────┐
│ 4. FILE ATTRIBUTION + CONFIDENCE                                     │
│    affected binary packages → their executable paths                 │
│    kernel sources reported as kernel image (reboot required)         │
│    modified binaries flagged via *.md5sums mismatch                  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│ 5. PRIORITIZATION + EVIDENCE                                         │
│    KEV → fix available → EPSS → CVSS; exposure: setuid/socket/unit   │
│    references: Ubuntu CVE page, USN, upstream advisory, cve.org      │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│ 6. OUTPUT                                                            │
│    JSON keyed by file path · SARIF for CI · CycloneDX/SPDX for SBOM  │
│    OpenVEX for triage · human report with fix commands               │
└──────────────────────────────────────────────────────────────────────┘
```

### Intended output (what "report the CVE with references" should look like)

```json
{
  "cve": "CVE-2026-111497",
  "source_package": "brotli",
  "installed_version": "1.2.0-3build1",
  "fixed_version": "1.2.0-3ubuntu0.1",
  "fix_status": "fixed",
  "asset": "package",
  "executables": ["/usr/bin/brotli"],
  "libraries": ["/usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1.2.0"],
  "kev": {"dateAdded": "2026-10-27", "knownRansomwareCampaignUse": "Known"},
  "epss": 0.826, "cvss_score": 9.8,
  "references": [
    {"type": "OSV", "url": "https://osv.dev/vulnerability/UBUNTU-CVE-2026-111497"},
    {"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2026-111497"},
    {"type": "ADVISORY", "url": "https://ubuntu.com/security/notices/USN-…"},
    {"type": "REPORT", "url": "https://www.cve.org/CVERecord?id=CVE-2026-111497"}
  ]
}
```

---

## 4. Matching semantics that must be right

These are the details that separate a useful scanner from a generator of noise.

1. **Query source packages, not binaries.** Advisory data is keyed by source package.
   `openssl` is the source of `openssl`, `libssl3t64`, `openssl-provider-legacy`. Use
   `${source:Package}` / `${source:Version}` from dpkg; querying `libssl3t64` returns nothing.
   (OSV has `POST /v1experimental/ubuntu/binary-to-source` as a fallback for the reverse
   mapping; local dpkg data is faster and complete.)
2. **Use the full dpkg version**, including epoch and revision. OSV performs dpkg ordering
   server-side for `Ubuntu:*` queries; validate any local comparator against
   `dpkg --compare-versions` (Policy 5.6.12: epochs, `~` sorts before empty, `+esmN`,
   `~bpo`, `+really`).
3. **Filter `affected[]` by ecosystem and by package name.** A kernel CVE record contains one
   entry per variant (`linux`, `linux-aws`, `linux-gcp`, `linux-oem-7.0`, …), each with its own
   fixed version. Filtering only on ecosystem mixes them up: e.g. `linux-aws`'s
   `7.0.0-1016.17` compares numerically higher than the generic kernel's `7.0.0-42.42` and
   makes the generic kernel look fixed. (The prototype hit exactly this bug; see Appendix B.)
4. **No `fixed` event ≠ not vulnerable.** It means "no fixed package published" — report it as
   such, and tag Pro-gated fixes via `ecosystem_specific.availability`.
5. **Report the tracker's willingness-to-fix separately if you can.** Ubuntu's tracker status
   vocabulary is `released | pending | needed | in-progress | deferred | ignored |
   not-affected | DNE`. `deferred`/`ignored` mean *will not fix* (informational), while
   `needed`/`pending` mean a fix is coming. OSV does **not** expose this status, so OSV alone
   cannot distinguish them (validated: sampled no-fix findings were `needs-triage`,
   `deferred`, and `ignored`). Ingest `ubuntu-cve-tracker` or OVAL to separate
   actionable from won't-fix.
6. **Kernel CVEs belong to the kernel image, not to userspace tools built from the same
   source** (`/usr/bin/perf`, `bpftool`, `acpidbg`). Report them as a kernel asset with
   "upgrade linux-image-* and reboot"; also flag installed-vs-running kernel mismatch.
7. **Pro/ESM changes "fixed" semantics.** Query `Ubuntu:<release>[:LTS]` and
   `Ubuntu:Pro:<release>:LTS`, merge, and carry `pro status` into the report; otherwise a
   non-entitled host shows ESM-only fixes as unfixed (or hides them).
8. **Provenance matters for third-party packages.** A package from a third-party apt repo can
   share a source name with Ubuntu's but use a different version scheme; querying Ubuntu
   ranges with it can produce both false positives and negatives. Record package origin
   (`apt-cache policy`, apt lists `Origin`/`Site`) and mark those findings lower-confidence.
9. **Deduplicate across ecosystems and aliases.** One CVE can appear as `UBUNTU-CVE-…`,
   `DEBIAN-CVE-…`, a USN, and a GitHub advisory. Key findings on the canonical CVE id
   (`aliases` + the `UBUNTU-CVE-`/`DEBIAN-CVE-` prefix convention; also `upstream[]`/`related[]`).
10. **Confidence tiers, not a single truth claim.** A dpkg-owned file with md5sum verified is
    exact; a static binary with an OpenSSL banner is `needs_triage`; an obfuscated binary is
    `unknown`. Emit the tier and the evidence with every finding.

---

## 5. Hurdles (and how to handle each)

### Data & matching

| Hurdle | Why it bites | Mitigation |
|---|---|---|
| **Backported fixes** | Upstream version unchanged; NVD/CPE says vulnerable | Distro data + dpkg comparison; never upstream version for dpkg packages |
| **Deferred/ignored CVEs** | OSV marks them affected forever → ancient CVEs match every version (84/94 kernel findings on this host were no-fix, sampled as `deferred`/`ignored`/`needs-triage`) | Ingest tracker status/OVAL; separate "fix pending" / "will not fix" / "no fix"; don't rank them as actionable |
| **Source vs binary packages** | Querying binaries yields zero results | dpkg `Source:` mapping; OSV `binaries[]` for attribution |
| **Kernel variants** | Per-variant affected entries; cross-contamination of fixed versions | Filter `affected[]` by package name; treat kernel as an asset |
| **Pro/ESM namespaces** | Separate `Ubuntu:Pro:` records; ESM-only fixes | Query both, merge; report entitlement context |
| **Ingest lag** | Measured: USN → OSV.dev ~14.5 h in one sample; >3 h still missing in another | Canonical `osv-all.tar.xz` (~60 MB, daily 06:29Z) and `notices.json` (real-time) for same-day; cache with timestamps |
| **Third-party repos** | Same source name, different version scheme | Record origin; lower confidence; don't apply Ubuntu ranges blindly |
| **NVD/CPE is now partial** | NIST stopped universal enrichment 2026-04-15; CPE inconsistent, no backports | Use only for unowned/third-party binaries; mark low confidence; prefer CNA/GHSA/Vulnrichment |
| **Large-package API behavior** | OSV `/v1/querybatch` caps at 1000 ids with `next_page_token` for huge packages (`linux`) and returns *unfiltered* results — 1,000 vs the correct 94 | Detect pagination and fall back to `/v1/query` (prototype does this); or use `/v1/query` per package |

### Identity & coverage

| Hurdle | Why it bites | Mitigation |
|---|---|---|
| **Unowned/static binaries** (`/usr/local`, `/opt`, AppImage, vendored Go/Rust) | No package owns them; version invisible | Confidence ladder: `.note.package` → build-id → Go `debug/buildinfo` → Rust `.dep-v0` → product-anchored strings → `unknown_binary` + sha256 |
| **Embedded C libs** (OpenSSL/zlib/curl inside a Go binary) | Package data cannot see them; regexes false-positive on GCC/glibc banners | Product-anchored patterns + CONTAINS guard + evidence string; treat as tier 4 |
| **Scripts and language packages** | "Executable" includes shebang scripts, Python/Node wheels, venvs, pipx | Separate resolvers per ecosystem; don't force them into ELF logic |
| **snap / flatpak / containers** | Isolated trees, own version channels; mounts | Read squashfs/OSTree metadata offline; scan image layers with whiteout handling; never `docker run` |
| **Modified/replaced binaries** | Package says patched, file was replaced | `*.md5sums` verification (debsums-style); flag mismatch |
| **Symlinks, alternatives, merged-/usr, diversions** | Naive path→package lookups miss `/bin→/usr/bin`, `/etc/alternatives`, `dpkg-divert` | Resolve realpath, apply diversions/alternatives when building the index |
| **Zero-days / unpublished CVEs** | No feed can help | Set expectations; optionally add hardening/config checks |
| **Kernel livepatch** | Patched-in-memory but package version still "vulnerable" | Check `pro api u.pro.security.status.livepatch_cves.v1` and report patched CVEs |

### Engineering, security, legal

| Hurdle | Why it bites | Mitigation |
|---|---|---|
| **Don't execute `--version`** | Arbitrary code execution as root; side effects; hangs; runtime-linked libs answer for the wrong copy; libraries can't run | Static parsing only; document why |
| **Scale & performance** | 10⁴–10⁵ files; `dpkg -S` per file is a linear scan each time | One reverse index from `*.list`; only hash when verifying integrity; cache API data; avoid `strings` on everything |
| **Cache/storage growth** | Distro records are large: 519 matched records produced ~540 MB of uncompressed JSON on this host (kernel entries embed every shipped version and variant) | Bound/prune the cache; use the Canonical ~60 MB compressed OSV tarball for offline use; never bundle the raw cache |
| **Scanning as root** | Needed for some roots; report must remain trustworthy | Read-only operations; no execution; signed report; least privilege where possible |
| **Corrupt/tampered tooling** | A compromised scanner is worse than none | Verify its own integrity; sign reports; pin data versions |
| **Legal/licensing** | OSV Ubuntu data **CC-BY-SA 4.0** (share-alike if redistributed); OVAL license is self-contradictory (CC-BY-SA file vs GPLv3 XML terms); `ubuntu-cve-tracker` has no LICENSE; EPSS has its own usage agreement | Attribute; isolate data; legal review before redistributing bundled data |
| **Noise / trust** | A report with 500 CVEs is ignored | Prioritize, explain confidence, suppress with expiry (OpenVEX), diff vs last scan |
| **Freshness** | Same-day USNs may be absent from OSV; EOL releases freeze | Surface data timestamps + source per finding; refresh offline bundle daily |

---

## 6. Key design decisions

| Decision | Recommended choice | Why | Alternative |
|---|---|---|---|
| Primary data source | Ubuntu OSV (source packages, backport-aware) | Only source with per-release fixed dpkg versions + references | Ubuntu OVAL as independent fallback; USN JSON for same-day |
| Secondary | Ubuntu OVAL CVE + USN | Offline CVSS, patch-state cross-check | Trivy/Grype DBs (redistribute their work) |
| Upstream data | NVD only for unpackaged/static binaries | NVD backports-blind, now partially unenriched | cve-bin-tool checkers for strings tier |
| Identity | dpkg provenance first | Authoritative, cheap, complete for distro files | SBOM catalogers, build-id/note fingerprinting |
| Matching unit | source package + full dpkg version | Matches advisory data model | binary package (fails) |
| File attribution | package→files via in-memory index | One pass over `*.list` | `dpkg -S` per file (O(n²)), Syft relationships |
| Kernel | kernel asset, reboot advice | CVEs are in the image, not in `perf` | package-level only |
| Duplicate/no-fix | status-aware buckets | Avoids "deferred from 2013" top findings | naive unfixed list |
| Prioritization | KEV → fixable → EPSS → CVSS + exposure | Matches how admins act | CVSS alone |
| Output | JSON per file + SARIF + CycloneDX + VEX | Automation + audit + SBOM reuse | text only |
| Implementation language | Go for production; Python fine for prototype | Library ecosystem: `go-deb-version`, Syft/Scalibr as libs | Python + `python-debian` |

---

## 7. Improvements and roadmap (ordered by value)

1. **Status-aware triage (highest value).** Ingest `ubuntu-cve-tracker` (or OVAL CVE+USN) and
   split findings into `fixed` / `fix-pending` / `deferred-or-ignored` / `not-affected`. This
   removes the bulk of noise on an updated host and answers "is this actionable?"
2. **Exposure-aware prioritization.** Correlate findings with listening sockets
   (`/proc/net/tcp*`, `ss`), setuid/capabilities, systemd units, and running processes. Rank
   "remotely reachable + KEV" first; deprioritize command-line-only tools not run as a service.
3. **Fix guidance + lifecycle.** Emit exact remediation (`apt install --only-upgrade <pkg>`,
   target version), detect reboot-required (kernel, libc, systemd) via needrestart, and check
   Livepatch for kernel CVEs. Re-scan diff mode: "what's new since last run".
4. **SBOM + signed evidence.** CycloneDX/SPDX with `pkg:deb` purls per file; sign the report;
   store data-source versions and timestamps for audit.
5. **Tier the unowned/static path.** Implement `.note.package`, build-id matching against
   distro debuginfo, Go buildinfo + module scanning (OSV `Go` ecosystem), Rust `.dep-v0`;
   only then strings. Emit `unknown_binary` + sha256 instead of guessing.
6. **Integrity flags.** `*.md5sums` verification to detect replaced binaries (nobody ships
   this per file), plus ELF hardening summary (PIE/NX/RELRO/canary/fortify) as context.
7. **Container/snap/flatpak roots.** Same engine against a mounted rootfs or OCI layers;
   per-layer whiteouts; image digest in the report.
8. **Suppression & VEX.** OpenVEX import/export with expiry and justification, so teams can
   accept risk explicitly instead of ignoring the report.
9. **Cross-validation.** Differential-test against Trivy/Grype/osv-scanner on a golden corpus
   of known package versions; property-test the Debian comparator; track precision/recall.
10. **Multi-distro abstraction.** Debian (`Debian:12`) first, then RPM-based; keep the
    ecosystem/version/comparator behind an interface from day one.

---

## 8. Build vs buy

**Buy / reuse (do not rebuild):**

- Inventory: **Syft** or **OSV-Scalibr** as a Go library — dpkg, snap, flatpak, OCI, Go/Rust/
  .NET/JS catalogers, file↔package relationships, CycloneDX/SPDX emit. Scalibr additionally
  has the unknown-binaries + no-executable annotators.
- Vulnerability facts: **Ubuntu OSV** (CC-BY-SA 4.0) + **Ubuntu OVAL/USN**; EPSS + CISA KEV
  for prioritization.
- Version comparison: `go-deb-version` (Trivy's), `python-debian`, or libdpkg.
- Formats: OSV schema internally, CycloneDX/SPDX for SBOM, SARIF for CI, OpenVEX for triage.

**Build (the differentiated product):**

1. **File→CVE attribution** keyed by absolute path, with package fallback and evidence.
2. **Ubuntu-aware, status-aware decision layer** (backports, ESM, deferred/ignored,
   source-vs-binary, kernel variants).
3. **Unowned/static binary classifier** with confidence tiers and `unknown_binary` fallback.
4. **Noise control + actionable remediation** (VEX, exposure context, fix commands).

---

## 9. Prototype in this repo: what it proves, and results

`cvewalk` (Python, ~1,000 lines incl. tests) implements layers 1–4 end-to-end and was run
against this host (`/home/ubuntu/security-auditor`, Ubuntu 26.04.1 LTS, kernel 7.0.0-38):

| Metric | Result |
|---|---|
| Packages / source packages | 713 / 438 |
| Files indexed / executable ELF files | 3,399 / 1,222 |
| Unowned ELF executables | 0 (this host is fully dpkg-managed) |
| OSV queries | 438 (one per unique source package + version) |
| Vulnerability records matched | 519 (→ 552 finding rows; the same CVE can affect more than one source package) |
| Unique CVE ids | **519 across 87 source packages** |
| Fix available (`installed < fixed`) | **57** |
| KEV-listed | **1** (CVE-2026-111497, brotli, EPSS 0.826) |
| No fix published | 495 rows (includes deferred/ignored — see caveat) |
| Runtime (warm cache) | ~22 s |

**Validation performed:**

- **Fix detection vs apt:** every fixable finding's binary package appears in
  `apt list --upgradable`; zero discrepancies. The 57 actionable findings are genuinely
  fixable on this host.
- **Version comparator:** cross-checked against `dpkg --compare-versions` (unit tests,
  Policy cases incl. `~`, epochs, `+esm`, `+really`).
- **OSV semantics:** reproduced and fixed the two failure modes above (batch pagination;
  cross-variant fixed versions). Directly verified `Ubuntu:26.04:LTS` matches an old openssl
  build (71 CVEs) and a low kernel version correctly, and does *not* match a fixed version.
- **No-fix caveat:** sampled no-fix findings are tracker `needs-triage`, `deferred`, and
  `ignored`; the report states this instead of calling them all exploitable.
- **References:** each finding carries OSV, Ubuntu CVE page, USN (when issued), cve.org, and
  upstream advisory links.

**Not implemented (deliberately, roadmap items):** tracker-status ingestion, OVAL fallback,
EPS/ESM-aware merge, unowned-binary catalogers, md5sums verification, exposure correlation,
SARIF/CycloneDX/OpenVEX output, container/snap scanning. These are called out in the JSON
`limitations` array and in §7.

Usage: see [`README.md`](README.md). Tests: `python3 -m unittest discover -s tests`.

---

## 10. Suggested milestones

- **M0 (prototype, done):** dpkg inventory → OSV Ubuntu → per-executable findings → JSON +
  console, with tests. Proves the data model and the backport-correct matching.
- **M1 (noise reduction):** tracker status ingestion; separate actionable vs deferred/
  ignored/pending; OVAL cross-check; fix-command generation. This is the release that makes
  the report trustworthy.
- **M2 (coverage):** unowned/static binary ladder (note/build-id/Go/Rust/strings), snap/
  flatpak/container roots, md5sums integrity, scripts/language packages.
- **M3 (integration):** SARIF + CycloneDX/SPDX + OpenVEX, CI exit policies, diff/watch mode,
  signed reports, offline bundle (Canonical OSV tarball + OVAL + EPSS/KEV).
- **M4 (context):** exposure-aware ranking (socket/setuid/unit/running process), Pro/ESM +
  Livepatch awareness, multi-distro (Debian then RPM).

---

## Appendix A — data sources & licensing

| Source | URL | Format | License | Backport-aware | Cadence |
|---|---|---|---|---|---|
| Ubuntu OSV | `api.osv.dev`; `security-metadata.canonical.com/osv/osv-all.tar.xz` (≈60 MB) | OSV JSON | CC-BY-SA-4.0 | **Yes** (fixed dpkg versions, `+esmN`) | repo several×/day; tarball daily; OSV ingest hours |
| Ubuntu OVAL | `security-metadata.canonical.com/oval/com.ubuntu.<release>.{cve,usn}.oval.xml.bz2` | OVAL 5.11 XML | CC-BY-SA-4.0 (XML terms say GPLv3 — conflict) | **Yes** | daily ~06:30 UTC; frozen at EOL |
| USN notices | `ubuntu.com/security/notices.json` (~685 KB) | JSON | unverified | Yes (fixed binary versions) | real-time |
| ubuntu-cve-tracker | `git.launchpad.net/ubuntu-cve-tracker` | text | no LICENSE (treat as reference) | Yes (status + version per release) | triage Mon/Wed/Fri |
| EPSS | `api.first.org/data/v1/epss`; daily CSV at `epss.empiricalsecurity.com` | JSON/CSV | FIRST EPSS Usage Agreement | n/a | daily |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON | US Gov work | n/a | several×/week |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | JSON | public (ToS unverified) | **No** | partial enrichment since 2026-04-15 |
| GitHub Advisory | `github.com/github/advisory-database` | OSV JSON | CC-BY-4.0 | ecosystem-dependent | continuous |

Offline recipe: Canonical OSV tarball + per-release OVAL + `notices.json` + EPSS CSV + KEV,
daily delta; local dpkg DB supplies inventory; no network at scan time.

## Appendix B — pitfalls discovered empirically (worth encoding as tests)

1. **`/v1/querybatch` is not a drop-in for `/v1/query`.** For large packages it returns 1,000
   ids plus `next_page_token` that are not version-filtered: `linux` 7.0.0-38.38 returned
   **1,000** batch ids vs **94** from `/v1/query`. Detect `next_page_token` (or 1,000 ids)
   and fall back to single queries; the docs only hint at this with "we recommend HTTP/2 for
   big OSV Linux queries".
2. **Kernel variant bleed.** Filtering `affected[]` only by ecosystem mixes `linux-aws`'s fixed
   version into the generic kernel's status. Always match package name too.
3. **Kernel CVE ↔ userspace tool attribution.** A kernel CVE record's `binaries[]` includes
   `perf`, `bpftool`, `acpidbg`; reporting those as affected executables is misleading. Model
   the kernel as an asset.
4. **OSV encodes deferred/ignored CVEs as fixed-less ranges**, so they match every installed
   version; 84 of 94 kernel findings on this host were no-fix, and samples were tracker
   `deferred`/`ignored`/`needs-triage`. Plan the status layer before shipping.
5. **`ubuntu.com/security/cves.json` is paginated** (default `limit=10`, `q`/`offset`; no
   per-CVE JSON) — not a bulk status API; use the tracker or OVAL for statuses.
6. **`pro security-status` does not list CVE ids** (coverage counts and update counts only);
   it is context, not a database.

## Appendix C — primary references

- OSV Ubuntu data: `github.com/canonical/ubuntu-security-notices`, `security-metadata.canonical.com/osv/`
- OSV API: `google.github.io/osv.dev/api/` (query, querybatch, vulns, binary-to-source)
- Ubuntu OVAL: `documentation.ubuntu.com/security/docs/security-updates/oval/`
- Ubuntu security notices: `ubuntu.com/security/notices`, `notices.json`, `notices/rss.xml`
- Ubuntu CVE tracker: `git.launchpad.net/ubuntu-cve-tracker`
- Debian version grammar: `debian.org/doc/debian-policy/ch-controlfields.html#version`
- EPSS: `first.org/epss` · CISA KEV: `cisa.gov/known-exploited-vulnerabilities-catalog`
- OSV-Scalibr (unknown binaries/no-executable annotators): `github.com/google/osv-scalibr`
- Syft/Grype: `github.com/anchore/syft`, `github.com/anchore/grype` · Trivy: `trivy.dev`
- cve-bin-tool (string-signature model): `github.com/intel/cve-bin-tool`
- Package metadata for executables (`.note.package`): `uapi-group.org/specifications/specs/package_metadata_for_executable_files/`
- cargo auditable: `github.com/rust-secure-code/cargo-auditable`
