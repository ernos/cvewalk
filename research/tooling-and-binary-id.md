# Tooling landscape and binary identification for a per-executable Ubuntu CVE scanner

Research as of **2026-11-13**, target OS **Ubuntu 26.04 LTS**. RESEARCH ONLY; no code in repo.
Conventions: claims are linked to primary docs/repos. `[UNVERIFIED]` = could not confirm from a primary source in this session.
Product of this doc: what to reuse, what to build, and which techniques actually get you **`/usr/bin/foo → CVE-XXXX-YYYY + references`**.

---

## Part A — Existing tools (what they inventory, where data comes from, whether they name the file)

| Tool (license) | Inventories | Ubuntu/Debian support + data source | Attributes to a specific **executable path**? | Output | Maturity |
|---|---|---|---|---|---|
| **osv-scanner** v2 (Apache-2.0) | lockfiles/manifests, OS packages on Linux, container images (layer-aware), vendored C/C++ | DPKG/Ubuntu via OSV-Scalibr; matches against **OSV.dev**, which ingests Canonical's Ubuntu OSV feed; offline mode w/ local DB | **No** for OS packages (package name+version). Image results carry package/layer, not per-file rows | JSON, SARIF, table/markdown, HTML [UNVERIFIED: exact v2 `--format` list]; not CycloneDX | Very active, Google-backed; the OSV frontend |
| **Trivy** (Apache-2.0) | container images, filesystem, rootfs, repo, VM images, K8s; OS pkgs + language pkgs + secrets + misconfig + license | Ubuntu documented in [coverage/os/ubuntu](https://trivy.dev/docs/latest/coverage/os/ubuntu/): data source, **fixed version, severity, status**; DB built from distro trackers/OVAL; also detects Go buildinfo and Rust `cargo auditable` | **Partially**: `Target` for language pkgs *is* the binary/jar path (e.g. `usr/local/bin/app`), OS-pkg findings are package-level | table, **JSON, SARIF**, template (JUnit/HTML/ASFF), **CycloneDX/SPDX**, VEX | De-facto standard; excellent Ubuntu patched-version handling |
| **Syft + Grype** (Apache-2.0) | Syft: images/filesystems/archives → SBOM. Grype: images/fs/SBOM → CVEs | Grype DB built by Vunnel from NVD + distro feeds incl. Ubuntu; Ubuntu backports handled in DB; EPSS/KEV/OpenVEX | Syft **produces the raw material**: `files[]` with `location` + `executable{format, importedLibraries, elfSecurityFeatures}` and `artifactRelationships`; package↔file linking is possible but Grype findings are still package-keyed | Syft: **CycloneDX, SPDX**, Syft-JSON. Grype: table, JSON, CycloneDX, SARIF [UNVERIFIED: SARIF] | Mature, huge cataloger coverage (see Part B5) |
| **cve-bin-tool** (GPL-3.0) | **Binaries by string signatures** (457 checkers), SBOM input, archives (.deb/.rpm/.apk/…), language lockfiles | Data: NVD + Red Hat + OSV + GitLab AD + curl; `--available-fix/--backport-fix` for distro fix data [UNVERIFIED: which distros] | **Yes — reports the file path where the signature matched** (its whole model) | CSV, JSON/JSON2, console, HTML, PDF, MD, SBOM (SPDX/CDX), VEX (CDX/CSAF/OpenVEX) | Best-in-class for *unpackaged/static* C libs; explicitly admits it cannot see backports nor obfuscated versions ([Limitations](https://github.com/intel/cve-bin-tool#limitations)) |
| **OpenSCAP/oscap + Ubuntu OVAL** (LGPL-2.1 [UNVERIFIED]) | OVAL/XCCDF/SCAP content evaluation; does not inventory by itself | Canonical ships **CVE OVAL and USN OVAL** per release at `security-metadata.canonical.com/oval/`; [documented workflow](https://documentation.ubuntu.com/security/docs/security-updates/oval/); Ubuntu Security Guide adds CIS/STIG profiles | **No.** OVAL definitions test installed **package versions** (`dpkg`/rpm state); no file entities | XML results, ARF, HTML report; no native JSON/SARIF | Authoritative data; operator UX poor |
| **debsecan** (GPL-2+ [UNVERIFIED]) | Installed dpkg packages from `/var/lib/dpkg/status` | **Debian only** — Debian Security Tracker data; man page calls it "Debian Security Analyzer" and suites are Debian codenames; no Ubuntu feed | No (package names). Caveat in man page: **source-package-based tracking flags all binary packages** incl. docs-only ones; unknown/backported versions compared against unstable → wrong | text only (summary/simple/bugs/packages/detail/report) | Legacy, unmaintained-ish |
| **Vuls** (GPL-3.0) | Linux/Win/macOS hosts, agentless SSH; OS packages, kernel, non-OS pkgs (locks, CPE, OWASP DC) | Ubuntu via **OVAL** (`security-metadata.canonical.com/oval/`) + gost/goval-dictionary, Ubuntu CVE Tracker; fast scan reads package DB without root | No for OS pkgs; CPE path is name/version matching (false positives) | JSON, TUI, VulsRepo HTML | Mature in Japan/enterprise; GPLv3 |
| **Lynis** (GPL-3.0) | Host hardening/config audit; shallow "outdated package" checks | No CVE database of its own; no Ubuntu patch-level data | No | `lynis-report.dat`, text log | Not a CVE scanner — baseline only |
| **ubuntu-security-status / pro client** | Installed packages vs standard security maintenance + ESM coverage, available security updates | Canonical archive + USN/ESM | No; **counts** of packages/updates [UNVERIFIED: current command name & JSON schema] | human text (+ JSON [UNVERIFIED]) | Canonical-supported baseline; good for "is ESM enabled" |
| **osquery + Fleet** | osquery: host tables. Fleet: fleet-wide vuln processing | osquery `deb_packages` has **no file path column** (`name, version, source, size, arch, revision, status, maintainer, section, priority, admindir` — [spec](https://github.com/osquery/osquery/blob/master/specs/linux/deb_packages.table)). Fleet matches: NVD/CPE + **Ubuntu OVAL** + VulnCheck; Debian packages **not covered** (NVD fallback → false positives) | No | osquery: JSON/CSV/events; Fleet: API/UI | Fleet's OVAL path is solid for Ubuntu packages; still package-granular |
| **Commercial (Wazuh/Qualys/Tenable)** | Agent package/software inventory (+ file integrity/registry) | Wazuh: own CTI feed + vendor advisories [UNVERIFIED: exact feed semantics]; Qualys/Tenable: vendor feeds + some file/hash local checks | Generally **no per-executable CVE attribution** for Linux ELF; file checks exist but are plugin-by-plugin [UNVERIFIED] | vendor-specific (JSON/QIDs) | Baseline expectation, not a reference design |

### What is already solved vs. the real gap

- **Solved (do not rebuild):** version→CVE resolution *for distro packages* with correct Ubuntu patched-version semantics (Trivy, Grype, Vuls, Fleet, oscap+Ubuntu OVAL), and CVE references (OSV/USN/NVD). Also solved: SBOM generation (Syft/Scalibr), Go/Rust binary provenance.
- **Gap 1 — per-executable attribution.** Every distro-feed tool keys findings on `(package, version)`. None answers "which file on disk is affected" — yet the mapping is available: `/var/lib/dpkg/info/<pkg>.list` is a complete package→files list, and `dpkg -S` is just an index over it. Tools stop at the package boundary because their data model (OVAL/OSV/USN) is package-scoped.
- **Gap 2 — non-packaged and static binaries.** Binaries copied to `/opt`, `/usr/local`, container images, AppImages/snaps, and statically linked third-party libs (openssl inside a Go binary via cgo) are invisible to dpkg-based scanners. Only string-signature scanners (cve-bin-tool) and OSV-Scalibr's *unknown binaries* extractor reach them.
- **Gap 3 — false positives from NVD/CPE matching.** Anything that matches by version alone (Vuls CPE path, Fleet's NVD fallback, cve-bin-tool for distro-patched libs, osquery-style inventories) reports CVEs Ubuntu already fixed via backport. Fleet documents this trade-off explicitly ([Linux coverage](https://fleetdm.com/guides/vulnerability-processing)).
- **Gap 4 — modified/replaced binaries.** Package says `1.2.3-1ubuntu1`, but the file may have been replaced or locally built. `*.md5sums` verification (debsums-style) is the cheap detector, and no mainstream scanner reports it per file.

---

## Part B — Identifying what a binary is (and its version) **without executing it**

### B1. ELF-level facts
- `.comment`: compiler/assembler version (`GCC: (Ubuntu 13.x) 13.x`). **Not** library versions — a classic false-positive source.
- `.note.gnu.build-id`: 160-bit build hash. Purpose: map a build to debuginfo. Ubuntu packages ship `/usr/lib/debug/.build-id/xx/yyyy.debug` symlinks (ddebs/dbgsym), and distro packages carry `.build-id` links (visible in cve-bin-tool's own examples for RPM/Debian packages). ⇒ build-id is a **stable fingerprint of an exact build** — usable to say "this file is (a copy of) the distro build of package P", even outside package paths.
- `.note.package`: **[UAPI "Package Metadata for Executable Files"](https://uapi-group.org/specifications/specs/package_metadata_for_executable_files/)** — a JSON note containing package name, version, architecture, os, osVersion, and optional CPE/purl. Syft models it as `ElfBinaryPackageNoteJsonPayload`. Where present (systemd-built distro binaries), this is **authoritative self-description** and should outrank any inference. Adoption is partial — treat as a bonus tier.
- `DT_NEEDED` (dynamic section): gives `.so` names — **sonames carry no patch version** (`libssl.so.3`). Map soname→package via `dpkg -S`/own index, then use the *package* version.
- Static detection: no `PT_INTERP`, no `DT_NEEDED` (or only `ld-linux` absent), or `file(1)` reporting "statically linked". Static binaries have **no dependency provenance at all** except embedded strings/Go/Rust metadata.

### B2. Language runtimes embedded in the binary
- **Go**: toolchain appends build info; read with `debug/buildinfo.ReadFile` / `go version -m <file>` — gives Go version, module path, **full module list with versions and sums**, and `vcs.revision`/`vcs.modified`. Syft `GoModuleBuildinfoEntry`, Scalibr `go/binary`. Covers vendored Go deps exactly; **does not** cover cgo-linked C libs.
- **Rust**: rustc version is embedded (Rust ≥1.73); crate list is *not* embedded by default. **`cargo auditable`** writes zlib-compressed JSON into ELF section **`.dep-v0`** — recoverable without running the binary, parseable in ~5 lines ([README](https://github.com/rust-secure-code/cargo-auditable)). Consumed by Syft (≥1.15), Scalibr (`rust/cargoauditable`), Trivy ≥0.31, Grype ≥0.83, osv-scanner ≥2.0.1, `cargo audit bin`. **Ubuntu 26.04 builds select packages with it and lets maintainers opt in** — on our target OS this is a first-class signal. FAQ admits statically linked C libs are not exposed.
- **.NET**: PE/CLR metadata + `deps.json`/`packages.lock.json` (Scalibr `dotnet/pe`, syft `DotnetPortableExecutableEntry`).
- **Electron/Node**: app code lives in `resources/app.asar` — parse the asar directory, read `package.json` versions and the Electron version; Scalibr `javascript/electronasar`. Embedded Node runtime version appears as `process.version`-style strings (`node vX`/NODE_MODULE_VERSION).

### B3. Embedded C libraries (OpenSSL, zlib, curl, …) — the string-signature school
cve-bin-tool's model, verbatim from its [checker guide](https://github.com/intel/cve-bin-tool/blob/main/doc/checkers/README.md): per product a `Checker` class with `CONTAINS_PATTERNS` (identity), `VERSION_PATTERNS` (regex on `strings` output), `FILENAME_PATTERNS`, `VENDOR_PRODUCT` (NVD vendor/product for CVE lookup), `IGNORE_PATTERNS`.
- Real banners: `OpenSSL 3.0.13 30 Jan 2024`, `1.3.1`/`deflate 1.3.1 Copyright` (zlib), `libcurl/8.5.0`, `Xiph.Org libVorbis I 20200704`.
- **Documented false-positive trap**: the naive `[0-9]+\.[0-9]+\.[0-9]+` pattern matches *everything* — gcc/glibc versions in `.comment` being the usual suspects (their worked example: libcurl 7.34.0 vs `GCC ... 8.1.0` in the same binary). Mitigations that actually work: (a) require a product-anchored prefix (`curl[ -/]([678]+\.[0-9]+\.[0-9]+)`); (b) require both a CONTAINS and a VERSION pattern; (c) `IGNORE_PATTERNS`; (d) product-specific parsers where regex fails (their `sqlite` checker uses embedded version *hashes*; `python` overrides `get_versions()`); (e) iterate across distro packages to find stable strings.
- Quantitative FP rate: **no published precision/recall for cve-bin-tool [UNVERIFIED]** — do not quote a number. Treat strings matches as *lower-confidence* tiers and always attach the matched string as evidence so a human can dismiss it.
- Packer/obfuscation: UPX magic → upstream limitation "will not work if version information was intentionally obfuscated". Entropy + section-count heuristics (what `upx`/syft classifiers see) are cheap; report `unknown_binary` explicitly instead of guessing.

### B4. Interrogating the dpkg database ourselves (fast, no subprocess)
- `dpkg -S /path` is a linear scan over `/var/lib/dpkg/info/*.list`; fine for one path, hopeless for 100k files. **Build the reverse index once** in memory: `{path -> [(pkg, arch)]}` from every `.list`.
- Facts the index must respect: multi-arch (`pkg:amd64` file lists), **diversions** (`/var/lib/dpkg/diversions`, `dpkg-divert --list`), **alternatives** (`/etc/alternatives` symlinks owned by the `dpkg-alternatives` db, not by a package file list), merged-`/usr` symlinks (`/bin → /usr/bin`), and conffile deletions.
- `*.md5sums` per package: verify file digests to detect replaced/modified binaries (debsums approach). Missing md5sums (not all packages ship them) ⇒ unknown integrity, not "bad".
- Package status matters: only `install ok installed` (and `Config-Files` residue excluded) — read `Status:` from the status file. `dpkg-query -W -f='${Package} ${Version} ${Architecture} ${db:Status-Abbrev}\n'` is the one acceptable subprocess (read-only, no target binary executed).

### B5. Reusable inventory engines (this is where buying wins)
- **Syft catalogers** ([dir](https://github.com/anchore/syft/tree/main/syft/pkg/cataloger)): `debian` (dpkg db) , `binary` (classifier cataloger: snippet/pattern matching for e.g. curl/openssl/redis-server, tested against real binaries), `golang`, `rust`, `dotnet`, `javascript`, `snap`, plus `files[]` + `artifactRelationships` + `executable`/ELF security metadata in JSON schema v16.
- **OSV-Scalibr** plugins ([supported inventory types](https://github.com/google/osv-scalibr/blob/main/docs/supported_inventory_types.md)): `os/dpkg`, `os/snap`, `os/flatpak`, `go/binary`, `rust/cargoauditable`, `javascript/electronasar`, `dotnet/pe`, `containers/*`.
- **Directly relevant new prior art** (2026) — Scalibr has an *unknown binaries* pipeline: `extractor/.../ffa/unknownbinariesextr` extracts executables not accounted for by any package manager, then `ffa/unknownbinariesanno` removes those that are in dpkg `.list` files (it ignores `var/lib/dpkg/info` itself because pre/post-install scripts live there, and evaluates symlinks), and `vex/no-executable/dpkg` annotates package findings with a **VEX "component not present"** signal when a package ships no executable at all. That is precisely the file-level attribution + noise-reduction problem we are solving — study it before building.

### B6. Packaged app formats
- **snap**: squashfs mounted at `/snap/<name>/<rev>`; read `meta/snap.yaml` (name, version, base, apps) from the squashfs — no execution. Revision dir names are not versions.
- **flatpak**: OSTree deployments under `/var/lib/flatpak/app/<id>/<arch>/<branch>/<commit>/files`; app metadata in `/var/lib/flatpak/app/<id>/current/active/metadata` and appstream XML; runtime versions (`org.freedesktop.Platform/x86_64/24.08`) are the security-relevant "version".
- **AppImage (type 2)**: squashfs with `AppRun` + `<app>.desktop`; version usually only in the `.desktop`/embedded app metadata — often `unknown`.
- **OCI/container layers**: tar layers + whiteouts; process in layer order and respect deletions; record layer digest as part of file identity (Syft `Coordinates.layerID`, osv-scanner/Scalibr do this). Never `docker run` the image to introspect it.

### B7. Confidence tiers to emit per file
1. **exact-package**: file ∈ dpkg `.list` of installed pkg (+ md5sums verified) → use package version, Ubuntu feeds.
2. **exact-build**: `.note.package` or build-id match to a distro build → same as above, works for relocated copies.
3. **embedded-metadata**: Go buildinfo / `.dep-v0` / asar/deps.json → match ecosystem-specific advisory DBs (Go vulndb, RustSec, npm) per module.
4. **signature**: strings/regex hit (openssl/zlib/curl banners) → CVE by upstream version range, marked `needs_triage`.
5. **unknown**: unowned static binary, packed, no metadata → report presence + hash, no CVE claim.

---

## Part C — Version and matching pitfalls

### C1. Debian/Ubuntu version grammar (get this exactly right)
`[epoch:]upstream_version[-debian_revision]` ([Debian Policy 5.6.12](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version)):
- epoch is an integer, compared numerically, omitted = 0; upstream is mandatory and may contain letters, digits, `. + - ~`; the split is at the **last** hyphen; absent revision = 0.
- Comparison: alternate non-digit and digit runs; non-digit runs compare with **`~` sorting before everything (even empty)**, letters before non-letters; digit runs compare numerically.
- Consequences the comparator MUST handle: `1.0~rc1 < 1.0`, `1:0.9 > 2.0`, `1.0+really0.9`, `1.2-3.1` (NMU), `1.2-3+deb12u1` (stable update), `1.2-3~bpo12u1` (backport) — all from Policy.
- Ubuntu additions you will actually see: `2.4.41-4ubuntu3.1`, `1.2.3-0ubuntu0.24.04.5`, `+esm1`…`+esm16` (ESM), `+esm`-style suffixes on Pro streams. Use a battle-tested comparator: `dpkg --compare-versions`/libdpkg-perl `version.pm`, `python-debian` `debian.debian_support.Version`, Go `github.com/knqyf263/go-deb-version` (what Trivy uses), Rust `debversion`. **Do not hand-roll**; if the prototype (`cvewalk/debver.py`) already implements it, validate it against `dpkg --compare-versions` on the Policy examples above as a test corpus.

### C2. Backports are the big one
Ubuntu fixes most CVEs **without changing upstream version** — the patch is in the Debian revision (`-0ubuntu0.24.04.x`). Therefore:
- Comparing the *upstream* part (`2.4.41`) against an NVD/CPE range or an upstream OSV range = guaranteed false positives on patched systems.
- The authoritative answer is **Canonical's own fixed-version data**: Ubuntu **OSV** (`github.com/canonical/ubuntu-security-notices`, `osv/` dir; also tarball at `security-metadata.canonical.com/osv/`; also osv.dev) and **USN OVAL**. Ubuntu OSV records carry per-release ecosystems (`Ubuntu:24.04:LTS`, `Ubuntu:Pro:18.04:LTS`), `ranges.events` with `{introduced, fixed}` and an explicit `versions[]` list of every shipped version — so "is my dpkg version ≥ fixed" is a pure Debian-version comparison within the right release.
- Bonus already in that feed: `affected[].ecosystem_specific.binaries[]` gives `{binary_name, binary_version}` — the official **source→binary package mapping** (e.g. source `php8.3` → `php8.3-cli`, `libphp8.3-embed`). Use it instead of guessing, and it keeps you correct on source-vs-binary naming.
- Ubuntu OSV data is **CC BY-SA 4.0** — attribution/share-alike obligations apply if you redistribute or serve it.
- Note the Ubuntu OVAL split: **CVE OVAL** = triage of every CVE (even unfixed), **USN OVAL** = "patch missing" checks. They answer different questions.

### C3. Source vs binary package, epochs across releases, ESM
- Advisory data is usually keyed by **source** package; installed state is **binary** packages. Map explicitly (`Source:` field in `dpkg-query -W -f='${source:Package}'`, or OSV `binaries[]`). Libraries are separate binaries (`libssl3t64`, `libssl3`) from their source (`openssl`).
- ESM/Pro streams change what "fixed" means (a CVE may be fixed only for ESM-enabled systems, or only in `esm-apps`). Carry `pro status` + the OSV `Ubuntu:Pro:*` ecosystems into the decision; otherwise you either over- or under-report.
- Release codename→OSV ecosystem mapping must be explicit (`noble`→`Ubuntu:24.04:LTS`; whatever 26.04's codename is → `Ubuntu:26.04:LTS`) and pinned; do not infer from version strings.

### C4. Vendored and statically linked copies
- Go: buildinfo module list is trustworthy and complete for Go modules. But a cgo-linked OpenSSL/zlib is invisible → strings tier.
- Rust: only if built with `cargo auditable`; otherwise nothing. This is why 26.04's opt-in matters.
- Python: wheel/site-packages metadata or PyInstaller archive; frozen binaries embed the interpreter version.
- Static copies defeat `dpkg -S` entirely (no package owns the code) — this is Gap 2, and the reason a strings/classifier tier is non-optional.

### C5. Why executing `--version` during a scan is unacceptable
1. **Arbitrary code execution on the scanned host** — a replaced/malicious binary, or a trojaned `/usr/local/bin` older PATH entry, runs with the scanner's privileges (often root). A scanner must never be a loader.
2. **Side effects**: daemons/one-shot tools may initialize state, write config/cache, bind ports, or send network traffic.
3. **Hangs / no timeout semantics**: waiting on stdin, tty, lock files, or a supervisor; no portable timeout that also prevents fork bombs.
4. **Wrong or absent output**: not all tools accept `--version` (`openssl version`, `python3 -V`, `curl --version` differ); output goes to stderr; localized/coloured; truncated by pagers; nonzero exit codes.
5. **Environment-dependent answers**: `--version` may report the *linked* library at runtime (LD_LIBRARY_PATH/LD_PRELOAD), not the static copy in the file; setuid/AppArmor/capability-restricted binaries may refuse to run.
6. **Sandbox escapes / unreliable isolation**: on a host scan you cannot assume user namespaces, seccomp, or a disposable VM; mounting the target rootfs and chrooting still executes target code on the same kernel.
7. **Libraries and data files can't be executed at all**, so the technique doesn't generalize.
⇒ Everything in Part B is deliberate: read bytes, parse headers/notes/buildinfo, query the package DB. (cve-bin-tool is built on exactly this premise.)

---

## Part D — Build vs. buy

**Buy (as libraries/data — saves months):**
- **Ubuntu vulnerability data**: OSV feed (`canonical/ubuntu-security-notices`, plus `security-metadata.canonical.com/osv/`) for version→CVE+fixed+references; fall back to USN OVAL for patch status. License: CC BY-SA 4.0 (attribute; share-alike on the data).
- **Debian version comparison**: dpkg/libdpkg-perl, `python-debian`, `go-deb-version`. Never custom string compares.
- **Inventory/cataloging**: Syft as a Go library (dpkg+binary+go+rust+dotnet+snap catalogers, file/package relationships, CycloneDX/SPDX emit) **or** OSV-Scalibr as a library (Apache-2.0; dpkg/snap/flatpak/OCI + `unknownbinaries` + `noexecutable` annotators + VEX output). Choose one, wrap it, do not fork it.
- **Standards**: **OSV schema** for internal findings (already the canonical distro format), **CycloneDX/SPDX** for SBOM output, **SARIF** for CI, **OpenVEX** for triage/false-positive suppression, `pkg:deb/ubuntu/...` **purls** for identity.
- **Advisory enrichment**: NVD/OSV for references, EPSS/KEV for prioritisation.

**Build (this is the differentiated product):**
1. **A file→CVE attribution layer** that no tool ships: one pass over dpkg `.list` (+ diversions, alternatives, merged-`/usr`, md5sums verification) → reverse index `path → package(+arch, version, status)`; then per-file resolvers in the Part B7 tier order; output must be keyed by **absolute file path**, with `package` as fallback and evidence (build-id/note/signature) attached.
2. **A matcher that speaks Ubuntu, not NVD**: given `(file, package, dpkg version, release, pro/ESM state)` → CVEs from Ubuntu OSV `ranges.events.fixed` using Debian comparison, joined to USN/NVD references. Refuse to infer Ubuntu patch status from upstream version strings.
3. **Coverage for unowned/static binaries**: index all ELF executables under a configurable root; classify owned vs unowned; for unowned: `.note.package` → build-id → Go buildinfo → `.dep-v0` → `.comment`/strings signatures; emit `unknown_binary` + sha256 instead of silence.
4. **Noise control**: confidence tiers, VEX/whitelist triage (reuse OpenVEX), and a "modified binary" flag from md5sums mismatch — because today's scanners' top complaint is not missing CVEs, it's unattributable CVEs.

**Verdict:** *buy the inventory and the vulnerability data; build the attribution and the Ubuntu-aware decision layer.* Concretely: Syft or OSV-Scalibr for cataloging + Ubuntu OSV/OVAL for facts + a comparator (dpkg/python-debian) = ~80% of the work already exists. The remaining 20% — per-file attribution, static/unowned binaries, modified-binary detection, and Ubuntu backport-correct matching — is the entire product, and none of the surveyed tools does it end-to-end.

### Primary references
- https://github.com/google/osv-scanner · https://github.com/google/osv-scalibr (`docs/supported_inventory_types.md`, `annotator/noexecutable/dpkg`, `annotator/ffa/unknownbinariesanno`)
- https://trivy.dev/docs/latest/coverage/os/ubuntu/ · https://trivy.dev/docs/latest/configuration/reporting/
- https://github.com/anchore/syft (catalogers, `syft/pkg/cataloger/binary/README.md`) · https://oss.anchore.com/docs/reference/syft/json/16/ · https://github.com/anchore/grype
- https://github.com/intel/cve-bin-tool (`doc/README.md` Limitations, `doc/checkers/README.md`)
- https://documentation.ubuntu.com/security/docs/security-updates/oval/ · https://documentation.ubuntu.com/security/docs/security-updates/osv/ · https://github.com/canonical/ubuntu-security-notices
- https://github.com/OpenSCAP/openscap · https://github.com/future-architect/vuls · https://github.com/CISOfy/lynis · https://manpages.debian.org/unstable/debsecan/debsecan.1.en.html
- https://github.com/osquery/osquery/blob/master/specs/linux/deb_packages.table · https://fleetdm.com/guides/vulnerability-processing
- https://github.com/rust-secure-code/cargo-auditable · https://pkg.go.dev/debug/buildinfo · https://uapi-group.org/specifications/specs/package_metadata_for_executable_files/ · https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
