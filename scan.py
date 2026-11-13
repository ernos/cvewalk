#!/usr/bin/env python3
"""cvehunt -- scan an Ubuntu/Debian host for CVEs affecting installed executables.

A normal scan does not require root: it only reads dpkg metadata and file headers,
and it never executes the binaries it scans.

Usage:
    python3 scan.py                          # full scan, writes report.json
    python3 scan.py --help                   # complete option reference
    python3 scan.py --limit 10 --json out.json
    python3 scan.py --no-epss --no-kev       # OSV still required
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import socket
import sys
import time
from collections import Counter
from pathlib import Path

from cvehunt import __version__, analyze, enrich, inventory, report
from cvehunt.osv import OsvClient, OsvError

WORKDIR = Path(__file__).resolve().parent
DEFAULT_CACHE = WORKDIR / ".cache" / "cvehunt"


def detect_system() -> dict:
    info: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                info[key] = value.strip().strip('"')
    except OSError:
        pass

    distro_id = info.get("ID", "").lower()
    version = info.get("VERSION_ID", "")
    if distro_id == "ubuntu":
        ecosystem = f"Ubuntu:{version}:LTS" if "LTS" in info.get("VERSION", "") else f"Ubuntu:{version}"
    elif distro_id == "debian":
        ecosystem = f"Debian:{version.split('.')[0]}"
    else:
        ecosystem = None
    return {
        "distro": {
            "id": distro_id,
            "version": version,
            "pretty": info.get("PRETTY_NAME", "unknown"),
        },
        "ecosystem": ecosystem,
    }


def kernel_meta(packages: dict[str, inventory.Package]) -> dict:
    running = os.uname().release
    images = sorted(
        package.name for package in packages.values() if package.name.startswith("linux-image-")
    )
    running_installed = any(running in name for name in images)
    return {
        "running": running,
        "installed_images": images,
        "running_image_installed": running_installed,
    }


def build_queries(inventory_obj: inventory.Inventory, ecosystem: str):
    queries = []
    keys = []
    seen = set()
    for package in inventory_obj.packages.values():
        key = (package.source, package.query_version)
        if key in seen:
            continue
        seen.add(key)
        keys.append(key)
        queries.append(
            {
                "package": {"name": package.source, "ecosystem": ecosystem},
                "version": package.query_version,
            }
        )
    return keys, queries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a dpkg-based host for CVEs affecting installed executables."
    )
    parser.add_argument("--json", default="report.json", help="JSON report path")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE), help="OSV/KEV cache directory")
    parser.add_argument("--ecosystem", default=None, help="override, e.g. Ubuntu:24.04:LTS")
    parser.add_argument("--extra-path", action="append", default=[], help="extra directory to scan")
    parser.add_argument("--limit", type=int, default=25, help="rows in the console table")
    parser.add_argument("--no-epss", action="store_true", help="skip EPSS enrichment")
    parser.add_argument("--no-kev", action="store_true", help="skip CISA KEV enrichment")
    parser.add_argument("--refresh", action="store_true", help="ignore caches")
    parser.add_argument(
        "--fail-on",
        choices=["none", "kev", "critical", "any"],
        default="none",
        help="exit 1 when matching findings exist",
    )
    parser.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    args = parser.parse_args(argv)

    def progress(message: str) -> None:
        if not args.quiet:
            print(message, file=sys.stderr)

    started_wall = dt.datetime.now(dt.timezone.utc)
    started = time.monotonic()

    system = detect_system()
    ecosystem = args.ecosystem or system["ecosystem"]
    if not ecosystem:
        print(
            f"unsupported distribution: {system['distro']['pretty']} "
            "(need an Ubuntu or Debian release with OSV ecosystem data)",
            file=sys.stderr,
        )
        return 2
    system["ecosystem"] = ecosystem

    warnings: list[str] = []

    progress("[1/5] inventorying packages and files ...")
    try:
        inventory_obj = inventory.load(extra_roots=args.extra_path)
    except Exception as error:  # noqa: BLE001 - report and fail cleanly
        print(f"inventory failed: {error}", file=sys.stderr)
        return 2

    executables = inventory_obj.executables
    progress(
        f"      {len(inventory_obj.packages)} packages, {len(inventory_obj.files)} files, "
        f"{len(executables)} executable ELF files, {len(inventory_obj.unmatched)} unowned"
    )

    kernel = kernel_meta(inventory_obj.packages)
    if not kernel["running_image_installed"]:
        warnings.append(
            f"running kernel {kernel['running']} does not match an installed linux-image package; "
            "kernel CVEs may be under-reported"
        )

    progress("[2/5] querying OSV distro vulnerability data ...")
    client = OsvClient(args.cache_dir, verbose=not args.quiet)
    keys, queries = build_queries(inventory_obj, ecosystem)
    try:
        results = client.query(queries)
        matched: dict[tuple[str, str], list[str]] = {}
        for key, ids in zip(keys, results):
            if ids:
                matched[key] = list(dict.fromkeys(ids))
        all_ids = [vuln_id for ids in matched.values() for vuln_id in ids]
        progress(
            f"      {len(keys)} unique source packages queried, "
            f"{len(all_ids)} vulnerable package/CVE pairs"
        )
        progress("[3/5] fetching vulnerability records ...")
        records = client.get_vulns(all_ids, refresh=args.refresh)
    except OsvError as error:
        print(f"OSV query failed: {error}", file=sys.stderr)
        return 2

    progress("[4/5] enriching with EPSS and KEV ...")
    epss_data: dict[str, dict] = {}
    epss_meta = {"ok": False, "hits": 0, "error": None}
    if not args.no_epss:
        all_cves = sorted({cve for vuln in records.values() for cve in enrich.cves_for(vuln)})
        try:
            epss_data = enrich.fetch_epss(all_cves, cache_dir=args.cache_dir)
            epss_meta = {"ok": True, "hits": len(epss_data), "error": None}
            progress(f"      EPSS: {len(epss_data)}/{len(all_cves)} CVEs scored")
        except Exception as error:  # noqa: BLE001
            epss_meta["error"] = str(error)
            warnings.append(f"EPSS unavailable: {error}")
    else:
        epss_meta["error"] = "disabled"

    kev_data: dict[str, dict] = {}
    kev_meta = {"ok": False, "entries": 0, "error": None}
    if not args.no_kev:
        try:
            kev_data = enrich.fetch_kev(args.cache_dir, refresh=args.refresh)
            kev_meta = {"ok": True, "entries": len(kev_data), "error": None}
            progress(f"      KEV: {len(kev_data)} catalog entries")
        except Exception as error:  # noqa: BLE001
            kev_meta["error"] = str(error)
            warnings.append(f"CISA KEV unavailable: {error}")
    else:
        kev_meta["error"] = "disabled"

    progress("[5/5] correlating files and building report ...")
    findings = analyze.build_findings(
        inventory_obj, ecosystem, matched, records, epss_data, kev_data, kernel=kernel
    )

    unowned = []
    for record in inventory_obj.unmatched[:50]:
        unowned.append(
            {"path": record.path, "hints": inventory.fingerprint(record.path)}
        )

    packages_with_findings = {finding["source_package"] for finding in findings}
    cves = {finding["cve"] for finding in findings}
    risk_counts = Counter(finding["risk"] for finding in findings)
    unfixed = sum(1 for finding in findings if finding["fix_status"] == "unfixed")
    fixable = sum(1 for finding in findings if finding["fix_status"] == "fixed")
    actionable = sum(1 for finding in findings if finding["actionable"])
    if unfixed:
        warnings.append(
            f"{unfixed} findings have no fixed version in the OSV data. OSV does not expose "
            "Ubuntu tracker status, so this set can include CVEs Canonical marked "
            "deferred/ignored (will-not-fix); cross-check ubuntu-cve-tracker or OVAL "
            "before treating them as actionable."
        )

    report_data = {
        "tool": {"name": "cvehunt", "version": __version__},
        "scan": {
            "started": started_wall.isoformat(),
            "duration_s": round(time.monotonic() - started, 2),
            "hostname": socket.gethostname(),
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "args": vars(args),
        },
        "system": system
        | {
            "kernel": kernel,
        },
        "inventory": {
            "packages": len(inventory_obj.packages),
            "source_packages": len({package.source for package in inventory_obj.packages.values()}),
            "files": len(inventory_obj.files),
            "executables": len([record for record in inventory_obj.files.values() if record.executable]),
            "elf_executables": len(executables),
            "unowned_elf": len(inventory_obj.unmatched),
        },
        "data": {
            "osv": {
                "ok": True,
                "ecosystem": ecosystem,
                "queries": len(keys),
                "matchers": len(all_ids),
                "vuln_records": len(records),
                "source": "https://osv.dev (Ubuntu/Debian tracker data)",
                "note": "Source-package indexed; 'fixed' versions are backported Ubuntu "
                "package versions, so version matching is backport-aware.",
            },
            "epss": epss_meta,
            "kev": kev_meta,
        },
        "summary": {
            "findings": len(findings),
            "cves": len(cves),
            "packages_with_findings": len(packages_with_findings),
            "kev": sum(1 for finding in findings if finding["kev"]),
            "actionable": actionable,
            "fixable": fixable,
            "unfixed": unfixed,
            "by_risk": dict(risk_counts),
        },
        "findings": findings,
        "unowned": unowned,
        "warnings": warnings,
        "limitations": [
            "Package provenance is taken from dpkg; packages installed from third-party "
            "repositories may be checked against Ubuntu version ranges and should be verified.",
            "Statically linked or vendored library copies inside binaries are not covered by "
            "package data; unowned binaries are reported with heuristic version hints only.",
            "OSV Ubuntu data does not expose the tracker status per release, so CVEs Canonical "
            "marked deferred/ignored appear as 'no fix' rather than 'will not fix'.",
            "Ubuntu Pro/ESM fixes live in a separate OSV namespace (Ubuntu:Pro:<release>); a "
            "non-entitled host may show ESM-only fixes as unfixed.",
            "OSV ingest can lag the Ubuntu security tracker by up to a day; very recent USNs "
            "may be missing.",
            "EPSS and KEV are exploit-likelihood signals, not proof of exploitability on this host.",
            "Kernel CVEs are reported against the kernel image and require a reboot; userspace "
            "tools shipped from the same source package are not listed as affected.",
        ],
    }

    console = report.render_console(report_data, limit=args.limit)
    print(console)
    report.write_json(report_data, args.json)
    print(f"\nJSON report written to {args.json}")

    if args.fail_on != "none":
        if args.fail_on == "any" and findings:
            return 1
        if args.fail_on == "kev" and any(finding["kev"] for finding in findings):
            return 1
        if args.fail_on == "critical" and any(
            finding["risk"] in ("CRITICAL", "EXPLOITED") for finding in findings
        ):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
