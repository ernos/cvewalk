"""Turn raw OSV matches into file-attributed findings.

One finding = (source package, CVE).  Each finding carries:
  * the distro fix status for the *installed* package version
  * the executable files (and shared libraries) that belong to the affected
    binary packages, i.e. the per-file attribution the whole tool exists for
  * references (Ubuntu CVE page, USN advisories, upstream commits)
  * priority signals: Ubuntu priority, CVSS base score, EPSS, KEV
"""

from __future__ import annotations

from . import enrich
from .inventory import Inventory


def build_findings(
    inventory: Inventory,
    ecosystem: str,
    matched: dict[tuple[str, str], list[str]],
    records: dict[str, dict],
    epss: dict[str, dict],
    kev: dict[str, dict],
    kernel: dict | None = None,
) -> list[dict]:
    """matched: (source package, source version) -> [osv vuln ids]."""
    findings: list[dict] = []

    for (source, version), vuln_ids in matched.items():
        source_packages = inventory.packages_for_source(source)
        if not source_packages:
            continue
        by_base = {package.base_name: package for package in source_packages}

        for vuln_id in dict.fromkeys(vuln_ids):
            vuln = records.get(vuln_id)
            if not vuln:
                continue
            info = enrich.fix_info(vuln, ecosystem, version, package_name=source)

            if info["binaries"]:
                affected_packages = [
                    by_base[name] for name in info["binaries"] if name in by_base
                ]
            else:
                affected_packages = list(by_base.values())
            if not affected_packages:
                continue

            # Kernel CVEs live in the kernel image, not in the userspace tools
            # (perf, bpftool, acpidbg, ...) that the same source package ships.
            # Attributing a kernel CVE to /usr/bin/perf would be misleading, so
            # kernel findings are reported against the running/installed image.
            is_kernel = source == "linux" or any(
                package.base_name.startswith(
                    ("linux-image-", "linux-modules-", "linux-headers-")
                )
                for package in affected_packages
            )
            executables: list[str] = []
            libraries: list[str] = []
            if not is_kernel:
                for package in affected_packages:
                    executables.extend(inventory.executable_paths(package.name))
                    libraries.extend(_library_paths(inventory, package.name))

            cves = enrich.cves_for(vuln)
            if not cves:
                cves = [vuln_id]

            epss_values = [epss[cve] for cve in cves if cve in epss]
            best_epss = max(epss_values, key=lambda row: row["epss"]) if epss_values else None
            kev_entry = next((kev[cve] for cve in cves if cve in kev), None)

            vector = enrich.cvss_vector(vuln)
            fixed_version = info["fixed_version"]
            if is_kernel and fixed_version:
                remediation = (
                    f"install linux-image-* >= {fixed_version} and reboot "
                    f"(running kernel {os_release() or 'unknown'})"
                )
            elif is_kernel:
                remediation = "no fixed kernel version published in OSV data"
            elif fixed_version:
                remediation = f"upgrade {source} to {fixed_version} or later"
            else:
                remediation = "no fixed version published in OSV data"

            finding = {
                "cve": cves[0],
                "cve_ids": cves,
                "osv_id": vuln_id,
                "summary": vuln.get("summary") or "",
                "package": sorted({p.name for p in affected_packages}),
                "source_package": source,
                "installed_version": version,
                "fixed_version": fixed_version,
                "fix_status": info["fix_status"],
                "remediation": remediation,
                "asset": "kernel" if is_kernel else "package",
                "ubuntu_priority": enrich.ubuntu_priority(vuln),
                "cvss_vector": vector,
                "cvss_score": enrich.cvss3_score(vector),
                "epss": round(best_epss["epss"], 4) if best_epss else None,
                "epss_percentile": round(best_epss["percentile"], 4) if best_epss else None,
                "kev": kev_entry,
                "availability": info["availability"],
                "executables": sorted(set(executables))[:20],
                "libraries": sorted(set(libraries))[:20],
                "references": _references(vuln),
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
            }
            if is_kernel and kernel:
                finding["kernel"] = kernel
            finding["risk"] = enrich.risk_bucket(finding)
            finding["actionable"] = bool(
                info["fix_status"] == "fixed" or kev_entry
            )
            findings.append(finding)

    findings.sort(key=enrich.sort_key)
    return findings


def os_release() -> str | None:
    try:
        with open("/proc/sys/kernel/osrelease") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _library_paths(inventory: Inventory, package_key: str) -> list[str]:
    """Shared-library files owned by a package (exposure is indirect but real)."""
    paths = []
    for record in inventory.files.values():
        if record.package != package_key:
            continue
        if record.elf and not record.executable and ".so" in record.path:
            paths.append(record.path)
    return paths


def _references(vuln: dict) -> list[dict]:
    refs = []
    seen = set()
    for reference in vuln.get("references") or []:
        url = reference.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        refs.append({"type": reference.get("type", "WEB"), "url": url})
    osv_url = f"https://osv.dev/vulnerability/{vuln.get('id', '')}"
    if osv_url not in seen:
        refs.insert(0, {"type": "OSV", "url": osv_url})
    return refs
