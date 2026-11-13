"""Console and JSON rendering."""

from __future__ import annotations

import json
from pathlib import Path


def _shorten(text: str, width: int) -> str:
    text = str(text)
    if len(text) <= width:
        return text
    return text[: width - 1] + "\u2026"


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = []
    header_line = "  ".join(header.ljust(widths[i]) for i, header in enumerate(headers))
    lines.append(header_line)
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines).rstrip()


def render_console(report: dict, limit: int = 25) -> str:
    system = report["system"]
    inventory = report["inventory"]
    data = report["data"]
    summary = report["summary"]
    findings = report["findings"]

    lines = []
    lines.append(
        f"cvehunt {report['tool']['version']} | {report['scan']['hostname']} | "
        f"{system['distro']['pretty']}"
    )
    lines.append(
        f"ecosystem {system['ecosystem']} | "
        f"{inventory['packages']} packages, {inventory['executables']} executables "
        f"({inventory['elf_executables']} ELF), {inventory['unowned_elf']} unowned ELF"
    )
    sources = []
    if data["osv"]["ok"]:
        sources.append(f"OSV Ubuntu/Debian tracker data ({data['osv']['vuln_records']} records)")
    if data["epss"]["ok"]:
        sources.append(f"EPSS ({data['epss']['hits']} scored)")
    if data["kev"]["ok"]:
        sources.append(f"CISA KEV ({data['kev']['entries']} catalog entries)")
    lines.append(f"data: {' + '.join(sources) or 'none available'} | {report['scan']['duration_s']:.1f}s")

    by_risk = summary["by_risk"]
    risk_text = ", ".join(f"{k}={v}" for k, v in sorted(by_risk.items()) if v) or "none"
    fixable = summary["fixable"]
    lines.append("")
    lines.append(
        f"FINDINGS: {summary['cves']} CVEs across {summary['packages_with_findings']} source packages "
        f"| KEV={summary['kev']} | actionable={summary['actionable']} | "
        f"fixable={summary['fixable']} | no-fix={summary['unfixed']}"
    )
    lines.append(f"risk: {risk_text}")

    if findings:
        lines.append("")
        rows = []
        for finding in findings[:limit]:
            fix = finding["fixed_version"] or ("no fix" if finding["fix_status"] == "unfixed" else "unknown")
            if finding.get("asset") == "kernel":
                executable = "kernel image (reboot required)"
            else:
                executable = finding["executables"][0] if finding["executables"] else (
                    finding["libraries"][0] if finding["libraries"] else "-"
                )
            rows.append(
                [
                    finding["risk"],
                    finding["cve"],
                    f"{finding['cvss_score']:.1f}" if finding["cvss_score"] is not None else "-",
                    f"{finding['epss']:.3f}" if finding["epss"] is not None else "-",
                    "yes" if finding["kev"] else "-",
                    _shorten(f"{finding['source_package']} {finding['installed_version']}", 42),
                    _shorten(fix, 22),
                    _shorten(executable, 34),
                ]
            )
        lines.append(
            _table(
                rows,
                ["RISK", "CVE", "CVSS", "EPSS", "KEV", "PACKAGE (installed)", "FIX", "EXECUTABLE"],
            )
        )
        if len(findings) > limit:
            lines.append(f"... {len(findings) - limit} more findings in the JSON report")

        lines.append("")
        lines.append("TOP FINDINGS WITH REFERENCES")
        for finding in findings[: min(3, limit)]:
            lines.append("")
            label = f"{finding['cve']}  ({finding['source_package']} {finding['installed_version']}"
            if finding["fixed_version"]:
                label += f" -> fix {finding['fixed_version']})"
            elif finding["fix_status"] == "unfixed":
                label += ", no fixed version published)"
            else:
                label += ")"
            if finding["kev"]:
                label += f"  [KEV {finding['kev']['dateAdded']}]"
            lines.append(label)
            for reference in finding["references"][:6]:
                lines.append(f"   {reference['url']}")

    if inventory["unowned_elf"]:
        lines.append("")
        lines.append(f"UNOWNED ELF EXECUTABLES ({inventory['unowned_elf']}) -- needs manual review")
        for entry in report["unowned"][:10]:
            hints = ", ".join(entry["hints"]) if entry["hints"] else "no version hints"
            lines.append(f"   {_shorten(entry['path'], 60)}  [{hints}]")
        if inventory["unowned_elf"] > 10:
            lines.append(f"   ... see report.json")

    if report.get("warnings"):
        lines.append("")
        lines.append("WARNINGS")
        for warning in report["warnings"]:
            lines.append(f"   - {warning}")

    return "\n".join(lines)


def write_json(report: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=2) + "\n")
