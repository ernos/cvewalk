"""Normalization + prioritization enrichment.

* derive canonical CVE ids from OSV records
* decide fix availability using Debian version comparison against the distro
  "fixed" events (this is what makes the tool backport-aware)
* compute CVSS v3.x base scores from vectors (records often only carry the
  vector, and Ubuntu records sometimes carry only a priority label)
* fetch EPSS and CISA KEV for exploit-likelihood ranking
"""

from __future__ import annotations

import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .debver import compare, smallest_newer

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "cvewalk/0.2 (+https://osv.dev)"

_CVE_RE = re.compile(r"^(?:UBUNTU-CVE|DEBIAN-CVE|CVE)-(\d{4})-(\d+)$")


# --------------------------------------------------------------------------
# CVE id derivation
# --------------------------------------------------------------------------
def cves_for(vuln: dict) -> list[str]:
    """Canonical CVE ids for an OSV record.

    Ubuntu/Debian records are keyed ``UBUNTU-CVE-YYYY-NNNN`` /
    ``DEBIAN-CVE-YYYY-NNNN`` and usually have no ``aliases`` field, so the id
    itself must be converted.
    """
    found: set[str] = set()
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            found.add(alias)
    match = _CVE_RE.match(vuln.get("id", ""))
    if match:
        found.add(f"CVE-{match.group(1)}-{match.group(2)}")
    return sorted(found)


# --------------------------------------------------------------------------
# severity
# --------------------------------------------------------------------------
def ubuntu_priority(vuln: dict) -> str | None:
    for entry in vuln.get("severity") or []:
        if entry.get("type") == "Ubuntu":
            return entry.get("score")
    return None


def cvss_vector(vuln: dict) -> str | None:
    preferred: str | None = None
    for entry in vuln.get("severity") or []:
        score = entry.get("score") or ""
        if entry.get("type", "").startswith("CVSS_V3") and score.startswith("CVSS:3"):
            return score
        if entry.get("type", "").startswith("CVSS_V4") and score.startswith("CVSS:4"):
            preferred = preferred or score
    return preferred


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_score(vector: str | None) -> float | None:
    """Base score for a CVSS v3.0/3.1 vector (spec section 7.1)."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    metrics = dict(
        part.split(":", 1) for part in vector.split("/")[1:] if ":" in part
    )
    try:
        changed = metrics["S"] == "C"
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
            * (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
            * _UI[metrics["UI"]]
        )
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            raw = min(1.08 * (impact + exploitability), 10.0)
        else:
            impact = 6.42 * iss
            raw = min(impact + exploitability, 10.0)
    except (KeyError, ValueError):
        return None
    if raw <= 0:
        return 0.0
    # CVSS uses "round up" to one decimal place.
    return math.ceil(round(raw, 6) * 10) / 10


# --------------------------------------------------------------------------
# fix availability (the backport-aware part)
# --------------------------------------------------------------------------
def match_affected(
    vuln: dict, ecosystem: str, package_name: str | None = None
) -> list[dict]:
    """Affected entries for the exact distro ecosystem and (source) package.

    Filtering on package name is essential: a kernel CVE record has an affected
    entry per kernel variant (linux-aws, linux-gcp, ...), each with its own
    fixed version.  Mixing them in makes the generic kernel look fixed when
    only, say, the AWS kernel was patched (their revision numbers compare
    numerically higher).
    """
    matched = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != ecosystem:
            continue
        if package_name is not None and package.get("name") != package_name:
            continue
        matched.append(affected)
    return matched


def fix_info(
    vuln: dict,
    ecosystem: str,
    installed_version: str,
    package_name: str | None = None,
) -> dict:
    """Return whether our installed distro version is fixed, pending, or unknown.

    OSV distro ranges use Debian version strings in ``fixed`` events.  If a
    fixed version greater than the installed version exists, an update fixes
    the CVE; if the record only has ``introduced: 0``, the distro has no fixed
    package (yet) and the CVE is genuinely present.
    """
    matched = match_affected(vuln, ecosystem, package_name)
    result = {
        "matched": bool(matched),
        "fixed_version": None,
        "fix_status": "unknown",
        "binaries": set(),
        "availability": None,
        "ubuntu_status": None,
    }
    if not matched:
        return result

    fixed_candidates: list[str] = []
    for affected in matched:
        specific = affected.get("ecosystem_specific") or {}
        if specific.get("availability") and not result["availability"]:
            result["availability"] = specific["availability"]
        for binary in specific.get("binaries") or []:
            name = binary.get("binary_name")
            if name:
                result["binaries"].add(name.split(":", 1)[0])
        for version_range in affected.get("ranges") or []:
            if version_range.get("type") != "ECOSYSTEM":
                continue
            for event in version_range.get("events") or []:
                fixed = event.get("fixed")
                if fixed and compare(fixed, installed_version) > 0:
                    fixed_candidates.append(fixed)

    fixed_version = smallest_newer(fixed_candidates, installed_version)
    if fixed_version:
        result["fixed_version"] = fixed_version
        result["fix_status"] = "fixed"
    else:
        result["fix_status"] = "unfixed"
    return result


# --------------------------------------------------------------------------
# EPSS / KEV
# --------------------------------------------------------------------------
def _http_json(url: str, timeout: int = 30) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def fetch_epss(
    cves: list[str],
    chunk_size: int = 50,
    cache_dir: str | Path | None = None,
    ttl: int = 24 * 3600,
) -> dict[str, dict]:
    """CVE -> {epss, percentile, date}. Unknown CVEs are simply absent.

    Scores are cached on disk for a day because EPSS updates daily and a full
    scan needs ~30 sequential API calls otherwise.
    """
    unique = sorted(set(cves))
    cache_file = Path(cache_dir) / "epss.json" if cache_dir else None
    cached: dict[str, dict | None] = {}
    if cache_file and cache_file.exists() and time.time() - cache_file.stat().st_mtime < ttl:
        try:
            cached = json.loads(cache_file.read_text())
        except (OSError, json.JSONDecodeError):
            cached = {}

    missing = [cve for cve in unique if cve not in cached]
    for start in range(0, len(missing), chunk_size):
        batch = missing[start : start + chunk_size]
        url = EPSS_URL + "?cve=" + urllib.parse.quote(",".join(batch))
        try:
            payload = _http_json(url)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
        for row in payload.get("data") or []:
            cached[row["cve"]] = {
                "epss": float(row.get("epss", 0.0)),
                "percentile": float(row.get("percentile", 0.0)),
                "date": row.get("date"),
            }
        for cve in batch:
            cached.setdefault(cve, None)  # remember "not scored" for the TTL

    if cache_file:
        try:
            cache_file.write_text(json.dumps(cached))
        except OSError:
            pass
    return {cve: cached[cve] for cve in unique if cached.get(cve)}


def fetch_kev(cache_dir: str | Path, ttl: int = 24 * 3600, refresh: bool = False) -> dict[str, dict]:
    """CISA Known Exploited Vulnerabilities catalog, cached for a day."""
    cache_file = Path(cache_dir) / "kev.json"
    payload: dict | None = None
    if not refresh and cache_file.exists() and time.time() - cache_file.stat().st_mtime < ttl:
        try:
            payload = json.loads(cache_file.read_text())
        except (OSError, json.JSONDecodeError):
            payload = None
    if payload is None:
        payload = _http_json(KEV_URL, timeout=60)
        try:
            cache_file.write_text(json.dumps(payload))
        except OSError:
            pass
    return {
        entry["cveID"]: {
            "dateAdded": entry.get("dateAdded"),
            "vendorProject": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerabilityName": entry.get("vulnerabilityName"),
            "knownRansomwareCampaignUse": entry.get("knownRansomwareCampaignUse"),
            "requiredAction": entry.get("requiredAction"),
        }
        for entry in payload.get("vulnerabilities") or []
        if entry.get("cveID")
    }


# --------------------------------------------------------------------------
# risk ordering
# --------------------------------------------------------------------------
def risk_bucket(finding: dict) -> str:
    if finding.get("kev"):
        return "EXPLOITED"
    score = finding.get("cvss_score") or 0.0
    priority = (finding.get("ubuntu_priority") or "").lower()
    if score >= 9.0 or priority == "critical":
        return "CRITICAL"
    if score >= 7.0 or priority == "high":
        return "HIGH"
    if score >= 4.0 or priority == "medium":
        return "MEDIUM"
    return "LOW"


def sort_key(finding: dict) -> tuple:
    """Actionable first: KEV, then a published fix, then exploit likelihood."""
    return (
        0 if finding.get("kev") else 1,
        0 if finding.get("actionable") else 1,
        -(finding.get("epss") or 0.0),
        -(finding.get("cvss_score") or 0.0),
        finding.get("cve") or finding.get("osv_id", ""),
    )
