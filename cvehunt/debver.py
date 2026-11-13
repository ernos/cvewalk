"""Debian/Ubuntu version comparison, following dpkg(7) semantics.

A Debian version is ``[epoch:]upstream_version[-debian_revision]``.  Epoch
dominates, then the upstream part, then the revision.  Inside a part the
ordering of characters is: ``~`` (sorts before everything, even the empty
string), the empty string, letters (ASCII order), then all other characters
(ASCII order + 256).  Runs of digits compare numerically, everything else
lexicographically.

This matters because distro version strings are *not* semver: ``1.0~rc1`` is
older than ``1.0``, and ``3.5.5-1ubuntu3.7`` is newer than ``3.5.5-1ubuntu3``.
"""

from __future__ import annotations


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if _is_digit(ch):
        return 0
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return ord(ch)
    return ord(ch) + 256


def _cmp_fragment(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # Compare the leading non-digit run character by character.
        while (i < len(a) and not _is_digit(a[i])) or (j < len(b) and not _is_digit(b[j])):
            ca = a[i] if i < len(a) and not _is_digit(a[i]) else ""
            cb = b[j] if j < len(b) and not _is_digit(b[j]) else ""
            oa, ob = _order(ca), _order(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca:
                i += 1
            if cb:
                j += 1
        # Compare the digit run numerically (ignore leading zeros).
        si, sj = i, j
        while i < len(a) and _is_digit(a[i]):
            i += 1
        while j < len(b) and _is_digit(b[j]):
            j += 1
        na = a[si:i].lstrip("0") or "0"
        nb = b[sj:j].lstrip("0") or "0"
        if len(na) != len(nb):
            return -1 if len(na) < len(nb) else 1
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, rest = version.split(":", 1)
        if head.isdigit():
            epoch = int(head)
            version = rest
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, ""
    return epoch, upstream, revision


def compare(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b (dpkg semantics)."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    result = _cmp_fragment(ua, ub)
    if result:
        return result
    return _cmp_fragment(ra, rb)


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0


def eq(a: str, b: str) -> bool:
    return compare(a, b) == 0


def smallest_newer(candidates: list[str], baseline: str) -> str | None:
    """Return the smallest candidate strictly newer than baseline, or None."""
    newer = [c for c in candidates if compare(c, baseline) > 0]
    if not newer:
        return None
    best = newer[0]
    for candidate in newer[1:]:
        if compare(candidate, best) < 0:
            best = candidate
    return best
