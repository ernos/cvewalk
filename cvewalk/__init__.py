"""cvewalk -- host-level CVE scanner with per-executable attribution.

Design summary:
  1. inventory installed packages (dpkg) and every ELF/executable file
  2. map files -> binary package -> source package (authoritative provenance)
  3. query distro-aware vulnerability data (OSV Ubuntu/Debian ecosystems) by
     source package + source version, so backported fixes are accounted for
  4. enrich with EPSS + CISA KEV and report CVE ids with references, ranked
"""

__version__ = "0.2.0"
