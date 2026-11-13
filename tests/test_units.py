"""Unit tests for the parts where correctness is non-negotiable."""

from __future__ import annotations

import shutil
import subprocess
import unittest

from cvehunt.debver import compare, smallest_newer
from cvehunt.enrich import cves_for, fix_info, cvss3_score

CASES = [
    ("1.0", "1.0"),
    ("1.0~rc1", "1.0"),
    ("1.0~", "1.0"),
    ("1.0-1", "1.0-2"),
    ("2:1.0", "1:9.9"),
    ("1.0+esm1", "1.0"),
    ("8.18.0-1ubuntu2.8", "8.18.0-1ubuntu2.10"),
    ("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3"),
    ("1.0a", "1.0"),
    ("1.0-0ubuntu1", "1.0-0ubuntu1.1"),
    ("3.5.5-1ubuntu3.7", "3.5.5-1ubuntu3"),
    ("1.0~~", "1.0~"),
    ("0.9", "1.0"),
    ("1.0+b1", "1.0"),
]


class DebianVersionTest(unittest.TestCase):
    def test_known_order(self):
        self.assertLess(compare("1.0~rc1", "1.0"), 0)
        self.assertLess(compare("1.0~", "1.0"), 0)
        self.assertGreater(compare("2:1.0", "1:9.9"), 0)
        self.assertGreater(compare("3.5.5-1ubuntu3.7", "3.5.5-1ubuntu3"), 0)
        self.assertEqual(compare("1.0", "1.0"), 0)

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg not available")
    def test_against_dpkg(self):
        for left, right in CASES:
            less = subprocess.run(
                ["dpkg", "--compare-versions", left, "lt", right]
            ).returncode == 0
            equal = subprocess.run(
                ["dpkg", "--compare-versions", left, "eq", right]
            ).returncode == 0
            expected = -1 if less else (0 if equal else 1)
            self.assertEqual(
                compare(left, right), expected, f"mismatch for {left!r} vs {right!r}"
            )

    def test_smallest_newer(self):
        self.assertEqual(
            smallest_newer(["3.5.5-1ubuntu3.9", "3.5.5-1ubuntu3", "3.5.5-1ubuntu4"], "3.5.5-1ubuntu3.7"),
            "3.5.5-1ubuntu3.9",
        )
        self.assertIsNone(smallest_newer(["3.5.5-1ubuntu3.1"], "3.5.5-1ubuntu3.7"))


class EnrichTest(unittest.TestCase):
    def test_cve_derivation(self):
        self.assertEqual(cves_for({"id": "UBUNTU-CVE-2026-107496"}), ["CVE-2026-107496"])
        self.assertEqual(cves_for({"id": "DEBIAN-CVE-2024-1234"}), ["CVE-2024-1234"])
        self.assertEqual(
            cves_for({"id": "GHSA-xxxx", "aliases": ["CVE-2024-9999"]}), ["CVE-2024-9999"]
        )

    def test_fix_info_distinguishes_fixed_and_unfixed(self):
        fixed_record = {
            "affected": [
                {
                    "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "openssl"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "3.5.5-1ubuntu3.8"}],
                        }
                    ],
                    "ecosystem_specific": {
                        "binaries": [{"binary_name": "openssl", "binary_version": "3.5.5-1ubuntu3.8"}]
                    },
                }
            ]
        }
        info = fix_info(fixed_record, "Ubuntu:26.04:LTS", "3.5.5-1ubuntu3.7")
        self.assertEqual(info["fix_status"], "fixed")
        self.assertEqual(info["fixed_version"], "3.5.5-1ubuntu3.8")
        self.assertIn("openssl", info["binaries"])

        unfixed_record = {
            "affected": [
                {
                    "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "openssl"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "ecosystem_specific": {"binaries": [{"binary_name": "openssl"}]},
                }
            ]
        }
        info = fix_info(unfixed_record, "Ubuntu:26.04:LTS", "3.5.5-1ubuntu3.7")
        self.assertEqual(info["fix_status"], "unfixed")
        self.assertIsNone(info["fixed_version"])

        wrong_eco = dict(fixed_record)
        info = fix_info(wrong_eco, "Ubuntu:24.04:LTS", "3.5.5-1ubuntu3.7")
        self.assertFalse(info["matched"])

    def test_fix_info_isolates_package_variants(self):
        # A kernel CVE has one affected entry per kernel variant. Only the entry
        # for the queried source package may influence the fix status: otherwise
        # linux-aws's higher revision makes the generic kernel look fixed.
        record = {
            "affected": [
                {
                    "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "linux"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.0.0-42.42"}]}
                    ],
                },
                {
                    "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "linux-aws"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.0.0-1016.17"}]}
                    ],
                },
            ]
        }
        generic = fix_info(record, "Ubuntu:26.04:LTS", "7.0.0-38.38", package_name="linux")
        self.assertEqual(generic["fixed_version"], "7.0.0-42.42")
        aws = fix_info(record, "Ubuntu:26.04:LTS", "7.0.0-38.38", package_name="linux-aws")
        self.assertEqual(aws["fixed_version"], "7.0.0-1016.17")
        other = fix_info(record, "Ubuntu:26.04:LTS", "7.0.0-38.38", package_name="linux-gcp")
        self.assertFalse(other["matched"])

    def test_cvss_scores(self):
        # Reference values from the CVSS v3.1 specification.
        self.assertEqual(
            cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8
        )
        self.assertEqual(
            cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H"), 6.1
        )
        self.assertEqual(
            cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1
        )


if __name__ == "__main__":
    unittest.main()
