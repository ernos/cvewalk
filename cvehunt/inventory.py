"""Installed-package and executable-file inventory.

The scanner's accuracy comes from *provenance*: every file is attributed to
the dpkg binary package that owns it, and every binary package to its source
package.  Vulnerability data is keyed on the source package + source version,
which is what distro security trackers actually maintain.

Files that no package owns (``/usr/local``, ``/opt``, vendored/static builds)
cannot be mapped authoritatively.  For those we only extract non-executing
version hints and mark them as low-confidence; see ``fingerprint()``.
"""

from __future__ import annotations

import dataclasses
import glob
import os
import re
import subprocess
from pathlib import Path

DPKG_INFO = Path("/var/lib/dpkg/info")
ELF_MAGIC = b"\x7fELF"
ET_EXEC, ET_DYN = 2, 3
EM_NAMES = {62: "x86_64", 3: "i386", 183: "aarch64", 40: "arm", 243: "riscv64"}

# Directories where executable files live, and where shared libraries live.
EXEC_ROOTS = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/games",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/games",
    "/snap/bin",
    "/opt",
)
LIB_ROOTS = ("/usr/lib", "/lib", "/usr/lib64", "/lib64", "/usr/libexec")

# Version fingerprints for common statically-linked / vendored components.
# These are *hints only* -- never enough to declare a CVE match on their own.
_HINT_PATTERNS = (
    ("openssl", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("libressl", re.compile(rb"LibreSSL\s+(\d+\.\d+\.\d+)")),
    ("curl", re.compile(rb"curl\s+(\d+\.\d+\.\d+)")),
    ("zlib", re.compile(rb"zlib\s+(\d+\.\d+(?:\.\d+)?)")),
    ("libxml2", re.compile(rb"libxml2\s+(\d+\.\d+\.\d+)")),
    ("sqlite", re.compile(rb"SQLite\s+(\d+\.\d+\.\d+)")),
    ("python", re.compile(rb"Python\s+(\d+\.\d+\.\d+)")),
    ("node", re.compile(rb"Node\.js/v?(\d+\.\d+\.\d+)")),
)


@dataclasses.dataclass
class Package:
    name: str          # dpkg binary package, e.g. "libc6:amd64"
    version: str       # installed binary version
    arch: str
    source: str        # source package, e.g. "glibc"
    source_version: str
    status: str

    @property
    def base_name(self) -> str:
        """Binary package name without the :arch qualifier."""
        return self.name.split(":", 1)[0]

    @property
    def query_version(self) -> str:
        """Version to match against distro vulnerability data (source version)."""
        return self.source_version or self.version


@dataclasses.dataclass
class FileRecord:
    path: str           # canonical (realpath) path
    package: str | None  # dpkg binary package key, or None if unowned
    elf: bool
    e_type: int | None
    executable: bool    # ELF executable, or non-ELF file with +x in a bin dir
    size: int


@dataclasses.dataclass
class Inventory:
    packages: dict[str, Package]
    file_index: dict[str, str]              # path -> binary package key
    files: dict[str, FileRecord]            # realpath -> record
    unmatched: list[FileRecord]             # ELF files owned by no package

    @property
    def executables(self) -> list[FileRecord]:
        return [f for f in self.files.values() if f.executable and f.elf]

    def packages_for_source(self, source: str) -> list[Package]:
        return [p for p in self.packages.values() if p.source == source]

    def _executable_paths(self, package_key: str) -> list[str]:
        return [f.path for f in self.files.values() if f.package == package_key and f.executable]

    def executable_paths(self, package_key: str, limit: int = 8) -> list[str]:
        if not hasattr(self, "_exe_cache"):
            self._exe_cache: dict[str, list[str]] = {}
        if package_key not in self._exe_cache:
            self._exe_cache[package_key] = sorted(set(self._executable_paths(package_key)))
        return self._exe_cache[package_key][:limit]


def load_packages() -> dict[str, Package]:
    """Read installed packages from dpkg (fast: single subprocess)."""
    fmt = (
        "${binary:Package}\t${Version}\t${Architecture}\t"
        "${source:Package}\t${source:Version}\t${Status}\n"
    )
    proc = subprocess.run(
        ["dpkg-query", "-W", "-f", fmt],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):  # 1 == some packages had no status? still parse
        raise RuntimeError(f"dpkg-query failed: {proc.stderr.strip()}")
    packages: dict[str, Package] = {}
    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            continue
        name, version, arch, source, source_version, status = fields
        if "installed" not in status:
            continue
        source = source or name.split(":", 1)[0]
        packages[name] = Package(
            name=name,
            version=version,
            arch=arch,
            source=source,
            source_version=source_version or version,
            status=status,
        )
    return packages


def build_file_index(packages: dict[str, Package]) -> dict[str, str]:
    """path -> binary package key, from /var/lib/dpkg/info/*.list.

    Read directly from the info directory instead of shelling out to
    ``dpkg -S`` per file (which would be thousands of subprocesses).
    """
    index: dict[str, str] = {}
    for listfile in glob.glob(str(DPKG_INFO / "*.list")):
        key = Path(listfile).name[: -len(".list")]
        if key not in packages:
            continue
        try:
            text = Path(listfile).read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("/") or line in ("/", "/."):
                continue
            index[os.path.normpath(line.rstrip("/"))] = key
    return index


def _interesting(path: str) -> bool:
    return any(path == root or path.startswith(root + "/") for root in EXEC_ROOTS + LIB_ROOTS)


def _walk(root: str, max_depth: int):
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count("/") - base_depth >= max_depth:
            dirnames[:] = []
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def _elf_header(data: bytes) -> tuple[bool, int | None, int | None]:
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        return False, None, None
    e_type = int.from_bytes(data[16:18], "little")
    machine = int.from_bytes(data[18:20], "little")
    return True, e_type, machine


def _read_header(path: str, size: int) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(min(size, 64))
    except OSError:
        return b""


def _add_candidate(
    candidates: dict[str, str | None], path: str, index: dict[str, str]
) -> None:
    try:
        real = os.path.realpath(path)
    except OSError:
        return
    if real in candidates:
        return
    candidates[real] = index.get(real) or index.get(os.path.normpath(path))


def enumerate_files(
    packages: dict[str, Package],
    index: dict[str, str],
    extra_roots: list[str] | None = None,
) -> dict[str, FileRecord]:
    """Map every ELF file (and unowned executable) under the scanned roots.

    Two sources are unioned:
      * every dpkg-owned path in executable/library directories (complete for
        distro files, including libs and multi-arch variants)
      * a walk of bin/opt/snap/local roots to catch unowned files
    """
    candidates: dict[str, str | None] = {}
    for path, key in index.items():
        if _interesting(path):
            _add_candidate(candidates, path, index)

    roots = list(EXEC_ROOTS) + list(extra_roots or [])
    for root in roots:
        if not os.path.isdir(root):
            continue
        max_depth = 4 if root in ("/opt", "/usr/local", "/snap") else 2
        for found in _walk(root, max_depth):
            _add_candidate(candidates, found, index)

    records: dict[str, FileRecord] = {}
    for path in candidates:
        try:
            stat = os.stat(path)
        except OSError:
            continue
        if not os.path.isfile(path):
            continue
        header = _read_header(path, stat.st_size)
        elf, e_type, _machine = _elf_header(header)
        if not elf and not path.startswith(EXEC_ROOTS):
            continue
        executable = bool(stat.st_mode & 0o111) and (
            not elf or e_type in (ET_EXEC, ET_DYN)
        )
        records[path] = FileRecord(
            path=path,
            package=candidates[path],
            elf=elf,
            e_type=e_type,
            executable=executable,
            size=stat.st_size,
        )
    return records


def fingerprint(path: str) -> list[str]:
    """Best-effort version hints for a binary we cannot attribute to a package.

    Never executes the binary.  Results are deliberately low-confidence and are
    reported as "needs manual review" rather than as CVE matches.
    """
    hints: list[str] = []
    try:
        with open(path, "rb") as handle:
            data = handle.read(8 * 1024 * 1024)
    except OSError:
        return hints
    for name, pattern in _HINT_PATTERNS:
        match = pattern.search(data)
        if match:
            hints.append(f"{name} {match.group(1).decode('latin-1')}")
    go = re.search(rb"go1\.(\d+\.\d+(?:\.\d+)?)", data)
    if go:
        hints.append(f"go {go.group(1).decode('latin-1')}")
    gcc = re.search(rb"GCC: \(.*?\) (\d+\.\d+\.\d+)", data)
    if gcc:
        hints.append(f"gcc {gcc.group(1).decode('latin-1')}")
    return hints


def load(extra_roots: list[str] | None = None) -> Inventory:
    packages = load_packages()
    index = build_file_index(packages)
    files = enumerate_files(packages, index, extra_roots)
    executable_keys = {
        record.package for record in files.values() if record.executable and record.package
    }
    unmatched = [
        record
        for record in files.values()
        if record.elf and record.executable and record.package is None
    ]
    del executable_keys
    return Inventory(
        packages=packages,
        file_index=index,
        files=files,
        unmatched=sorted(unmatched, key=lambda r: r.path),
    )
