"""Thin OSV.dev client with an on-disk cache.

OSV is used because its Ubuntu/Debian ecosystems are derived from the distro
security trackers: a query returns only CVEs that affect the exact installed
*distro* package version, with the fixed version encoded as a Debian version
string.  That single property eliminates the classic false-positive flood you
get from matching upstream versions against NVD/CPE.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE_URL = "https://api.osv.dev"
USER_AGENT = "cvewalk/0.2 (+https://osv.dev)"


class OsvError(RuntimeError):
    pass


class OsvClient:
    def __init__(
        self,
        cache_dir: str | Path,
        timeout: int = 30,
        retries: int = 4,
        workers: int = 8,
        verbose: bool = False,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.retries = retries
        self.workers = workers
        self.verbose = verbose
        self._vuln_cache: dict[str, dict] = {}

    # -- low level ---------------------------------------------------------
    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = BASE_URL + path
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"User-Agent": USER_AGENT}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                if error.code in (429, 500, 502, 503, 504):
                    last_error = error
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise OsvError(f"OSV HTTP {error.code} for {path}") from error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last_error = error
                time.sleep(1.0 * (attempt + 1))
        raise OsvError(f"OSV request failed after {self.retries} attempts: {path}: {last_error}")

    def _cache_path(self, vuln_id: str) -> Path:
        digest = hashlib.sha256(vuln_id.encode()).hexdigest()[:32]
        return self.cache_dir / f"vuln-{digest}.json"

    # -- public api --------------------------------------------------------
    def query(self, queries: list[dict], chunk_size: int = 100) -> list[list[str]]:
        """Version-correct package queries; returns OSV ids for each query.

        Uses POST /v1/querybatch for throughput, but the batch endpoint caps and
        paginates results for very large packages (Ubuntu ``linux`` yields 1000
        ids + ``next_page_token`` that are *not* version-filtered -- the OSV docs
        themselves warn about "big OSV Linux queries").  For any query that
        paginates, fall back to POST /v1/query, which applies the version match
        correctly and returns full records (cached, so hydration is free).
        """
        results: list[list[str] | None] = [None] * len(queries)
        fallback: list[int] = []

        for start in range(0, len(queries), chunk_size):
            chunk = queries[start : start + chunk_size]
            response = self._request("/v1/querybatch", {"queries": chunk})
            chunk_results = response.get("results", [])
            if len(chunk_results) != len(chunk):
                raise OsvError(
                    f"OSV querybatch returned {len(chunk_results)} results for "
                    f"{len(chunk)} queries"
                )
            for offset, result in enumerate(chunk_results):
                index = start + offset
                ids = [vuln["id"] for vuln in result.get("vulns") or []]
                if result.get("next_page_token") or len(ids) >= 1000:
                    fallback.append(index)
                else:
                    results[index] = ids

        if fallback:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(self._query_single, queries[i]): i for i in fallback}
                for future, index in futures.items():
                    results[index] = future.result()

        return [ids or [] for ids in results]

    def _query_single(self, query: dict) -> list[str]:
        """POST /v1/query -- exact version matching, returns full records."""
        response = self._request("/v1/query", query)
        ids: list[str] = []
        for record in response.get("vulns") or []:
            vuln_id = record.get("id")
            if not vuln_id:
                continue
            ids.append(vuln_id)
            self._vuln_cache[vuln_id] = record
        return ids

    def get_vuln(self, vuln_id: str, refresh: bool = False, ttl: int = 12 * 3600) -> dict:
        if vuln_id in self._vuln_cache:
            return self._vuln_cache[vuln_id]
        cache_file = self._cache_path(vuln_id)
        if not refresh and cache_file.exists() and time.time() - cache_file.stat().st_mtime < ttl:
            try:
                data = json.loads(cache_file.read_text())
                self._vuln_cache[vuln_id] = data
                return data
            except (OSError, json.JSONDecodeError):
                pass
        data = self._request("/v1/vulns/" + urllib.parse.quote(vuln_id, safe=""))
        try:
            cache_file.write_text(json.dumps(data))
        except OSError:
            pass
        self._vuln_cache[vuln_id] = data
        return data

    def get_vulns(self, vuln_ids: list[str], refresh: bool = False) -> dict[str, dict]:
        """Fetch vuln records concurrently; returns id -> record."""
        unique = list(dict.fromkeys(vuln_ids))
        records: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.get_vuln, vid, refresh): vid for vid in unique}
            for future, vid in futures.items():
                try:
                    records[vid] = future.result()
                except OsvError as error:
                    raise OsvError(f"failed to fetch {vid}: {error}") from error
        return records
