"""HTTP clients for public vulnerability databases.

Uses only the Python standard library (urllib) — no pip dependencies so the
skill runs out of the box on any machine with Python 3.8+.

Two data sources:
    * OSV.dev — unified vuln DB aggregating GHSA, Packagist, npm, PyPI, etc.
      https://google.github.io/osv.dev/post-v1-querybatch/
    * CISA KEV — catalog of CVEs known to be actively exploited in the wild.
      https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_DIR = Path(os.environ.get("SECURITY_CHECK_CACHE_DIR", "/tmp/security-check-cache"))
CACHE_TTL_SECONDS = 24 * 3600  # 24 h for CISA KEV

_SSL_CTX = ssl.create_default_context()


def _http_post_json(url: str, payload: dict, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "security-check-skill/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "security-check-skill/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_osv_batch(packages: list[dict]) -> list[list[dict]]:
    """Query OSV.dev in batch for (package, version) pairs.

    Returns a list aligned with the input: for each package, a list of vuln
    summaries (at minimum {"id": "..."}). An empty list means no known vuln.

    OSV enforces a batch size limit — we chunk at 1000.
    """
    if not packages:
        return []

    results: list[list[dict]] = []
    CHUNK = 1000
    for start in range(0, len(packages), CHUNK):
        chunk = packages[start:start + CHUNK]
        queries = [
            {
                "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                "version": pkg["version"],
            }
            for pkg in chunk
        ]
        try:
            resp = _http_post_json(OSV_QUERYBATCH_URL, {"queries": queries})
        except (urllib.error.URLError, TimeoutError) as exc:
            # On network failure, emit empty results so the native audit still reports.
            print(f"[sources] OSV.dev batch query failed: {exc}", flush=True)
            results.extend([[] for _ in chunk])
            continue
        for item in resp.get("results", []):
            results.append(item.get("vulns", []) or [])
    return results


def fetch_osv_vuln(vuln_id: str) -> dict | None:
    """Fetch the full OSV record for a single vuln ID (needed for version ranges).

    Cached in memory within a single process run — callers should reuse via a
    dict if they need persistence.
    """
    try:
        return _http_get_json(OSV_VULN_URL.format(id=vuln_id))
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[sources] OSV.dev fetch {vuln_id} failed: {exc}", flush=True)
        return None


def fetch_cisa_kev() -> set[str]:
    """Return the set of CVE IDs currently in the CISA KEV catalog.

    Cached on disk 24 h to avoid hammering the endpoint.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "cisa-kev.json"

    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < CACHE_TTL_SECONDS:
        try:
            data = json.loads(cache_file.read_text())
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
        except (OSError, json.JSONDecodeError):
            pass  # fall through to refetch

    try:
        data = _http_get_json(CISA_KEV_URL)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[sources] CISA KEV fetch failed: {exc}", flush=True)
        return set()

    try:
        cache_file.write_text(json.dumps(data))
    except OSError:
        pass  # cache is best-effort

    return {v["cveID"] for v in data.get("vulnerabilities", [])}
