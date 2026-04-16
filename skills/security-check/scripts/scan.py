#!/usr/bin/env python3
"""Orchestrator for the /security-check skill.

Usage:
    python3 scan.py [--project-root PATH] [--severity LEVEL]

Reads lock files in the project root, queries OSV.dev in batch, cross-checks
CVE IDs against CISA KEV, and emits a normalised JSON report on stdout.

The skill's SKILL.md instructs Claude to parse this JSON and produce the
markdown report, ask the user for confirmation, then optionally run the
update commands directly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from parsers import detect_and_parse
from sources import fetch_cisa_kev, fetch_osv_vuln, query_osv_batch

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNKNOWN": 0}


def parse_semver(version: str) -> tuple[int, int, int] | None:
    """Parse a semver string into (major, minor, patch).

    Returns None for unparseable versions (dev branches, weird formats).
    """
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def classify_bump(current: str, target: str) -> str:
    """Return 'patch' | 'minor' | 'major' | 'unknown'."""
    c = parse_semver(current)
    t = parse_semver(target)
    if not c or not t:
        return "unknown"
    if t[0] != c[0]:
        return "major"
    if t[1] != c[1]:
        return "minor"
    return "patch"


def extract_severity(osv_record: dict) -> str:
    """Map the OSV severity vector to a simple level."""
    database = osv_record.get("database_specific", {}) or {}
    level = database.get("severity")
    if level:
        return level.upper()
    # Fallback — check CVSS score
    severities = osv_record.get("severity", [])
    for sev in severities:
        score = sev.get("score", "")
        # Accept numeric CVSS or vector
        m = re.search(r"(\d+\.\d+)", score)
        if m:
            val = float(m.group(1))
            if val >= 9.0:
                return "CRITICAL"
            if val >= 7.0:
                return "HIGH"
            if val >= 4.0:
                return "MODERATE"
            return "LOW"
    return "UNKNOWN"


def extract_fixed_version(
    osv_record: dict, package_name: str, ecosystem: str, current_version: str
) -> str | None:
    """Find the fixed version relevant for our *current* version.

    OSV ranges come as sequences of events (introduced, fixed, last_affected).
    A vuln that spans several branches has several ranges; we want the "fixed"
    from the branch that matches the installed version.

    Strategy:
      1. Parse all (introduced, fixed) pairs for our package.
      2. Keep the pair whose [introduced, fixed) window contains current_version.
      3. Fallback: smallest fixed >= current_version.
      4. Last resort: smallest fixed available (same as old behaviour).
    """
    current = parse_semver(current_version)
    if not current:
        return None

    pairs: list[tuple[tuple[int, int, int] | None, tuple[int, int, int], str]] = []
    for affected in osv_record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package_name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            introduced: tuple[int, int, int] | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = parse_semver(event["introduced"])
                elif "fixed" in event:
                    fixed_parsed = parse_semver(event["fixed"])
                    if fixed_parsed:
                        pairs.append((introduced, fixed_parsed, event["fixed"]))
                    introduced = None  # reset for next pair

    if not pairs:
        return None

    # 1. Matching branch — current is in [introduced, fixed)
    for introduced, fixed_parsed, fixed_str in pairs:
        if introduced is None or introduced <= current < fixed_parsed:
            if introduced is None:
                # "0" introduced — only keep if current < fixed
                if current < fixed_parsed:
                    return fixed_str
            else:
                return fixed_str

    # 2. Smallest fixed >= current
    above = [(f, s) for _, f, s in pairs if f > current]
    if above:
        above.sort(key=lambda x: x[0])
        return above[0][1]

    # 3. Fallback
    pairs.sort(key=lambda x: x[1])
    return pairs[0][2]


def extract_cve_ids(osv_record: dict) -> list[str]:
    aliases = osv_record.get("aliases", [])
    return [a for a in aliases if a.startswith("CVE-")]


def run_scan(project_root: Path, min_severity: str) -> dict:
    """Main entry — returns a JSON-serialisable report."""
    inventory = detect_and_parse(project_root)
    if not inventory:
        return {
            "status": "no_lockfile",
            "message": "No composer.lock or package-lock.json/yarn.lock/pnpm-lock.yaml found.",
            "ecosystems": [],
            "findings": [],
            "summary": {"total": 0, "patch": 0, "minor": 0, "major": 0, "no_fix": 0},
        }

    all_packages = [pkg for pkgs in inventory.values() for pkg in pkgs]
    osv_batch = query_osv_batch(all_packages)
    kev_cves = fetch_cisa_kev()

    min_sev_rank = SEVERITY_ORDER.get(min_severity.upper(), 0)
    findings: list[dict] = []
    vuln_record_cache: dict[str, dict | None] = {}

    for pkg, vulns in zip(all_packages, osv_batch):
        for vuln_summary in vulns:
            vuln_id = vuln_summary.get("id")
            if not vuln_id:
                continue
            if vuln_id not in vuln_record_cache:
                vuln_record_cache[vuln_id] = fetch_osv_vuln(vuln_id)
            record = vuln_record_cache[vuln_id]
            if not record:
                continue

            severity = extract_severity(record)
            if SEVERITY_ORDER.get(severity, 0) < min_sev_rank:
                continue

            fixed_version = extract_fixed_version(
                record, pkg["name"], pkg["ecosystem"], pkg["version"]
            )
            bump = classify_bump(pkg["version"], fixed_version) if fixed_version else "none"
            cve_ids = extract_cve_ids(record)
            exploited = any(cve in kev_cves for cve in cve_ids)

            findings.append({
                "package": pkg["name"],
                "ecosystem": pkg["ecosystem"],
                "current_version": pkg["version"],
                "fixed_version": fixed_version,
                "bump": bump,
                "severity": severity,
                "vuln_id": vuln_id,
                "cve_ids": cve_ids,
                "summary": record.get("summary", "")[:200],
                "references": [r.get("url") for r in record.get("references", []) if r.get("url")][:3],
                "cisa_kev": exploited,
                "dev": pkg.get("dev", False),
            })

    findings.sort(
        key=lambda f: (
            -1 if f["cisa_kev"] else 0,
            -SEVERITY_ORDER.get(f["severity"], 0),
            f["package"],
        )
    )

    summary = {
        "total": len(findings),
        "patch": sum(1 for f in findings if f["bump"] == "patch"),
        "minor": sum(1 for f in findings if f["bump"] == "minor"),
        "major": sum(1 for f in findings if f["bump"] == "major"),
        "no_fix": sum(1 for f in findings if f["bump"] == "none"),
        "cisa_kev": sum(1 for f in findings if f["cisa_kev"]),
    }

    return {
        "status": "ok",
        "ecosystems": list(inventory.keys()),
        "package_count": len(all_packages),
        "findings": findings,
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan project dependencies for known CVEs.")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--severity",
        default="LOW",
        help="Minimum severity to report: LOW | MODERATE | HIGH | CRITICAL",
    )
    args = parser.parse_args()

    report = run_scan(args.project_root, args.severity)
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
