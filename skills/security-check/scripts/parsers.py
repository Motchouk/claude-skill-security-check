"""Parsers for dependency lock files — Composer (PHP) and npm/yarn/pnpm (JS).

Each parser returns a normalised list of dicts:
    [{"name": "vendor/pkg", "version": "1.2.3", "ecosystem": "Packagist"}, ...]

Ecosystem values follow the OSV.dev specification
(https://ossf.github.io/osv-schema/#affectedpackage-field):
    - "Packagist" for PHP Composer
    - "npm" for Node.js
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def parse_composer_lock(path: Path) -> list[dict]:
    """Extract packages from composer.lock.

    Reads both "packages" (prod) and "packages-dev" sections.
    """
    with path.open() as fh:
        data = json.load(fh)

    packages = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            version = pkg.get("version", "")
            # Composer prefixes some releases with "v", normalise.
            if version.startswith("v"):
                version = version[1:]
            # Skip dev branches (e.g. "dev-main") — OSV cannot match them.
            if version.startswith("dev-"):
                continue
            packages.append({
                "name": pkg["name"],
                "version": version,
                "ecosystem": "Packagist",
                "dev": section == "packages-dev",
            })
    return packages


def parse_package_lock(path: Path) -> list[dict]:
    """Extract packages from package-lock.json (v1, v2, v3).

    v1: top-level "dependencies" tree
    v2/v3: flat "packages" map keyed by path (root is "")
    """
    with path.open() as fh:
        data = json.load(fh)

    lockfile_version = data.get("lockfileVersion", 1)
    packages: list[dict] = []

    if lockfile_version >= 2 and "packages" in data:
        for key, info in data["packages"].items():
            if key == "" or not info.get("version"):
                continue
            # Key looks like "node_modules/vendor/pkg" — extract after last "node_modules/"
            name = info.get("name")
            if not name:
                parts = key.split("node_modules/")
                name = parts[-1] if parts else key
            packages.append({
                "name": name,
                "version": info["version"],
                "ecosystem": "npm",
                "dev": bool(info.get("dev", False)),
            })
        return packages

    # v1 fallback — recursive walk of "dependencies"
    def walk(deps: dict, dev: bool = False) -> None:
        for name, info in deps.items():
            if "version" in info:
                packages.append({
                    "name": name,
                    "version": info["version"],
                    "ecosystem": "npm",
                    "dev": dev or bool(info.get("dev", False)),
                })
            nested = info.get("dependencies")
            if nested:
                walk(nested, dev=dev or bool(info.get("dev", False)))

    walk(data.get("dependencies", {}))
    return packages


_YARN_ENTRY = re.compile(r'^"?(?P<header>[^"\n]+?)"?:\s*$', re.MULTILINE)
_YARN_VERSION = re.compile(r'^\s+version\s+"?(?P<version>[^"\s]+)"?\s*$', re.MULTILINE)


def parse_yarn_lock(path: Path) -> list[dict]:
    """Extract packages from yarn.lock (classic v1 format).

    Each entry is a block like:
        "pkg@^1.0.0", "pkg@^1.2.0":
          version "1.2.3"
          ...
    """
    text = path.read_text()
    packages: list[dict] = []
    blocks = text.split("\n\n")
    for block in blocks:
        if not block.strip() or block.lstrip().startswith("#"):
            continue
        first_line = block.splitlines()[0].rstrip(":").strip()
        # First spec → extract the package name before "@"
        first_spec = first_line.split(",")[0].strip().strip('"')
        if first_spec.startswith("@"):
            # Scoped package: "@scope/name@range"
            at_pos = first_spec.rfind("@")
            name = first_spec[:at_pos]
        else:
            name = first_spec.split("@", 1)[0]

        m = _YARN_VERSION.search(block)
        if not m:
            continue
        packages.append({
            "name": name,
            "version": m.group("version"),
            "ecosystem": "npm",
            "dev": False,  # yarn.lock doesn't distinguish
        })
    return packages


def parse_pnpm_lock(path: Path) -> list[dict]:
    """Extract packages from pnpm-lock.yaml without requiring PyYAML.

    Uses a minimal parser that only reads the "packages:" top-level map,
    which is sufficient to enumerate resolved packages + versions.
    """
    text = path.read_text()
    packages: list[dict] = []
    in_packages = False
    # Match keys like "/vendor/pkg@1.2.3" or "/vendor/pkg/1.2.3"
    key_re = re.compile(r'^\s{2}[\'"]?/?(?P<spec>[^\'"\s:]+)[\'"]?:\s*$')

    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and stripped and not stripped.startswith(" "):
            break
        if not in_packages:
            continue
        m = key_re.match(line)
        if not m:
            continue
        spec = m.group("spec")
        # Split name and version — format varies: name@version or name/version
        if "@" in spec.lstrip("@"):
            # Handle scoped: @scope/name@version
            if spec.startswith("@"):
                at_pos = spec.rfind("@")
                name = spec[:at_pos]
                version = spec[at_pos + 1:]
            else:
                name, _, version = spec.rpartition("@")
        elif "/" in spec:
            name, _, version = spec.rpartition("/")
        else:
            continue
        # Strip peer dep suffixes like "1.2.3_react@18.0.0"
        version = version.split("(")[0].split("_")[0]
        packages.append({
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "dev": False,
        })
    return packages


def detect_and_parse(project_root: Path) -> dict[str, list[dict]]:
    """Walk the project root and parse every lock file found.

    Returns a dict keyed by ecosystem label, suitable for later dispatch.
    """
    results: dict[str, list[dict]] = {}

    composer = project_root / "composer.lock"
    if composer.exists():
        results["Packagist"] = parse_composer_lock(composer)

    # Prefer package-lock.json > yarn.lock > pnpm-lock.yaml to avoid double counting
    npm_lock = project_root / "package-lock.json"
    yarn_lock = project_root / "yarn.lock"
    pnpm_lock = project_root / "pnpm-lock.yaml"

    if npm_lock.exists():
        results["npm"] = parse_package_lock(npm_lock)
    elif yarn_lock.exists():
        results["npm"] = parse_yarn_lock(yarn_lock)
    elif pnpm_lock.exists():
        results["npm"] = parse_pnpm_lock(pnpm_lock)

    return results
