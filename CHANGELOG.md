# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-16

### Added
- Initial release of the `/security-check` skill for Claude Code.
- Multi-ecosystem dependency scanning: Composer, npm, Yarn, pnpm.
- OSV.dev integration for unified CVE lookup across Packagist and npm.
- CISA KEV integration to flag actively exploited CVEs (24 h cache).
- Semver-aware fix version resolution: picks the correct branch fix.
- Bump classification: patch / minor / major / no-fix.
- `--apply` mode to auto-apply safe (patch/minor) bumps after confirmation.
- `--severity` filter (LOW / MODERATE / HIGH / CRITICAL).
- `install.sh` supporting user-level, project-level, force overwrite and uninstall.
- Claude Code plugin manifest (`.claude-plugin/plugin.json`).
- Zero pip dependencies — Python 3.8+ stdlib only.
