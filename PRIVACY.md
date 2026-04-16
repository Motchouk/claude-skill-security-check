# Privacy Policy

**Last updated:** 2026-04-16
**Plugin:** claude-skill-security-check (v1.0.0)
**Maintainer:** Timothée Garnaud — https://github.com/Motchouk

## Summary

The `security-check` skill does not collect, store, or transmit personal data. It is a read-only dependency auditor that runs locally on your machine and contacts only two public data sources:

- **OSV.dev** (operated by Google LLC)
- **CISA KEV** (operated by the U.S. Cybersecurity and Infrastructure Security Agency)

No telemetry, analytics, or error reporting is sent to Anthropic, the plugin author, or any third party.

## 1. Data the skill reads locally

From the project directory in which `/security-check` is invoked, the skill reads:

- `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` — to build the list of installed packages and their versions.

No source code, credentials, environment variables, git history, or other file contents are read.

## 2. Data transmitted to third parties

### 2.1 OSV.dev (Google LLC)

- **Endpoint:** `POST https://api.osv.dev/v1/querybatch` and `GET https://api.osv.dev/v1/vulns/<vuln_id>`
- **What is sent:** batched tuples of `(package_name, ecosystem, version)`. Example: `("symfony/http-kernel", "Packagist", "5.0.0")`.
- **What is NOT sent:** project name, file paths, git metadata, machine identifiers, user identifiers, or any data beyond package coordinates.
- **Purpose:** query known vulnerabilities affecting the exact (package, version) pairs present in your lock files.
- **Provider privacy policy:** https://policies.google.com/privacy

### 2.2 CISA KEV (U.S. Cybersecurity and Infrastructure Security Agency)

- **Endpoint:** `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **What is sent:** a standard HTTPS GET with no body, no query parameters, and no custom identifiers.
- **Purpose:** download the public catalog of CVEs known to be actively exploited.
- **Provider privacy policy:** https://www.cisa.gov/privacy-policy

As with any HTTP request, your IP address is visible to the destination server. The skill does not add any identifying headers beyond a generic `User-Agent: security-check-skill/1.0`.

## 3. Local storage

- A verbatim copy of the CISA KEV catalog is cached at `/tmp/security-check-cache/cisa-kev.json` with a **24-hour TTL** to avoid repeated downloads. This cache contains only public data.
- The cache location can be overridden via the environment variable `SECURITY_CHECK_CACHE_DIR`.
- No other files are created or modified by the skill, **except** when you explicitly pass `--apply`. In that case the standard `composer update` / `npm update` / `yarn up` / `pnpm update` commands update your lock files in place.

## 4. What the skill does NOT do

- No telemetry, analytics, crash reporting, or usage tracking.
- No network calls other than those described in section 2.
- No data sent to Anthropic, the plugin author, or any third party besides OSV.dev and CISA.
- No cookies, tokens, or persistent identifiers.
- No background or scheduled activity — the skill only runs when you invoke `/security-check`.

## 5. Security

- All outbound requests use HTTPS with full certificate validation.
- The skill exposes no network listener and accepts no incoming connections.
- No API keys, authentication tokens, or credentials are used or stored.
- The skill code is open source under GPL-3.0 and auditable at the repository URL above.

## 6. Your rights

The skill does not process personal data, so rights under the GDPR (access, rectification, erasure, portability, objection) or similar frameworks do not apply in the usual sense.

If you nevertheless want to stop all processing, you can uninstall the skill at any time:

```bash
./install.sh --uninstall
```

Deleting `/tmp/security-check-cache/` also removes any locally cached data.

## 7. Children's privacy

The skill is not directed at children and does not knowingly process data related to children.

## 8. Changes to this policy

Material changes will be listed in `CHANGELOG.md` and reflected in this document with an updated "Last updated" date. The full revision history is publicly auditable via git:

```
https://github.com/Motchouk/claude-skill-security-check/commits/main/PRIVACY.md
```

## 9. Contact

For privacy-related questions or requests, open an issue on the project repository:

**https://github.com/Motchouk/claude-skill-security-check/issues**
