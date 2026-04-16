# claude-skill-security-check

Skill [Claude Code](https://claude.com/product/claude-code) pour auditer les dépendances d'un projet contre les CVE publiques et appliquer les correctifs sûrs en un clic.

Inspiré des recommandations Anthropic sur la [préparation aux attaques accélérées par IA](https://claude.com/blog/preparing-your-security-program-for-ai-accelerated-offense) : fermer le patch gap, prioriser les CVE activement exploitées (CISA KEV), automatiser le triage.

## Ce que fait le skill

Quand tu tapes `/security-check` dans Claude Code depuis un projet :

1. **Détection auto** des lock files : `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
2. **Scan** des paquets installés contre [OSV.dev](https://osv.dev/) (base unifiée qui agrège GHSA, Packagist, npm, PyPI, etc.)
3. **Cross-check** des CVE remontées avec le catalogue [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) pour flagger celles qui sont exploitées dans la nature
4. **Résolution sémantique** : pour chaque vulnérabilité, identifie la plus petite version corrigée dans la bonne branche semver (ex : 7.1.11 → 7.3.7, pas 5.4.50)
5. **Classification** du bump requis : `patch` / `minor` / `major` / `pas de correctif`
6. **Rapport markdown** trié par sévérité, avec indicateur 🔥 sur les CVE exploitées
7. **Application automatique** (si `--apply`) des bumps patch et minor via `composer update` ou `npm update`, après confirmation. **Les majors restent toujours manuels** pour éviter les risque de breaking change et/ou de dépendances incompatibles.

## Installation

### Rapide (recommandée)

```bash
git clone https://github.com/Motchouk/claude-skill-security-check.git
cd claude-skill-security-check
./install.sh              # niveau utilisateur → ~/.claude/skills/security-check/
```

Après redémarrage Claude Code (ou recharge de la session).

### Options d'installation

```bash
./install.sh --project    # Installer dans le projet courant (./.claude/skills/)
./install.sh --force      # Écraser une install existante sans prompt
./install.sh --uninstall  # Supprimer l'installation (user + project)
```

### Installation manuelle

```bash
# Niveau utilisateur
mkdir -p ~/.claude/skills/security-check
cp -R skills/security-check/* ~/.claude/skills/security-check/

# Ou niveau projet
mkdir -p .claude/skills/security-check
cp -R skills/security-check/* .claude/skills/security-check/
```

### Prérequis

- **Python 3.8+** — uniquement la stdlib, aucun `pip install` requis
- **Claude Code** (desktop, CLI ou IDE extension)
- Accès réseau vers `api.osv.dev` et `www.cisa.gov`
- Pour `--apply` : `composer` et/ou `npm`/`yarn`/`pnpm` disponibles localement ou via `make exec`

## Usage

```
/security-check                       # Rapport seul (dry-run)
/security-check --severity HIGH       # Filtre: HIGH + CRITICAL uniquement
/security-check --apply               # Applique les bumps patch/minor après confirmation
```

### Exemple de sortie

```
# Rapport sécurité — 2026-04-16

> 203 paquets scannés dans Packagist.
> 3 vulnérabilités détectées : 0 patch, 2 minor, 1 major, 0 sans correctif.
> 0 exploitées activement (CISA KEV).

## Actions recommandées

### À appliquer automatiquement (patch + minor)

| Sévérité | Paquet | Actuelle → Corrigée | Bump | KEV | CVE |
|---|---|---|---|---|---|
| **HIGH** | `aws/aws-sdk-php` | 3.369.24 → 3.371.4 | minor |  | [GHSA-27qh-8cxx-2cr5](...) |
| **HIGH** | `symfony/http-foundation` | 7.1.11 → 7.3.7 | minor |  | [CVE-2025-64500](...) |

### À revoir manuellement (major bumps / pas de correctif)

| Sévérité | Paquet | Actuelle → Corrigée | Raison | Détails |
|---|---|---|---|---|
| **HIGH** | `phpoffice/phpspreadsheet` | 4.5.0 → 5.0.0 | breaking changes probables | [CVE-2025-54370](...) |
```

## Architecture

```
claude-skill-security-check/
├── .claude-plugin/
│   └── plugin.json                 # Manifest plugin Claude Code
├── skills/
│   └── security-check/
│       ├── SKILL.md                # Procédure suivie par Claude
│       └── scripts/
│           ├── scan.py             # Orchestrateur (sortie JSON)
│           ├── parsers.py          # composer.lock + package-lock/yarn/pnpm
│           └── sources.py          # Clients OSV.dev + CISA KEV
├── install.sh                      # Installeur
├── CHANGELOG.md
├── LICENSE                         # GPL-3.0
└── README.md
```

**Zéro dépendance externe** : tout tient dans la stdlib Python 3.8+.

## Sources de vulnérabilités

| Source | Rôle | Pourquoi ce choix |
|---|---|---|
| [OSV.dev](https://osv.dev/) | Détection des CVE | Base unifiée multi-écosystèmes (GHSA + Packagist + npm + …), API batch sans auth |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Priorisation | Catalogue officiel des CVE exploitées dans la nature, mis à jour quotidiennement |

Le catalogue KEV est mis en cache 24 h dans `/tmp/security-check-cache/` pour éviter les requêtes répétées. Override possible via `SECURITY_CHECK_CACHE_DIR`.

## Limites connues

- **CVE fraîches** : les advisories publiées il y a moins de 24 h peuvent ne pas être encore indexées dans OSV.
- **Contraintes strictes** : si `composer.json` / `package.json` bloque un bump (ex. `"^5.0"` pour une version corrigée en 6.x), il faut assouplir la contrainte à la main. Le skill le signale mais ne modifie pas ces fichiers.
- **Majors non appliqués** : choix volontaire pour éviter les breaking changes.
- **Hors scope** : images Docker, extensions PHP natives, paquets système. Utiliser [Trivy](https://trivy.dev/) ou [Grype](https://github.com/anchore/grype) en complément.

## Portabilité

Le skill fonctionne sur les type de projets suivants :

- **Backend PHP** (Composer)
- **Frontend JS** (npm/yarn/pnpm seul)
- **Fullstack** (PHP + JS dans le même répository) — agrégé dans un seul rapport
- **Projet en conteneur Docker** (ex. Symfony + FrankenPHP) — détecte automatiquement `make exec` si disponible

## Contribuer

Les issues et PR sont bienvenues :

- Nouveaux écosystèmes (PyPI, RubyGems, Cargo, Go modules) — OSV.dev les supporte déjà, il faut ajouter un parser dédié
- Export du rapport (JSON, SARIF, HTML)
- Intégration CI (GitHub Actions, GitLab CI)

## Licence

[GPL-3.0](LICENSE)

## Crédits

- Sources de données : [OSV.dev](https://osv.dev/) (Google), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Inspiration : Anthropic, *[Preparing your security program for AI-accelerated offense](https://claude.com/blog/preparing-your-security-program-for-ai-accelerated-offense)*
