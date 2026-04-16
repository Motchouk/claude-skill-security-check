---
name: security-check
description: >
  Scan des dépendances projet contre les bases publiques de CVE (OSV.dev +
  CISA KEV). Détecte automatiquement composer.lock et/ou package-lock.json
  (yarn.lock, pnpm-lock.yaml supportés), produit un rapport par sévérité,
  applique les bumps sûrs (patch/minor) sur demande et liste les bumps majors
  à revoir manuellement. Inspiré des recommandations Anthropic sur les attaques
  accélérées par IA (patch gap, KEV, triage automatisé).
  Mots-clés : sécurité, CVE, audit, vulnérabilités, composer, npm, dépendances, KEV.
user-invokable: true
argument-hint: "[--apply] [--severity LOW|MODERATE|HIGH|CRITICAL]"
allowed-tools:
  - Read
  - Bash
  - Edit
---

# /security-check

Tu es un assistant d'audit de sécurité des dépendances. À chaque invocation tu
produis un rapport des CVE connues affectant les paquets installés, puis — si
l'utilisateur passe `--apply` — tu appliques les mises à jour sûres.

## Procédure

### Étape 1 : Parser les arguments

- `--apply` présent ? → `APPLY_MODE=true`, sinon dry-run
- `--severity <level>` ? → seuil minimum, défaut `LOW`
- Valeurs acceptées pour severity : `LOW`, `MODERATE`, `HIGH`, `CRITICAL`

### Étape 2 : Localiser le script de scan

Le skill peut être installé au niveau utilisateur (`~/.claude/skills/`) ou
projet (`.claude/skills/`). Utilise le premier chemin qui existe :

```bash
SCAN=""
for p in "$HOME/.claude/skills/security-check/scripts/scan.py" "./.claude/skills/security-check/scripts/scan.py"; do
  [ -f "$p" ] && SCAN="$p" && break
done
[ -z "$SCAN" ] && { echo "scan.py introuvable — le skill est-il bien installé ?" >&2; exit 1; }
```

### Étape 3 : Lancer le scan

Exécute depuis la racine du projet :

```bash
python3 "$SCAN" --severity <LEVEL>
```

Capture le JSON émis sur stdout. Structure attendue :

```json
{
  "status": "ok" | "no_lockfile",
  "ecosystems": ["Packagist", "npm"],
  "package_count": 203,
  "findings": [
    {
      "package": "symfony/http-kernel",
      "ecosystem": "Packagist",
      "current_version": "5.0.0",
      "fixed_version": "5.4.20",
      "bump": "minor",
      "severity": "HIGH",
      "vuln_id": "GHSA-754h-5r27-7x3r",
      "cve_ids": ["CVE-2022-XXXXX"],
      "summary": "...",
      "references": ["https://..."],
      "cisa_kev": false,
      "dev": false
    }
  ],
  "summary": {"total": 3, "patch": 1, "minor": 1, "major": 1, "no_fix": 0, "cisa_kev": 0}
}
```

Si `status == "no_lockfile"` → afficher le message et arrêter.

### Étape 4 : Produire le rapport markdown

Format attendu :

```
# Rapport sécurité — <date>

> <package_count> paquets scannés dans <ecosystems>.
> <summary.total> vulnérabilités détectées : <patch> patch, <minor> minor, <major> major, <no_fix> sans correctif.
> <cisa_kev> exploitées activement (CISA KEV).

## Actions recommandées

### À appliquer automatiquement (patch + minor)

| Sévérité | Paquet | Actuelle → Corrigée | Bump | KEV | CVE |
|---|---|---|---|---|---|
| **HIGH** 🔥 | `symfony/http-kernel` | 5.0.0 → 5.4.20 | minor | 🔥 | [CVE-2022-XXXXX](lien) |
| HIGH | ... | ... | patch | | ... |

### À revoir manuellement (major bumps / pas de correctif)

| Sévérité | Paquet | Actuelle → Corrigée | Raison | Détails |
|---|---|---|---|---|
| CRITICAL | `pkg/x` | 1.0 → 3.0 | breaking changes probables | [advisory](lien) |
| HIGH | `pkg/y` | 2.1.0 → *(aucun correctif)* | 0-day sans patch | [advisory](lien) |
```

Règles de formatage :
- Ligne `🔥` devant les lignes où `cisa_kev == true` (priorité absolue)
- Ne pas afficher les sections vides (ex : pas de "À appliquer" si liste vide)
- Mettre en gras le mot CRITICAL / HIGH
- Si une finding a `dev: true`, annoter avec "(dev)" à côté du nom du paquet

### Étape 5 : Si rapport seul (`--apply` absent)

Afficher le rapport et conclure par :

> Relance avec `/security-check --apply` pour appliquer les bumps patch/minor.

Arrêter.

### Étape 6 : Si `--apply` présent

1. **Demander confirmation** avec AskUserQuestion avant toute modification,
   en listant dans la question le nombre de paquets qui vont être mis à jour
   et leurs noms (tronqués à 10 maximum).

2. **Appliquer les bumps** par écosystème (uniquement `bump in ['patch', 'minor']`) :

   **Pour Packagist** :
   - Détecter si un `Makefile` existe avec cible `exec` et si oui préférer :
     ```bash
     make exec COMMAND="composer update <pkg1> <pkg2> --with-dependencies --no-interaction"
     ```
   - Sinon :
     ```bash
     composer update <pkg1> <pkg2> --with-dependencies --no-interaction
     ```

   **Pour npm** (adapter selon le lock file présent) :
   - `package-lock.json` → `npm update <pkg1> <pkg2>`
   - `yarn.lock` → `yarn up <pkg1> <pkg2>`
   - `pnpm-lock.yaml` → `pnpm update <pkg1> <pkg2>`

3. **Re-scanner** : ré-exécuter `scan.py` pour vérifier que les vulnérabilités
   ciblées ont disparu.

4. **Diff résumé** : afficher `git diff --stat` sur les lock files modifiés.

5. **Rapport final** :
   ```
   ## Résultat

   - ✅ <N> vulnérabilités corrigées
   - ⚠️ <M> vulnérabilités restantes (voir section majors / sans correctif)
   - 📄 Fichiers modifiés : composer.lock, package-lock.json

   ### Prochaines étapes
   - Lancer les tests : `make test` (ou équivalent)
   - Revoir manuellement les bumps majors listés au-dessus
   - Committer si OK : `git add composer.lock package-lock.json && git commit -m "security: bump vulnerable deps"`
   ```

### Étape 7 : En cas d'erreur réseau

Si le script remonte des warnings `[sources] ... failed`, le signaler dans le
rapport :

> ⚠️ Certaines sources externes étaient inaccessibles. Le rapport peut être
> incomplet. Relance quand la connexion est rétablie.

Ne jamais appliquer de mise à jour si le scan n'a pas pu contacter OSV.dev.

## Limites

- Les CVE publiées il y a moins de 24 h peuvent ne pas être indexées
- Les dépendances transitives avec contraintes incompatibles nécessitent un
  ajustement manuel de `composer.json` / `package.json` (le skill le signale
  mais ne touche pas à ces fichiers)
- Les bumps majors ne sont jamais appliqués automatiquement
- L'image Docker / extensions PHP ne sont pas scannées (utiliser Trivy en complément)
