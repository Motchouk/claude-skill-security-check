#!/usr/bin/env bash
# Installer pour le skill Claude Code /security-check.
#
# Usage:
#   ./install.sh                 # Install au niveau utilisateur (~/.claude/skills/)
#   ./install.sh --project       # Install au niveau projet (./.claude/skills/)
#   ./install.sh --uninstall     # Supprime l'installation (détecte auto user/project)
#   ./install.sh --force         # Écrase une install existante sans prompt
#
# Prérequis: Python 3.8+ et bash.

set -euo pipefail

SKILL_NAME="security-check"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SKILL="$SCRIPT_DIR/skills/$SKILL_NAME"

MODE="user"
FORCE=0
UNINSTALL=0

for arg in "$@"; do
    case "$arg" in
        --user) MODE="user" ;;
        --project) MODE="project" ;;
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^# //;s/^#$//'
            exit 0
            ;;
        *)
            echo "Argument inconnu: $arg" >&2
            exit 1
            ;;
    esac
done

c_red()   { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
c_blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

# --- Resolve target directory ---
if [ "$MODE" = "user" ]; then
    TARGET_ROOT="$HOME/.claude/skills"
else
    TARGET_ROOT="$(pwd)/.claude/skills"
fi
TARGET="$TARGET_ROOT/$SKILL_NAME"

# --- Uninstall path ---
if [ "$UNINSTALL" -eq 1 ]; then
    removed=0
    for candidate in "$HOME/.claude/skills/$SKILL_NAME" "$(pwd)/.claude/skills/$SKILL_NAME"; do
        if [ -d "$candidate" ]; then
            rm -rf "$candidate"
            c_green "Supprimé: $candidate"
            removed=1
        fi
    done
    [ "$removed" -eq 0 ] && c_yellow "Rien à désinstaller."
    exit 0
fi

# --- Pre-flight checks ---
if ! command -v python3 >/dev/null 2>&1; then
    c_red "Python 3 est requis mais n'a pas été trouvé dans le PATH."
    exit 1
fi

PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)')
if [ "$PY_OK" != "1" ]; then
    c_red "Python 3.8+ requis. Version détectée: $(python3 --version 2>&1)"
    exit 1
fi

if [ ! -d "$SOURCE_SKILL" ]; then
    c_red "Dossier source introuvable: $SOURCE_SKILL"
    c_red "Lance ce script depuis la racine du dépôt cloné."
    exit 1
fi

# --- Guard against overwrite ---
if [ -e "$TARGET" ] && [ "$FORCE" -ne 1 ]; then
    c_yellow "Une installation existe déjà à: $TARGET"
    printf "Écraser ? [y/N] "
    read -r reply < /dev/tty
    case "$reply" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Annulé."; exit 0 ;;
    esac
fi

# --- Install ---
mkdir -p "$TARGET_ROOT"
rm -rf "$TARGET"
cp -R "$SOURCE_SKILL" "$TARGET"
chmod +x "$TARGET/scripts/scan.py" 2>/dev/null || true

c_green "✓ Skill installé dans: $TARGET"
echo
c_blue "Prochaines étapes:"
echo "  1. Redémarre Claude Code (ou recharge la session) pour que le skill soit détecté."
echo "  2. Depuis un projet contenant composer.lock ou package-lock.json, tape:"
echo "       /security-check                     # rapport seul"
echo "       /security-check --severity HIGH     # filtre"
echo "       /security-check --apply             # applique les bumps patch/minor"
echo
if [ "$MODE" = "user" ]; then
    c_blue "Install utilisateur: le skill est dispo dans tous tes projets."
else
    c_blue "Install projet: le skill est dispo uniquement dans ce repo."
    c_yellow "Pense à ajouter .claude/skills/$SKILL_NAME/ à .gitignore si tu ne veux pas le versionner."
fi
