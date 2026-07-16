#!/usr/bin/env bash
# =====================================================================
# push-to-github.sh — Push the local repo to GitHub from your machine.
#
# This script is needed because the sandboxed build environment cannot
# authenticate against GitHub directly (no credentials available).
#
# USAGE (from your local machine, after cloning this project):
#
#   # Option A: HTTPS with Personal Access Token (PAT)
#   export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
#   bash push-to-github.sh
#
#   # Option B: SSH (if you have an SSH key set up with GitHub)
#   bash push-to-github.sh --ssh
#
#   # Option C: Already configured git credentials
#   bash push-to-github.sh --default
#
# PREREQUISITES:
#   - git installed
#   - A GitHub account with write access to di3go04/zero-knowledge-vault
#   - Either a PAT (with `repo` scope) or an SSH key registered with GitHub
# =====================================================================

set -euo pipefail

REPO_URL_HTTPS="https://github.com/di3go04/zero-knowledge-vault.git"
REPO_URL_SSH="git@github.com:di3go04/zero-knowledge-vault.git"

MODE="${1:---default}"

case "$MODE" in
  --ssh)
    echo "▶ Configuring remote to SSH..."
    git remote set-url origin "$REPO_URL_SSH"
    ;;
  --default)
    # Leave remote as-is
    :
    ;;
  *)
    if [[ "$MODE" == --token ]] && [[ -n "${GH_TOKEN:-}" ]]; then
      echo "▶ Configuring remote to HTTPS with token..."
      git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/di3go04/zero-knowledge-vault.git"
    elif [[ -n "${GH_TOKEN:-}" ]]; then
      echo "▶ GH_TOKEN detected, configuring remote..."
      git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/di3go04/zero-knowledge-vault.git"
    else
      echo "Usage: $0 [--ssh|--token|--default]"
      echo "  --ssh     Use SSH (requires ~/.ssh/id_ed25519 registered with GitHub)"
      echo "  --token   Use GH_TOKEN env var (requires PAT with 'repo' scope)"
      echo "  --default Use existing git credentials (credential.helper)"
      exit 1
    fi
    ;;
esac

echo "▶ Current remote:"
git remote -v | head -2

echo ""
echo "▶ Current local commits (about to push):"
git log --oneline -5

echo ""
echo "▶ Pushing to origin main..."
git push origin main

echo ""
echo "▶ Pushing tags (if any)..."
git push origin main --tags || true

echo ""
echo "✓ Push complete."
echo ""
echo "Next steps:"
echo "  1. Visit https://github.com/di3go04/zero-knowledge-vault/actions"
echo "     to verify CI workflows run green (CI, CodeQL, Semgrep, Supply Chain, Secrets)."
echo "  2. Visit https://github.com/di3go04/zero-knowledge-vault/security/code-scanning"
echo "     to review SARIF findings from CodeQL/Semgrep/Snyk/Trivy/gitleaks."
echo "  3. Run a local audit:"
echo "       bun install && bun run audit:full"
echo "  4. Feed the audit report + docs/AI_AUDIT_PROMPT.md to an LLM"
echo "     to produce 30+ structured improvement findings."
