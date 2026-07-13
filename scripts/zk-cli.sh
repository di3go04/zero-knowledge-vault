#!/usr/bin/env bash
# MEJORA 42/50: CLI tool para DevOps — gestión de secretos desde terminal.
# Uso: ./scripts/zk-cli.sh [command] [args]
#
# Comandos:
#   health        — verificar salud del servidor
#   metrics       — obtener métricas
#   export <id>   — exportar datos de usuario (requiere token)
#   purge-shares  — purgar shares expirados (admin)

set -euo pipefail

BASE_URL="${ZK_VAULT_URL:-http://localhost:3000}"
CMD="${1:-help}"

case "$CMD" in
  health)
    echo "🔍 Verificando salud del servidor..."
    curl -s "$BASE_URL/api/health" | python3 -m json.tool 2>/dev/null || curl -s "$BASE_URL/api/health"
    ;;
  metrics)
    echo "📊 Métricas del servidor:"
    curl -s "$BASE_URL/api/metrics" | python3 -m json.tool 2>/dev/null || curl -s "$BASE_URL/api/metrics"
    ;;
  purge-shares)
    echo "🧹 Purgando shares expirados..."
    echo "⚠️  Esto requiere acceso admin al servidor."
    echo "Ejecuta: bun run scripts/purge-shares.ts"
    ;;
  help|*)
    echo "Zero-Knowledge Vault CLI"
    echo ""
    echo "Comandos:"
    echo "  health        Verificar salud del servidor"
    echo "  metrics       Obtener métricas"
    echo "  purge-shares  Purgar shares expirados"
    echo "  help          Mostrar esta ayuda"
    echo ""
    echo "Variables:"
    echo "  ZK_VAULT_URL  URL del servidor (default: http://localhost:3000)"
    ;;
esac
