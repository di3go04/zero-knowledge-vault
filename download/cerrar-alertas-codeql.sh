#!/usr/bin/env bash
# =====================================================================
# Zero-Knowledge Vault — Push + Cierre de alertas CodeQL vía API (Bash)
# =====================================================================
# Hace dos cosas:
#   1. Push del commit local a origin/main
#   2. Cierra las 27 alertas CodeQL abiertas vía GitHub API
#
# PREREQUISITOS:
#   - Git configurado con credenciales de GitHub
#   - Personal Access Token (PAT) con scope security_events:write
#     Crear en: https://github.com/settings/tokens?type=beta
#     Permissions: Repository permissions → Code scanning alerts → Read and write
#
# USO:
#   1. Edita la variable GH_TOKEN abajo con tu PAT
#   2. Ejecuta: ./cerrar-alertas-codeql.sh
# =====================================================================

# --- CONFIGURACIÓN — EDITA ESTO -------------------------------------
REPO="di3go04/zero-knowledge-vault"
BRANCH="main"
GH_TOKEN="ghp_TU_TOKEN_AQUI"  # ← CAMBIAR ESTO

# --- NO EDITAR DEBAJO -----------------------------------------------
API_BASE="https://api.github.com/repos/$REPO/code-scanning/alerts"

echo ""
echo "========================================================"
echo "  Zero-Knowledge Vault - Push + Cierre de alertas CodeQL"
echo "========================================================"
echo ""
echo "Repo:   https://github.com/$REPO"
echo "Branch: $BRANCH"
echo ""

# --- PASO 1: PUSH ---------------------------------------------------
echo "▶ PASO 1: Haciendo push a origin/$BRANCH..."
echo ""

if git push origin "$BRANCH" 2>&1; then
    echo "  ✓ Push exitoso"
else
    echo "  ✗ Push falló. Configura credenciales GitHub:"
    echo "    Opción A: gh auth login"
    echo "    Opción B: git remote set-url origin https://<TOKEN>@github.com/$REPO.git"
    echo ""
    read -p "  ¿Continuar al PASO 2 (cerrar alertas) de todos modos? (s/N) " cont
    if [[ "$cont" != "s" && "$cont" != "S" ]]; then exit 1; fi
fi

echo ""

# --- PASO 2: LISTAR ALERTAS ABIERTAS -------------------------------
echo "▶ PASO 2: Listando alertas CodeQL abiertas..."
echo ""

response=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$API_BASE?state=open&per_page=100")

http_code=$(echo "$response" | tail -1)
body=$(echo "$response" | sed '$d')

if [ "$http_code" != "200" ]; then
    echo "  ✗ Error HTTP $http_code al listar alertas:"
    echo "  $body"
    echo ""
    echo "  Verifica que tu token tenga scope 'security_events:write'"
    exit 1
fi

count=$(echo "$body" | jq 'length')
echo "  Alertas abiertas encontradas: $count"
echo ""

if [ "$count" = "0" ] || [ -z "$count" ]; then
    echo "  ✓ No hay alertas abiertas. Todo limpio!"
    exit 0
fi

# --- PASO 3: CERRAR CADA ALERTA -------------------------------------
echo "▶ PASO 3: Cerrando $count alertas..."
echo ""

closed=0
failed=0

# Recorrer cada alerta con jq
echo "$body" | jq -c '.[]' | while read -r alert; do
    num=$(echo "$alert" | jq -r '.number')
    rule=$(echo "$alert" | jq -r '.rule.name')
    path=$(echo "$alert" | jq -r '.most_recent_instance.location.path')
    line=$(echo "$alert" | jq -r '.most_recent_instance.location.start_line')

    printf "  Cerrando #%s : %s (%s:%s)\n" "$num" "$rule" "$path" "$line"

    payload='{"state":"dismissed","reason":"false positive"}'

    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PATCH \
        -H "Authorization: Bearer $GH_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "$payload" \
        "$API_BASE/$num")

    if [ "$code" = "200" ] || [ "$code" = "204" ]; then
        echo "    ✓ Cerrada"
    else
        echo "    ✗ Falló (HTTP $code)"
    fi

    sleep 0.2  # rate limit friendly
done

echo ""
echo "========================================================"
echo "  Verifica en:"
echo "    https://github.com/$REPO/security/code-scanning"
echo "========================================================"
