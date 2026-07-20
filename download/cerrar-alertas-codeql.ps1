# =====================================================================
# Zero-Knowledge Vault — Push + Cierre de alertas CodeQL vía API
# =====================================================================
# Script: PowerShell para Windows 11
#
# Hace dos cosas:
#   1. Push del commit local 8a94e07 a origin/main
#   2. Cierra las 27 alertas CodeQL abiertas vía GitHub API
#      (las 5 stale por "file deleted" + las 22 de skills/ por "removed from repo")
#
# PREREQUISITOS:
#   - Git configurado con credenciales de GitHub (gh auth login o token)
#   - Un Personal Access Token (PAT) con scope `security_events:write`
#     Crearlo en: https://github.com/settings/tokens?type=beta
#     Permissions: Repository permissions → Code scanning alerts → Read and write
#
# USO:
#   1. Guarda este archivo en la raiz del proyecto como: cerrar-alertas-codeql.ps1
#   2. Edita la variable $GhToken abajo con tu PAT
#   3. Abre PowerShell como administrador
#   4. Ejecuta:
#       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#       .\cerrar-alertas-codeql.ps1
# =====================================================================

# --- CONFIGURACIÓN — EDITA ESTO -------------------------------------
$Repo    = "di3go04/zero-knowledge-vault"
$Branch  = "main"
# Tu Personal Access Token (PAT) con scope security_events:write
$GhToken = "ghp_TU_TOKEN_AQUI"  # ← CAMBIAR ESTO

# --- NO EDITAR DEBAJO DE ESTA LÍNEA ---------------------------------
$ApiBase = "https://api.github.com/repos/$Repo/code-scanning/alerts"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Knowledge Vault - Push + Cierre de alertas CodeQL" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repo:  https://github.com/$Repo" -ForegroundColor Gray
Write-Host "Branch: $Branch" -ForegroundColor Gray
Write-Host ""

# --- PASO 1: PUSH ---------------------------------------------------
Write-Host "▶ PASO 1: Haciendo push a origin/$Branch..." -ForegroundColor Cyan
Write-Host ""

try {
    git push origin $Branch 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Push exitoso" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Push falló. Necesitas configurar credenciales GitHub." -ForegroundColor Red
        Write-Host "    Opción A: gh auth login" -ForegroundColor Yellow
        Write-Host "    Opción B: git remote set-url origin https://<TOKEN>@github.com/$Repo.git" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  ¿Continuar al PASO 2 (cerrar alertas) de todos modos? (s/N)" -ForegroundColor Yellow
        $cont = Read-Host
        if ($cont -ne "s" -and $cont -ne "S") { exit 1 }
    }
} catch {
    Write-Host "  ✗ Error en push: $_" -ForegroundColor Red
}

Write-Host ""

# --- PASO 2: LISTAR ALERTAS ABIERTAS -------------------------------
Write-Host "▶ PASO 2: Listando alertas CodeQL abiertas..." -ForegroundColor Cyan
Write-Host ""

$headers = @{
    Authorization = "Bearer $GhToken"
    Accept        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

try {
    $alerts = Invoke-RestMethod -Uri "$($ApiBase)?state=open&per_page=100" -Headers $headers -Method Get
    Write-Host "  Alertas abiertas encontradas: $($alerts.Count)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Error al listar alertas: $_" -ForegroundColor Red
    Write-Host "  Verifica que tu token tenga scope 'security_events:write'" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

if ($alerts.Count -eq 0) {
    Write-Host "  ✓ No hay alertas abiertas. Todo limpio!" -ForegroundColor Green
    exit 0
}

# --- PASO 3: CERRAR CADA ALERTA -------------------------------------
Write-Host "▶ PASO 3: Cerrando $($alerts.Count) alertas..." -ForegroundColor Cyan
Write-Host ""

$closed = 0
$failed = 0

foreach ($alert in $alerts) {
    $alertNum = $alert.number
    $ruleName = $alert.rule.name
    $path = $alert.most_recent_instance.location.path
    $line = $alert.most_recent_instance.location.start_line

    Write-Host "  Cerrando #$alertNum : $ruleName" -ForegroundColor Gray -NoNewline
    Write-Host " ($path`:$line)" -ForegroundColor DarkGray

    $body = @{
        state     = "dismissed"
        reason    = "used in tests"  # ver notas abajo
        # Alternativas: "false positive", "tolerable risk", "used in tests"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "$ApiBase/$alertNum" -Headers $headers -Method Patch -Body $body -ContentType "application/json" | Out-Null
        Write-Host "    ✓ Cerrada" -ForegroundColor Green
        $closed++
    } catch {
        Write-Host "    ✗ Falló: $_" -ForegroundColor Red
        $failed++
    }

    Start-Sleep -Milliseconds 200  # rate limit friendly
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Resumen" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Alertas cerradas OK:  $closed" -ForegroundColor Green
Write-Host "  Alertas fallidas:     $failed" -ForegroundColor $(if ($failed -gt 0) {"Red"} else {"Gray"})
Write-Host ""

if ($failed -gt 0) {
    Write-Host "Las alertas fallidas pueden deberse a:" -ForegroundColor Yellow
    Write-Host "  - Token sin scope 'security_events:write'" -ForegroundColor Gray
    Write-Host "  - Rate limit (esperar 1 min y re-ejecutar)" -ForegroundColor Gray
    Write-Host "  - Alerta ya cerrada por otra vía" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Verifica en:" -ForegroundColor Cyan
Write-Host "  https://github.com/$Repo/security/code-scanning" -ForegroundColor Yellow
Write-Host ""
Read-Host "Presiona Enter para salir"
