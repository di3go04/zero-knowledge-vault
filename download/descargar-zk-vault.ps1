# =====================================================================
# Zero-Knowledge Vault — Descargador de archivos para auditoría
# =====================================================================
# Script: PowerShell para Windows 11
#
# Descarga los archivos clave del repositorio para auditoría de código
# y los organiza en una carpeta dentro de Descargas.
#
# USO:
#   1. Guarda este archivo como: descargar-zk-vault.ps1
#   2. Abre PowerShell (Win+X → Terminal)
#   3. Navega a la carpeta donde guardaste el script
#   4. Ejecuta:
#       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#       .\descargar-zk-vault.ps1
#
# El script crea la carpeta:
#   C:\Users\<tu-usuario>\Downloads\zk-vault-audit\
#
# Y descarga dentro los archivos organizados en subcarpetas.
# =====================================================================

# --- Configuracion ---------------------------------------------------
$Repo       = "di3go04/zero-knowledge-vault"
$Branch     = "main"
$RawBase    = "https://raw.githubusercontent.com/$Repo/$Branch"
$OutputBase = Join-Path $env:USERPROFILE "Downloads\zk-vault-audit"

# --- Lista de archivos a descargar ----------------------------------
# Formato: @{ Source = "ruta/en/repo"; Dest = "subcarpeta/destino" }
$Files = @(
    # 1. Configuracion y nucleo
    @{ Source = "package.json";                              Dest = "01-config\package.json" }
    @{ Source = "tsconfig.json";                             Dest = "01-config\tsconfig.json" }
    @{ Source = "next.config.ts";                            Dest = "01-config\next.config.ts" }
    @{ Source = "prisma/schema.prisma";                      Dest = "01-config\schema.prisma" }

    # 2. Criptografia
    @{ Source = "src/lib/crypto-client.ts";                  Dest = "02-crypto\crypto-client.ts" }
    @{ Source = "src/lib/crypto-server.ts";                  Dest = "02-crypto\crypto-server.ts" }
    # key-management.ts NO EXISTE — alternativa: key-rotation.ts
    @{ Source = "src/lib/key-rotation.ts";                   Dest = "02-crypto\key-rotation.ts (alternativa a key-management)" }
    @{ Source = "src/lib/pq-kem-real.ts";                    Dest = "02-crypto\pq-kem-real.ts" }
    @{ Source = "src/lib/memory-zero.ts";                    Dest = "02-crypto\memory-zero.ts" }
    @{ Source = "src/lib/subkey-derivation.ts";              Dest = "02-crypto\subkey-derivation.ts" }

    # 3. Backend (rutas API)
    @{ Source = "src/app/api/auth/register/route.ts";        Dest = "03-backend\auth-register-route.ts" }
    @{ Source = "src/app/api/auth/login/route.ts";           Dest = "03-backend\auth-login-route.ts" }
    @{ Source = "src/app/api/secrets/route.ts";              Dest = "03-backend\secrets-route.ts" }
    # middleware.ts NO EXISTE — el proyecto no usa middleware de Next.js
    # Se descarga layout.tsx como punto de entrada del servidor
    @{ Source = "src/app/layout.tsx";                        Dest = "03-backend\layout.tsx (no hay middleware.ts)" }

    # 4. Frontend (paginas principales)
    @{ Source = "src/app/page.tsx";                          Dest = "04-frontend\page.tsx" }
    # login/page.tsx NO EXISTE — la autenticacion es por componente AuthView
    @{ Source = "src/components/AuthView.tsx";               Dest = "04-frontend\AuthView.tsx (no hay login/page.tsx)" }
    @{ Source = "src/components/VaultView.tsx";              Dest = "04-frontend\VaultView.tsx" }
    # dashboard/SecretList.tsx NO EXISTE — equivalentes son los dialogos
    @{ Source = "src/components/ViewSecretDialog.tsx";       Dest = "04-frontend\ViewSecretDialog.tsx (alternativa a SecretList)" }
    @{ Source = "src/components/CreateSecretDialog.tsx";     Dest = "04-frontend\CreateSecretDialog.tsx" }

    # 5. Extras recomendados para auditoria
    @{ Source = "AUDITING.md";                               Dest = "05-audit\AUDITING.md" }
    @{ Source = "SECURITY_CHECKLIST.md";                     Dest = "05-audit\SECURITY_CHECKLIST.md" }
    @{ Source = "ARCHITECTURE.md";                           Dest = "05-audit\ARCHITECTURE.md" }
    @{ Source = "docs/AI_AUDIT_PROMPT.md";                   Dest = "05-audit\AI_AUDIT_PROMPT.md" }
    @{ Source = "docs/SECURITY_AUDIT_REPORT.md";             Dest = "05-audit\SECURITY_AUDIT_REPORT.md" }
    @{ Source = "scripts/crypto-audit.mjs";                  Dest = "05-audit\crypto-audit.mjs" }
    @{ Source = "scripts/zk-property-audit.mjs";             Dest = "05-audit\zk-property-audit.mjs" }
    @{ Source = "semgrep.yml";                               Dest = "05-audit\semgrep.yml" }
    @{ Source = ".gitleaks.toml";                            Dest = "05-audit\gitleaks.toml" }
    @{ Source = "README.md";                                 Dest = "05-audit\README.md" }
)

# --- Preparar carpeta destino ---------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Knowledge Vault - Descargador de auditoria"        -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repo origen:   https://github.com/$Repo"                  -ForegroundColor Gray
Write-Host "Branch:        $Branch"                                    -ForegroundColor Gray
Write-Host "Destino:       $OutputBase"                                -ForegroundColor Gray
Write-Host ""

# Limpiar carpeta si ya existe (con confirmacion)
if (Test-Path $OutputBase) {
    $resp = Read-Host "La carpeta ya existe. Borrar y recrear? (s/N)"
    if ($resp -eq "s" -or $resp -eq "S") {
        Remove-Item -Recurse -Force $OutputBase
        Write-Host "Carpeta anterior eliminada" -ForegroundColor Yellow
    } else {
        Write-Host "Se mantendra la carpeta existente (se sobreescribiran archivos)" -ForegroundColor Yellow
    }
}

# Crear estructura de subcarpetas
$subfolders = @("01-config", "02-crypto", "03-backend", "04-frontend", "05-audit")
foreach ($sub in $subfolders) {
    $path = Join-Path $OutputBase $sub
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# --- Descargar archivos ---------------------------------------------
$okCount = 0
$failCount = 0
$failed = @()

Write-Host ""
Write-Host "Descargando $($Files.Count) archivos..." -ForegroundColor Cyan
Write-Host ""

foreach ($f in $Files) {
    $url  = "$RawBase/$($f.Source)"
    $dest = Join-Path $OutputBase $f.Dest

    # Crear subcarpeta destino si no existe
    $destDir = Split-Path $dest -Parent
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # Extraer nombre corto para mostrar
    $shortName = Split-Path $f.Dest -Leaf

    try {
        # Forzar TLS 1.2 para compatibilidad con GitHub
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Intentar descarga
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] $shortName" -ForegroundColor Green
        $okCount++
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg.Length -gt 80) { $errMsg = $errMsg.Substring(0, 80) }
        Write-Host "  [FAIL] $shortName - $errMsg" -ForegroundColor Red
        $failCount++
        $failed += $f.Source
    }
}

# --- Resumen ---------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Resumen"                                               -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Descargados: $okCount"                                  -ForegroundColor Green
Write-Host "  Fallidos:    $failCount"                                -ForegroundColor $(if ($failCount -gt 0) {"Red"} else {"Gray"})
Write-Host "  Carpeta:     $OutputBase"                               -ForegroundColor Gray
Write-Host ""

if ($failed.Count -gt 0) {
    Write-Host "Archivos no descargados:" -ForegroundColor Yellow
    foreach ($fa in $failed) {
        Write-Host "  - $fa" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Posibles causas:" -ForegroundColor Gray
    Write-Host "  - El archivo no existe en el repo (verificar nombre)" -ForegroundColor Gray
    Write-Host "  - El commit 10378cc aun no se ha subido a GitHub"     -ForegroundColor Gray
    Write-Host "  - Problemas de red / proxy corporativo"               -ForegroundColor Gray
    Write-Host ""
    Write-Host "Si el commit aun no esta en GitHub, ejecuta primero:" -ForegroundColor Yellow
    Write-Host "  bash scripts/push-to-github.sh --ssh"                 -ForegroundColor Yellow
    Write-Host "  (o sube el repo manualmente con git push origin main)"
    Write-Host ""
}

# Abrir la carpeta en Explorer
Write-Host "Abriendo carpeta en Explorer..." -ForegroundColor Cyan
Start-Process explorer.exe $OutputBase

Write-Host ""
Write-Host "Listo. Ahora puedes:" -ForegroundColor Green
Write-Host "  1. Revisar manualmente los archivos en 01-config/ a 04-frontend/" -ForegroundColor Gray
Write-Host "  2. Leer AUDITING.md y SECURITY_CHECKLIST.md en 05-audit/" -ForegroundColor Gray
Write-Host "  3. Pasar docs/AI_AUDIT_PROMPT.md + los archivos del core a un LLM" -ForegroundColor Gray
Write-Host "     para obtener 30+ hallazgos estructurados." -ForegroundColor Gray
Write-Host ""
Read-Host "Presiona Enter para salir"
