@echo off
REM =====================================================================
REM Zero-Knowledge Vault - Descargador simple con curl (Windows 11)
REM =====================================================================
REM
REM Windows 11 incluye curl por defecto, asi que este script funciona
REM sin necesidad de PowerShell ni configuracion previa.
REM
REM USO:
REM   1. Guarda este archivo como: descargar-zk-vault.bat
REM   2. Doble clic para ejecutarlo
REM
REM Crea la carpeta:
REM   C:\Users\<tu-usuario>\Downloads\zk-vault-audit\
REM =====================================================================

setlocal enabledelayedexpansion

set "REPO=di3go04/zero-knowledge-vault"
set "BRANCH=main"
set "RAWBASE=https://raw.githubusercontent.com/%REPO%/%BRANCH%"
set "OUTDIR=%USERPROFILE%\Downloads\zk-vault-audit"

echo.
echo ========================================================
echo   Zero-Knowledge Vault - Descargador (curl)
echo ========================================================
echo.
echo  Repo origen:  https://github.com/%REPO%
echo  Branch:       %BRANCH%
echo  Destino:      %OUTDIR%
echo.

REM Preguntar si borrar carpeta existente
if exist "%OUTDIR%" (
    set /p CONFIRM="La carpeta ya existe. Borrar y recrear? (s/N): "
    if /i "!CONFIRM!"=="s" (
        rmdir /s /q "%OUTDIR%"
        echo Carpeta anterior eliminada.
    )
)

REM Crear estructura de carpetas
mkdir "%OUTDIR%\01-config" 2>nul
mkdir "%OUTDIR%\02-crypto" 2>nul
mkdir "%OUTDIR%\03-backend" 2>nul
mkdir "%OUTDIR%\04-frontend" 2>nul
mkdir "%OUTDIR%\05-audit" 2>nul

set OK=0
set FAIL=0

echo.
echo Descargando archivos...
echo.

REM --- 1. Configuracion ---
call :download "package.json"                                    "01-config\package.json"
call :download "tsconfig.json"                                   "01-config\tsconfig.json"
call :download "next.config.ts"                                  "01-config\next.config.ts"
call :download "prisma/schema.prisma"                            "01-config\schema.prisma"

REM --- 2. Criptografia ---
call :download "src/lib/crypto-client.ts"                        "02-crypto\crypto-client.ts"
call :download "src/lib/crypto-server.ts"                        "02-crypto\crypto-server.ts"
call :download "src/lib/key-rotation.ts"                         "02-crypto\key-rotation.ts"
call :download "src/lib/pq-kem-real.ts"                          "02-crypto\pq-kem-real.ts"
call :download "src/lib/memory-zero.ts"                          "02-crypto\memory-zero.ts"
call :download "src/lib/subkey-derivation.ts"                    "02-crypto\subkey-derivation.ts"

REM --- 3. Backend ---
call :download "src/app/api/auth/register/route.ts"              "03-backend\auth-register-route.ts"
call :download "src/app/api/auth/login/route.ts"                 "03-backend\auth-login-route.ts"
call :download "src/app/api/secrets/route.ts"                    "03-backend\secrets-route.ts"
call :download "src/app/layout.tsx"                              "03-backend\layout.tsx"

REM --- 4. Frontend ---
call :download "src/app/page.tsx"                                "04-frontend\page.tsx"
call :download "src/components/AuthView.tsx"                     "04-frontend\AuthView.tsx"
call :download "src/components/VaultView.tsx"                    "04-frontend\VaultView.tsx"
call :download "src/components/ViewSecretDialog.tsx"             "04-frontend\ViewSecretDialog.tsx"
call :download "src/components/CreateSecretDialog.tsx"           "04-frontend\CreateSecretDialog.tsx"

REM --- 5. Extras de auditoria ---
call :download "AUDITING.md"                                     "05-audit\AUDITING.md"
call :download "SECURITY_CHECKLIST.md"                           "05-audit\SECURITY_CHECKLIST.md"
call :download "ARCHITECTURE.md"                                 "05-audit\ARCHITECTURE.md"
call :download "docs/AI_AUDIT_PROMPT.md"                         "05-audit\AI_AUDIT_PROMPT.md"
call :download "docs/SECURITY_AUDIT_REPORT.md"                   "05-audit\SECURITY_AUDIT_REPORT.md"
call :download "scripts/crypto-audit.mjs"                        "05-audit\crypto-audit.mjs"
call :download "scripts/zk-property-audit.mjs"                   "05-audit\zk-property-audit.mjs"
call :download "semgrep.yml"                                     "05-audit\semgrep.yml"
call :download ".gitleaks.toml"                                  "05-audit\gitleaks.toml"
call :download "README.md"                                       "05-audit\README.md"

echo.
echo ========================================================
echo   Resumen
echo ========================================================
echo   Descargados OK: %OK%
echo   Fallidos:       %FAIL%
echo   Carpeta:        %OUTDIR%
echo.

if %FAIL% gtr 0 (
    echo NOTA: Algunos archivos no se pudieron descargar.
    echo Posibles causas:
    echo   - El commit 10378cc no esta en GitHub todavia (ejecuta push-to-github.sh)
    echo   - El archivo no existe en el repo
    echo   - Problemas de red
    echo.
)

echo Abriendo carpeta en Explorer...
explorer "%OUTDIR%"

echo.
echo Listo. Para auditar:
echo   1. Lee AUDITING.md y SECURITY_CHECKLIST.md en 05-audit\
echo   2. Pasa docs/AI_AUDIT_PROMPT.md + los archivos del core a un LLM
echo.
pause
goto :eof

REM === Funcion de descarga ===
:download
set "SRC=%~1"
set "DST=%~2"
set "URL=%RAWBASE%/%SRC%"
set "FULLPATH=%OUTDIR%\%DST%"

curl -sL -o "%FULLPATH%" "%URL%"
if %ERRORLEVEL% equ 0 (
    if exist "%FULLPATH%" (
        for %%A in ("%FULLPATH%") do set "FSIZE=%%~zA"
        if !FSIZE! gtr 0 (
            echo   [OK] %DST%
            set /a OK+=1
        ) else (
            echo   [FAIL] %DST% - archivo vacio
            set /a FAIL+=1
        )
    ) else (
        echo   [FAIL] %DST% - no se creo
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] %DST% - error curl (%ERRORLEVEL%)
    set /a FAIL+=1
)
goto :eof
