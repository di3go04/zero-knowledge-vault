@echo off
REM =====================================================================
REM Zero-Knowledge Vault - Concatenador a archivo unico de texto
REM =====================================================================
REM
REM Descarga todos los archivos clave y los combina en UN SOLO archivo
REM .txt listo para subir a un LLM (Claude, GPT, Gemini, etc.).
REM
REM USO: doble clic sobre este archivo .bat
REM
REM Salida:
REM   C:\Users\<tu-usuario>\Downloads\zk-vault-codigo-completo.txt
REM =====================================================================

setlocal enabledelayedexpansion

set "REPO=di3go04/zero-knowledge-vault"
set "BRANCH=main"
set "RAWBASE=https://raw.githubusercontent.com/%REPO%/%BRANCH%"
set "OUTDIR=%USERPROFILE%\Downloads"
set "OUTFILE=%OUTDIR%\zk-vault-codigo-completo.txt"
set "TMPDIR=%TEMP%\zk-vault-tmp"

echo.
echo ========================================================
echo   Zero-Knowledge Vault - Concatenador a texto unico
echo ========================================================
echo.
echo  Repo origen:  https://github.com/%REPO%
echo  Branch:       %BRANCH%
echo  Archivo out:  %OUTFILE%
echo.

REM Limpiar temporales y archivo final previo
if exist "%TMPDIR%" rmdir /s /q "%TMPDIR%"
mkdir "%TMPDIR%"
if exist "%OUTFILE%" del "%OUTFILE%"

set OK=0
set FAIL=0
set TOTAL_LINES=0
set TOTAL_BYTES=0

REM --- Encabezado del archivo unico ---
(
echo ================================================================================================
echo  ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
echo ================================================================================================
echo  Repositorio:  https://github.com/%REPO%
echo  Branch:       %BRANCH%
echo  Generado:     %DATE% %TIME%
echo  Total archivos: 27
echo.
echo  FORMATO:
echo    Cada archivo comienza con: ===== LABEL =====
echo    Y termina con: ----- fin del archivo -----
echo.
echo  USO:
echo    - Sube este archivo a Claude / GPT / Gemini / etc.
echo    - O abrela en tu editor para revision manual.
echo    - El prompt de auditoria esta al final del archivo.
echo ================================================================================================
echo.
echo.
) > "%OUTFILE%"

echo Descargando y concatenando archivos...
echo.

REM --- Lista de archivos: SOURCE|LABEL ---
REM 1. Configuracion
call :concat "package.json"                                     "CONFIG: package.json"
call :concat "tsconfig.json"                                    "CONFIG: tsconfig.json"
call :concat "next.config.ts"                                   "CONFIG: next.config.ts"
call :concat "prisma/schema.prisma"                             "DB SCHEMA: prisma/schema.prisma"

REM 2. Criptografia
call :concat "src/lib/crypto-client.ts"                         "CRYPTO CLIENT: src/lib/crypto-client.ts"
call :concat "src/lib/crypto-server.ts"                         "CRYPTO SERVER: src/lib/crypto-server.ts"
call :concat "src/lib/key-rotation.ts"                          "KEY MANAGEMENT: src/lib/key-rotation.ts"
call :concat "src/lib/pq-kem-real.ts"                           "POST-QUANTUM: src/lib/pq-kem-real.ts (ML-KEM-768)"
call :concat "src/lib/memory-zero.ts"                           "MEMORY ZEROING: src/lib/memory-zero.ts"
call :concat "src/lib/subkey-derivation.ts"                     "SUBKEY HKDF: src/lib/subkey-derivation.ts"
call :concat "src/lib/session-token.ts"                         "SESSION: src/lib/session-token.ts"
call :concat "src/lib/rate-limit.ts"                            "RATE LIMIT: src/lib/rate-limit.ts"
call :concat "src/lib/validation-schemas.ts"                    "VALIDATION: src/lib/validation-schemas.ts"

REM 3. Backend
call :concat "src/app/api/auth/register/route.ts"               "API REGISTER: src/app/api/auth/register/route.ts"
call :concat "src/app/api/auth/login/route.ts"                  "API LOGIN: src/app/api/auth/login/route.ts"
call :concat "src/app/api/secrets/route.ts"                     "API SECRETS: src/app/api/secrets/route.ts"
call :concat "src/app/layout.tsx"                               "LAYOUT: src/app/layout.tsx"

REM 4. Frontend
call :concat "src/app/page.tsx"                                 "PAGE: src/app/page.tsx"
call :concat "src/components/AuthView.tsx"                      "AUTH VIEW: src/components/AuthView.tsx"
call :concat "src/components/VaultView.tsx"                     "VAULT VIEW: src/components/VaultView.tsx"
call :concat "src/components/ViewSecretDialog.tsx"              "VIEW SECRET: src/components/ViewSecretDialog.tsx"
call :concat "src/components/CreateSecretDialog.tsx"            "CREATE SECRET: src/components/CreateSecretDialog.tsx"

REM 5. Documentacion
call :concat "ARCHITECTURE.md"                                  "DOC: ARCHITECTURE.md"
call :concat "AUDITING.md"                                      "DOC: AUDITING.md"
call :concat "SECURITY_CHECKLIST.md"                            "DOC: SECURITY_CHECKLIST.md"
call :concat "docs/AI_AUDIT_PROMPT.md"                          "DOC: docs/AI_AUDIT_PROMPT.md"
call :concat "docs/SECURITY_AUDIT_REPORT.md"                    "DOC: docs/SECURITY_AUDIT_REPORT.md"
call :concat "README.md"                                        "DOC: README.md"

REM --- Prompt de auditoria al final ---
(
echo ================================================================================================
echo  PROMPT DE AUDITORIA PARA LLM ^(CLAUDE / GPT / GEMINI / ETC.^)
echo ================================================================================================
echo.
echo Copia el bloque a continuacion y pegalo en un chat con un LLM despues de subir
echo este archivo. El LLM producira una tabla con 30+ hallazgos concretos.
echo.
echo ----- inicio del prompt -----
echo.
echo Eres un ingeniero de seguridad senior auditando un Zero-Knowledge Password
echo Manager en TypeScript / Next.js 16. El codigo completo esta en el archivo
echo adjunto ^(o arriba en este chat^).
echo.
echo Stack criptografico:
echo - Argon2id ^(hash-wasm en Web Worker^) con fallback honesto a PBKDF2 ^(600k iter^)
echo - AES-256-GCM para cifrado simetrico
echo - RSA-OAEP 2048 para wrapping de llaves
echo - ECDH P-256 para sync multi-device
echo - ECDSA P-256 para challenge-response
echo - ML-KEM-768 ^(post-cuantico^) en flujo activo de share/decrypt
echo - HKDF-SHA256 para derivacion de subkeys
echo.
echo Propiedad fundamental: el servidor es "crypto-blind" - NUNCA recibe:
echo masterPassword, masterKey, privateKeyJwk, plainSecret, decryptedSecret.
echo Tampoco ejecuta crypto.subtle.deriveKey ni deriveBits.
echo.
echo Tu tarea: produce una tabla Markdown con AL MENOS 30 hallazgos concretos
echo usando este formato exacto:
echo.
echo ^| # ^| Severity ^| Category ^| File:Line ^| Finding ^| Recommendation ^| Effort ^|
echo.
echo - Severity: CRITICAL ^| HIGH ^| MEDIUM ^| LOW ^| INFO
echo - Category: crypto ^| auth ^| authz ^| injection ^| zk-property ^| secret-leak ^|
echo             supply-chain ^| i18n ^| a11y ^| performance ^| reliability ^| compliance ^| docs
echo - File:Line: ruta clickeable como src/lib/crypto-client.ts:142
echo - Finding: 1-2 oraciones, especificas a una ubicacion del codigo
echo - Recommendation: 1-2 oraciones, con bosquejo de codigo si util
echo - Effort: S ^(<1h^) ^| M ^(1-4h^) ^| L ^(4-16h^) ^| XL ^(>16h^)
echo.
echo Reglas:
echo - NO recomiendes "agregar tests" genericos - especifica el test
echo - NO recomiendes "agregar logging" - especifica que registrar y que redactar
echo - NO consolides hallazgos en archivos distintos - una fila por ubicacion
echo - NO omitas un hallazgo por aparecer en el reporte - reafirmalo
echo - Flag todo lo que viole SECURITY_CHECKLIST.md
echo - Flag cualquier drift entre ARCHITECTURE.md y el codigo real
echo - Flag cualquier primitiva fuera de la lista aprobada:
echo   AES-GCM, RSA-OAEP, RSA-PSS, ECDH P-256, ECDSA P-256, HKDF-SHA256,
echo   PBKDF2 ^(^>=600k iter^), Argon2id ^(m^>=64MiB, t^>=3, p^>=1^), ML-KEM-768
echo.
echo Despues de la tabla, anade "Verdict" con:
echo - Postura de seguridad general ^(1 parrafo^)
echo - Top 3 riesgos a remediar primero
echo - Cadencia de auditoria recomendada ^(trimestral / anual / por release^)
echo.
echo Comienza ahora. Lee cada archivo cuidadosamente antes de producir la tabla.
echo No inventes rutas de codigo que no estan en el archivo.
echo.
echo ----- fin del prompt -----
echo.
echo ================================================================================================
echo  FIN DEL ARCHIVO
echo ================================================================================================
echo  Estadisticas:
echo    Archivos descargados OK:  %OK%
echo    Archivos fallidos:        %FAIL%
echo    Total lineas concatenadas: %TOTAL_LINES%
echo    Total bytes de codigo:    %TOTAL_BYTES%
echo.
echo  Auditoria siguiente paso:
echo    1. Sube este archivo a tu LLM favorito
echo    2. Copia el prompt de arriba y pegalo como mensaje
echo    3. El LLM devolvera una tabla con 30+ hallazgos
echo    4. Triaga por Severity ^(CRITICAL - XL primero^)
echo    5. File cada hallazgo aceptado como GitHub Issue
echo ================================================================================================
) >> "%OUTFILE%"

REM --- Limpiar temporales ---
rmdir /s /q "%TMPDIR%"

REM --- Resumen final ---
echo.
echo ========================================================
echo   Resumen
echo ========================================================
echo   Archivos OK:        %OK%
echo   Archivos fallidos:  %FAIL%
echo   Total lineas:       %TOTAL_LINES%
echo   Total bytes:        %TOTAL_BYTES%
echo   Archivo final:      %OUTFILE%
for %%A in ("%OUTFILE%") do set "FSIZE=%%~zA"
set /a FKB=%FSIZE%/1024
echo   Tamano en disco:    %FKB% KB
echo.

if %FAIL% gtr 0 (
    echo NOTA: %FAIL% archivo^(s^) no se pudieron descargar.
    echo Si son archivos de auditoria ^(AUDITING.md, etc.^), el commit 10378cc
    echo aun no esta en GitHub. Ejecuta primero:
    echo   git push origin main
    echo.
)

echo Abriendo archivo en Explorer...
explorer /select,"%OUTFILE%"

echo.
echo Listo! Siguiente paso:
echo   1. Sube %OUTFILE% a Claude / GPT / Gemini
echo   2. Copia el prompt al final del archivo y pegalo en el chat
echo   3. Recibiras una tabla con 30+ hallazgos de auditoria
echo.
pause
goto :eof

REM === Funcion: descargar y concatenar un archivo ===
:concat
set "SRC=%~1"
set "LABEL=%~2"
set "URL=%RAWBASE%/%SRC%"
set "TMPFILE=%TMPDIR%\file_%OK%.txt"

REM Descargar con curl
curl -sL -o "%TMPFILE%" "%URL%"

REM Verificar
if not exist "%TMPFILE%" (
    echo   [FAIL] %LABEL%
    set /a FAIL+=1
    goto :eof
)

REM Verificar tamano
for %%A in ("%TMPFILE%") do set "FSIZE=%%~zA"
if !FSIZE! equ 0 (
    echo   [FAIL] %LABEL% - archivo vacio o 404
    set /a FAIL+=1
    goto :eof
)

REM Contar lineas
for /f %%a in ('type "%TMPFILE%" ^| find /c /v ""') do set "LINES=%%a"

REM Escribir separador + metadata + contenido
(
echo ================================================================================================
echo  %LABEL%
echo ================================================================================================
echo  Ruta original:  %SRC%
echo  Tamano:         !FSIZE! bytes
echo  Lineas:         !LINES!
echo ================================================================================================
echo ----- inicio del archivo -----
echo.
type "%TMPFILE%"
echo.
echo ----- fin del archivo -----
echo.
echo.
) >> "%OUTFILE%"

echo   [OK] %LABEL%  ^(!FSIZE! bytes, !LINES! lineas^)
set /a OK+=1
set /a TOTAL_LINES+=!LINES!
set /a TOTAL_BYTES+=!FSIZE!
goto :eof
