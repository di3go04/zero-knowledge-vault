# =====================================================================
# Zero-Knowledge Vault — Concatenador a archivo unico de texto
# =====================================================================
# Script: PowerShell para Windows 11
#
# Descarga todos los archivos clave del repositorio y los combina en
# UN SOLO archivo de texto listo para subir a un LLM (Claude, GPT,
# Gemini, etc.) o para compartir como unico archivo.
#
# USO:
#   1. Guarda este archivo como: concatenar-zk-vault.ps1
#   2. Abre PowerShell (Win+X → Terminal)
#   3. Ejecuta:
#       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#       .\concatenar-zk-vault.ps1
#
# Salida:
#   C:\Users\<tu-usuario>\Downloads\zk-vault-codigo-completo.txt
# =====================================================================

# --- Configuracion ---------------------------------------------------
$Repo       = "di3go04/zero-knowledge-vault"
$Branch     = "main"
$RawBase    = "https://raw.githubusercontent.com/$Repo/$Branch"
$OutputBase = Join-Path $env:USERPROFILE "Downloads"
$OutputFile = Join-Path $OutputBase "zk-vault-codigo-completo.txt"

# --- Lista de archivos a descargar y concatenar ----------------------
# Orden: config → crypto → backend → frontend → docs de auditoria
$Files = @(
    # 1. Configuracion y nucleo
    @{ Source = "package.json";                              Label = "CONFIG: package.json" }
    @{ Source = "tsconfig.json";                             Label = "CONFIG: tsconfig.json" }
    @{ Source = "next.config.ts";                            Label = "CONFIG: next.config.ts" }
    @{ Source = "prisma/schema.prisma";                      Label = "DB SCHEMA: prisma/schema.prisma" }

    # 2. Criptografia (el corazon del proyecto)
    @{ Source = "src/lib/crypto-client.ts";                  Label = "CRYPTO CLIENT: src/lib/crypto-client.ts" }
    @{ Source = "src/lib/crypto-server.ts";                  Label = "CRYPTO SERVER: src/lib/crypto-server.ts" }
    @{ Source = "src/lib/key-rotation.ts";                   Label = "KEY MANAGEMENT: src/lib/key-rotation.ts (alternativa a key-management.ts)" }
    @{ Source = "src/lib/pq-kem-real.ts";                    Label = "POST-QUANTUM: src/lib/pq-kem-real.ts (ML-KEM-768)" }
    @{ Source = "src/lib/memory-zero.ts";                    Label = "MEMORY ZEROING: src/lib/memory-zero.ts" }
    @{ Source = "src/lib/subkey-derivation.ts";              Label = "SUBKEY HKDF: src/lib/subkey-derivation.ts" }
    @{ Source = "src/lib/session-token.ts";                  Label = "SESSION: src/lib/session-token.ts" }
    @{ Source = "src/lib/rate-limit.ts";                     Label = "RATE LIMIT: src/lib/rate-limit.ts" }
    @{ Source = "src/lib/validation-schemas.ts";             Label = "VALIDATION: src/lib/validation-schemas.ts" }

    # 3. Backend (rutas API)
    @{ Source = "src/app/api/auth/register/route.ts";        Label = "API REGISTER: src/app/api/auth/register/route.ts" }
    @{ Source = "src/app/api/auth/login/route.ts";           Label = "API LOGIN: src/app/api/auth/login/route.ts" }
    @{ Source = "src/app/api/secrets/route.ts";              Label = "API SECRETS: src/app/api/secrets/route.ts" }
    @{ Source = "src/app/layout.tsx";                        Label = "LAYOUT (no hay middleware.ts): src/app/layout.tsx" }

    # 4. Frontend (paginas principales)
    @{ Source = "src/app/page.tsx";                          Label = "PAGE: src/app/page.tsx" }
    @{ Source = "src/components/AuthView.tsx";               Label = "AUTH VIEW (no hay login/page.tsx): src/components/AuthView.tsx" }
    @{ Source = "src/components/VaultView.tsx";              Label = "VAULT VIEW (dashboard): src/components/VaultView.tsx" }
    @{ Source = "src/components/ViewSecretDialog.tsx";       Label = "VIEW SECRET (alternativa a SecretList): src/components/ViewSecretDialog.tsx" }
    @{ Source = "src/components/CreateSecretDialog.tsx";     Label = "CREATE SECRET: src/components/CreateSecretDialog.tsx" }

    # 5. Documentacion y scripts de auditoria
    @{ Source = "ARCHITECTURE.md";                           Label = "DOC: ARCHITECTURE.md" }
    @{ Source = "AUDITING.md";                               Label = "DOC: AUDITING.md" }
    @{ Source = "SECURITY_CHECKLIST.md";                     Label = "DOC: SECURITY_CHECKLIST.md" }
    @{ Source = "docs/AI_AUDIT_PROMPT.md";                   Label = "DOC: docs/AI_AUDIT_PROMPT.md" }
    @{ Source = "docs/SECURITY_AUDIT_REPORT.md";             Label = "DOC: docs/SECURITY_AUDIT_REPORT.md" }
    @{ Source = "README.md";                                 Label = "DOC: README.md" }
)

# --- Preparar -------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Knowledge Vault - Concatenador a texto unico"     -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repo origen:  https://github.com/$Repo"                  -ForegroundColor Gray
Write-Host "Branch:       $Branch"                                    -ForegroundColor Gray
Write-Host "Archivo out:  $OutputFile"                                -ForegroundColor Gray
Write-Host ""

# Forzar TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Crear encabezado del archivo unico -----------------------------
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
$header = @"
================================================================================
 ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
================================================================================
 Repositorio:  https://github.com/$Repo
 Branch:       $Branch
 Generado:     $timestamp
 Total archivos: $($Files.Count)
 Commit:       $(try { (Invoke-RestMethod "https://api.github.com/repos/$Repo/commits/$Branch" -UseBasicParsing).sha.Substring(0,7) } catch { "desconocido" })

 FORMATO:
   Cada archivo comienza con:
     ===== <LABEL> =====
     (ruta original / tamaño / lineas)
     ----- inicio del archivo -----
   Y termina con:
     ----- fin del archivo -----

 USO:
   - Sube este archivo a Claude / GPT / Gemini / etc.
   - O abrelo en tu editor para revision manual.
   - El prompt de auditoria esta al final del archivo.
================================================================================


"@

Set-Content -Path $OutputFile -Value $header -Encoding UTF8
Add-Content -Path $OutputFile -Value "" -Encoding UTF8

# --- Descargar y concatenar -----------------------------------------
$okCount = 0
$failCount = 0
$totalLines = 0
$totalBytes = 0
$failed = @()

Write-Host "Descargando y concatenando $($Files.Count) archivos..." -ForegroundColor Cyan
Write-Host ""

foreach ($f in $Files) {
    $url    = "$RawBase/$($f.Source)"
    $label  = $f.Label

    try {
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        $text    = $content.Content
        $size    = $text.Length
        $lines   = ($text -split "`n").Count

        # Escribir separador y metadata
        $sep = "=" * 80
        $block = @"
$sep
 $label
$sep
 Ruta original:  $($f.Source)
 Tamano:         $size bytes
 Lineas:         $lines
$sep
----- inicio del archivo -----

$text

----- fin del archivo -----

"@
        Add-Content -Path $OutputFile -Value $block -Encoding UTF8

        Write-Host "  [OK] $label  ($size bytes, $lines lineas)" -ForegroundColor Green
        $okCount++
        $totalLines += $lines
        $totalBytes += $size
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg.Length -gt 80) { $errMsg = $errMsg.Substring(0, 80) }

        $sep = "=" * 80
        $block = @"
$sep
 $label
$sep
 Ruta original:  $($f.Source)
 ESTADO:         NO DISPONIBLE
 Error:          $errMsg
$sep

"@
        Add-Content -Path $OutputFile -Value $block -Encoding UTF8

        Write-Host "  [FAIL] $label - $errMsg" -ForegroundColor Red
        $failCount++
        $failed += $f.Source
    }
}

# --- Anadir prompt de auditoria al final ----------------------------
$promptBlock = @"

================================================================================
 PROMPT DE AUDITORIA PARA LLM (CLAUDE / GPT / GEMINI / ETC.)
================================================================================

Copia el bloque a continuacion y pegalo en un chat con un LLM despues de subir
este archivo. El LLM producira una tabla con 30+ hallazgos concretos.

----- inicio del prompt -----

Eres un ingeniero de seguridad senior auditando un Zero-Knowledge Password
Manager en TypeScript / Next.js 16. El codigo completo esta en el archivo
adjunto (o arriba en este chat).

Stack criptografico:
- Argon2id (hash-wasm en Web Worker) con fallback honesto a PBKDF2 (600k iter)
- AES-256-GCM para cifrado simetrico
- RSA-OAEP 2048 para wrapping de llaves
- ECDH P-256 para sync multi-device
- ECDSA P-256 para challenge-response
- ML-KEM-768 (post-cuantico) en flujo activo de share/decrypt
- HKDF-SHA256 para derivacion de subkeys

Propiedad fundamental: el servidor es "crypto-blind" — NUNCA recibe:
masterPassword, masterKey, privateKeyJwk, plainSecret, decryptedSecret.
Tampoco ejecuta crypto.subtle.deriveKey ni deriveBits.

Tu tarea: produce una tabla Markdown con AL MENOS 30 hallazgos concretos
usando este formato exacto:

| # | Severity | Category | File:Line | Finding | Recommendation | Effort |

- Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
- Category: crypto | auth | authz | injection | zk-property | secret-leak |
            supply-chain | i18n | a11y | performance | reliability | compliance | docs
- File:Line: ruta clickeable como src/lib/crypto-client.ts:142
- Finding: 1-2 oraciones, especificas a una ubicacion del codigo
- Recommendation: 1-2 oraciones, con bosquejo de codigo si util
- Effort: S (<1h) | M (1-4h) | L (4-16h) | XL (>16h)

Reglas:
- NO recomiendes "agregar tests" genericos — especifica el test
- NO recomiendes "agregar logging" — especifica que registrar y que redactar
- NO consolides hallazgos en archivos distintos — una fila por ubicacion
- NO omitas un hallazgo por aparecer en el reporte — reafirmalo
- Flag todo lo que viole SECURITY_CHECKLIST.md
- Flag cualquier drift entre ARCHITECTURE.md y el codigo real
- Flag cualquier primitiva fuera de la lista aprobada:
  AES-GCM, RSA-OAEP, RSA-PSS, ECDH P-256, ECDSA P-256, HKDF-SHA256,
  PBKDF2 (>=600k iter), Argon2id (m>=64MiB, t>=3, p>=1), ML-KEM-768

Despues de la tabla, anade "Verdict" con:
- Postura de seguridad general (1 parrafo)
- Top 3 riesgos a remediar primero
- Cadencia de auditoria recomendada (trimestral / anual / por release)

Comienza ahora. Lee cada archivo cuidadosamente antes de producir la tabla.
No inventes rutas de codigo que no estan en el archivo.

----- fin del prompt -----

================================================================================
 FIN DEL ARCHIVO
================================================================================
 Estadisticas:
   Archivos descargados OK:  $okCount
   Archivos fallidos:        $failCount
   Total lineas concatenadas: $totalLines
   Total bytes de codigo:    $totalBytes

 Auditoria siguiente paso:
   1. Sube este archivo a tu LLM favorito
   2. Copia el prompt de arriba y pegalo como mensaje
   3. El LLM devolvera una tabla con 30+ hallazgos
   4. Triaga por Severity (CRITICAL → XL primero)
   5. File cada hallazgo aceptado como GitHub Issue
================================================================================
"@

Add-Content -Path $OutputFile -Value $promptBlock -Encoding UTF8

# --- Resumen ---------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Resumen"                                               -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Archivos OK:        $okCount"                          -ForegroundColor Green
Write-Host "  Archivos fallidos:  $failCount"                        -ForegroundColor $(if ($failCount -gt 0) {"Red"} else {"Gray"})
Write-Host "  Total lineas:       $totalLines"                       -ForegroundColor Gray
Write-Host "  Total bytes:        $totalBytes"                       -ForegroundColor Gray
Write-Host "  Archivo final:      $OutputFile"                       -ForegroundColor Yellow
$fileSize = (Get-Item $OutputFile).Length
$fileKB = [math]::Round($fileSize / 1024, 1)
Write-Host "  Tamano en disco:    $fileKB KB"                        -ForegroundColor Gray
Write-Host ""

if ($failed.Count -gt 0) {
    Write-Host "Archivos no descargados:" -ForegroundColor Yellow
    foreach ($fa in $failed) {
        Write-Host "  - $fa" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Si son archivos de auditoria (AUDITING.md, etc.), el commit 10378cc" -ForegroundColor Gray
    Write-Host "aun no esta en GitHub. Ejecuta primero:"                                -ForegroundColor Gray
    Write-Host "  git push origin main"                                                 -ForegroundColor Yellow
    Write-Host ""
}

# Abrir carpeta en Explorer y seleccionar el archivo
Write-Host "Abriendo carpeta en Explorer..." -ForegroundColor Cyan
explorer.exe /select, $OutputFile

Write-Host ""
Write-Host "Listo!" -ForegroundColor Green
Write-Host ""
Write-Host "Siguiente paso:" -ForegroundColor Green
Write-Host "  1. Sube $OutputFile a Claude / GPT / Gemini" -ForegroundColor Gray
Write-Host "  2. Copia el prompt al final del archivo y pegalo en el chat" -ForegroundColor Gray
Write-Host "  3. Recibiras una tabla con 30+ hallazgos de auditoria" -ForegroundColor Gray
Write-Host ""
Read-Host "Presiona Enter para salir"
