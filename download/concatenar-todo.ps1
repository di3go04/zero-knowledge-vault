# =====================================================================
# Zero-Knowledge Vault — Concatenador de TODO el código fuente a .txt
# =====================================================================
# Script: PowerShell para Windows 11
#
# Recorre ABSOLUTAMENTE TODO el proyecto y concatena cada archivo de
# código fuente en UN SOLO archivo .txt, listo para:
#   - Subir a un LLM (Claude, GPT, Gemini) para auditoría
#   - Compartir como archivo único
#   - Hacer grep / buscar en un solo lugar
#
# USO:
#   1. Guarda este archivo en la RAÍZ del proyecto como: concatenar-todo.ps1
#   2. Abre PowerShell (Win+X → Terminal)
#   3. Ejecuta:
#       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#       .\concatenar-todo.ps1
#
# Salida:
#   .\zk-vault-codigo-completo.txt
# =====================================================================

# --- Configuración ---------------------------------------------------
$ProjectRoot = $PSScriptRoot
$OutputFile  = Join-Path $ProjectRoot "zk-vault-codigo-completo.txt"

# --- Extensiones de archivo a incluir -------------------------------
$IncludeExtensions = @(
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".json", ".prisma", ".md", ".css", ".scss",
    ".yml", ".yaml", ".toml", ".env.example",
    ".sh", ".bat", ".ps1",
    ".gitignore", ".gitattributes",
    ".config.mjs", ".config.ts", ".config.cjs"
)

# Archivos específicos sin extensión o con nombres especiales
$IncludeFilenames = @(
    ".env.example",
    ".gitignore",
    ".gitattributes"
)

# --- Directorios a excluir -------------------------------------------
$ExcludeDirs = @(
    "node_modules",
    ".next",
    ".git",
    "coverage",
    "dist",
    "build",
    "out",
    "playwright-report",
    "test-results",
    "audit-reports",
    "skills",          # skills no son parte del código del proyecto
    "upload",
    "download",        # carpeta con scripts de descarga, no código
    "db"               # base de datos SQLite binaria
)

# --- Archivos a excluir por nombre -----------------------------------
$ExcludeFiles = @(
    "bun.lock",
    "package-lock.json",
    "yarn.lock",
    "tsconfig.tsbuildinfo",
    "dev.log",
    "server.log",
    ".env",            # excluir el .env real (puede tener secretos), solo .env.example
    "next-env.d.ts"    # generado por Next.js
)

# --- Helpers ---------------------------------------------------------
function Test-ShouldInclude {
    param($File)

    # Excluir por nombre exacto
    if ($ExcludeFiles -contains $File.Name) { return $false }

    # Excluir paths en directorios prohibidos
    foreach ($dir in $ExcludeDirs) {
        if ($File.FullName -match "\\$dir\\") { return $false }
    }

    # Incluir por nombre exacto (.env.example, .gitignore, etc.)
    if ($IncludeFilenames -contains $File.Name) { return $true }

    # Incluir por extensión
    $ext = $File.Extension.ToLower()
    if ($IncludeExtensions -contains $ext) { return $true }

    # Casos especiales sin extensión clásica
    if ($File.Name -match "\.config\.(mjs|ts|cjs|js)$") { return $true }

    return $false
}

function Get-FileLanguage {
    param($File)
    $ext = $File.Extension.ToLower()
    switch ($ext) {
        ".ts"    { "TypeScript" }
        ".tsx"   { "TypeScript React" }
        ".js"    { "JavaScript" }
        ".jsx"   { "JavaScript React" }
        ".mjs"   { "ES Module" }
        ".cjs"   { "CommonJS" }
        ".json"  { "JSON" }
        ".prisma"{ "Prisma Schema" }
        ".md"    { "Markdown" }
        ".css"   { "CSS" }
        ".scss"  { "SCSS" }
        ".yml"   { "YAML" }
        ".yaml"  { "YAML" }
        ".toml"  { "TOML" }
        ".sh"    { "Shell" }
        ".bat"   { "Batch" }
        ".ps1"   { "PowerShell" }
        default  { "Text" }
    }
}

# --- Banner ----------------------------------------------------------
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Knowledge Vault - Concatenador de TODO el codigo" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Proyecto:   $ProjectRoot" -ForegroundColor Gray
Write-Host "Salida:     $OutputFile" -ForegroundColor Gray
Write-Host ""

# --- Recopilar archivos ---------------------------------------------
Write-Host "Buscando archivos de codigo fuente..." -ForegroundColor Cyan

$allFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -Force |
    Where-Object { Test-ShouldInclude -File $_ } |
    Sort-Object FullName

Write-Host "Encontrados $($allFiles.Count) archivos para concatenar." -ForegroundColor Green
Write-Host ""

# --- Eliminar archivo previo si existe ------------------------------
if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
    Write-Host "Archivo anterior eliminado." -ForegroundColor Yellow
}

# --- Encabezado del archivo -----------------------------------------
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
$totalSize = ($allFiles | Measure-Object -Property Length -Sum).Sum
$totalSizeKB = [math]::Round($totalSize / 1024, 1)

$header = @"
================================================================================
 ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
================================================================================
 Proyecto:        $ProjectRoot
 Generado:        $timestamp
 Total archivos:  $($allFiles.Count)
 Tamano total:    $totalSizeKB KB

 Directorios excluidos:
   $(($ExcludeDirs | ForEach-Object { $_ }) -join ", ")

 Archivos excluidos:
   $(($ExcludeFiles | ForEach-Object { $_ }) -join ", ")

 FORMATO:
   Cada archivo se delimita con:
     ===== <ruta relativa> =====
     (Lenguaje: <lang> | Lineas: <N> | Bytes: <N>)
     ----- inicio del archivo -----
     <contenido completo del archivo>
     ----- fin del archivo -----

 USO:
   - Sube este archivo a Claude / GPT / Gemini para auditoria completa
   - O abrela en tu editor para revision manual
   - Busca con Ctrl+F cualquier funcion, variable o comentario
================================================================================


"@

Set-Content -Path $OutputFile -Value $header -Encoding UTF8

# --- Concatenar cada archivo ----------------------------------------
$okCount = 0
$failCount = 0
$totalLines = 0
$failed = @()

Write-Host "Concatenando..." -ForegroundColor Cyan
Write-Host ""

foreach ($file in $allFiles) {
    try {
        $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
        if ($null -eq $content) { $content = "" }

        $relPath = $file.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
        $language = Get-FileLanguage -File $file
        $lineCount = ($content -split "`n").Count
        $sizeBytes = $file.Length

        $sep = "=" * 80
        $block = @"
$sep
 $relPath
$sep
 Lenguaje:  $language
 Lineas:    $lineCount
 Bytes:     $sizeBytes
$sep
----- inicio del archivo -----

$content

----- fin del archivo -----

"@
        Add-Content -Path $OutputFile -Value $block -Encoding UTF8

        $okCount++
        $totalLines += $lineCount

        # Mostrar progreso cada 10 archivos
        if ($okCount % 10 -eq 0 -or $okCount -eq $allFiles.Count) {
            Write-Host "  [$okCount/$($allFiles.Count)] $relPath" -ForegroundColor Gray
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg.Length -gt 80) { $errMsg = $errMsg.Substring(0, 80) }
        Write-Host "  [FAIL] $($file.Name) - $errMsg" -ForegroundColor Red
        $failCount++
        $failed += $file.FullName
    }
}

# --- Resumen final --------------------------------------------------
$totalBytes = (Get-Item $OutputFile).Length
$totalKB = [math]::Round($totalBytes / 1024, 1)
$totalMB = [math]::Round($totalBytes / (1024 * 1024), 2)

$summary = @"

================================================================================
 RESUMEN FINAL
================================================================================
 Archivos concatenados OK:  $okCount
 Archivos fallidos:         $failCount
 Total lineas de codigo:    $totalLines
 Tamano del archivo final:  $totalKB KB ($totalMB MB)
 Archivo de salida:         $OutputFile
================================================================================

 SIGUIENTE PASO:
   1. Sube $OutputFile a Claude / GPT / Gemini
   2. Pidele que audite el codigo o que implemente una feature
   3. El LLM tiene contexto completo del proyecto en un solo archivo
================================================================================
"@

Add-Content -Path $OutputFile -Value $summary -Encoding UTF8

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Resumen" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Archivos OK:        $okCount" -ForegroundColor Green
Write-Host "  Archivos fallidos:  $failCount" -ForegroundColor $(if ($failCount -gt 0) {"Red"} else {"Gray"})
Write-Host "  Total lineas:       $totalLines" -ForegroundColor Gray
Write-Host "  Tamano final:       $totalKB KB ($totalMB MB)" -ForegroundColor Yellow
Write-Host "  Archivo salida:     $OutputFile" -ForegroundColor Yellow
Write-Host ""

if ($failed.Count -gt 0) {
    Write-Host "Archivos no procesados:" -ForegroundColor Yellow
    foreach ($f in $failed) {
        Write-Host "  - $f" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Abrir el archivo en el editor por defecto
$open = Read-Host "Abrir el archivo generado? (s/N)"
if ($open -eq "s" -or $open -eq "S") {
    Write-Host "Abriendo..." -ForegroundColor Cyan
    Start-Process notepad.exe $OutputFile
}

Write-Host ""
Write-Host "Listo!" -ForegroundColor Green
Write-Host ""
Read-Host "Presiona Enter para salir"
