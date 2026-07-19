@echo off
REM =====================================================================
REM Zero-Knowledge Vault - Concatenador de TODO el codigo a .txt (Bash)
REM =====================================================================
REM
REM Recorre ABSOLUTAMENTE TODO el proyecto y concatena cada archivo de
REM codigo fuente en UN SOLO archivo .txt.
REM
REM USO: Copia este archivo a la raiz del proyecto y doble clic.
REM
REM Salida: zk-vault-codigo-completo.txt en la raiz del proyecto.
REM =====================================================================

setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "OUTPUT_FILE=%PROJECT_ROOT%\zk-vault-codigo-completo.txt"

echo.
echo ========================================================
echo   Zero-Knowledge Vault - Concatenador de TODO el codigo
echo ========================================================
echo.
echo  Proyecto:  %PROJECT_ROOT%
echo  Salida:    %OUTPUT_FILE%
echo.

REM Eliminar archivo previo
if exist "%OUTPUT_FILE%" del "%OUTPUT_FILE%"

REM Encabezado
(
echo ================================================================================================
echo  ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
echo ================================================================================================
echo  Proyecto:        %PROJECT_ROOT%
echo  Generado:        %DATE% %TIME%
echo  Format:          Cada archivo se delimita con separadores === y --- inicio/fin ---
echo ================================================================================================
echo.
echo.
) > "%OUTPUT_FILE%"

set OK=0
set FAIL=0
set TOTAL_LINES=0
set TOTAL_BYTES=0

echo Buscando archivos de codigo fuente...
echo.

REM Procesar cada archivo con extensiones de codigo
REM Excluimos node_modules, .next, .git, coverage, etc.

for /r "%PROJECT_ROOT%" %%F in (*.ts *.tsx *.js *.jsx *.mjs *.cjs *.json *.prisma *.md *.css *.scss *.yml *.yaml *.toml *.sh *.bat *.ps1) do (
    set "filepath=%%F"
    set "filename=%%~nxF"
    set "filedir=%%~dpF"

    REM Excluir directorios prohibidos
    set "skip=0"
    echo !filepath! | findstr /i "\\node_modules\\ \\.next\\ \\.git\\ \\coverage\\ \\dist\\ \\build\\ \\out\\ \\skills\\ \\upload\\ \\download\\ \\db\\" >nul && set "skip=1"
    if "!skip!"=="0" (
        REM Excluir archivos prohibidos
        if "!filename!"=="bun.lock" set "skip=1"
        if "!filename!"=="package-lock.json" set "skip=1"
        if "!filename!"=="tsconfig.tsbuildinfo" set "skip=1"
        if "!filename!"=="dev.log" set "skip=1"
        if "!filename!"=="server.log" set "skip=1"
        if "!filename!"=="next-env.d.ts" set "skip=1"
    )

    if "!skip!"=="0" (
        REM Obtener ruta relativa
        set "relpath=!filepath:%PROJECT_ROOT%\=!"

        REM Contar lineas
        for /f %%a in ('type "%%F" ^| find /c /v ""') do set "lines=%%a"

        REM Tamano del archivo
        for %%S in ("%%F") do set "fsize=%%~zS"

        REM Escribir separador + metadata
        (
        echo ================================================================================================
        echo  !relpath!
        echo ================================================================================================
        echo  Lineas:    !lines!
        echo  Bytes:     !fsize!
        echo ================================================================================================
        echo ----- inicio del archivo -----
        echo.
        type "%%F"
        echo.
        echo ----- fin del archivo -----
        echo.
        echo.
        ) >> "%OUTPUT_FILE%"

        set /a OK+=1
        set /a TOTAL_LINES+=!lines!
        set /a TOTAL_BYTES+=!fsize!

        if !OK! lss 100 (
            echo   [!OK!] !relpath!
        ) else if !OK! lss 1000 (
            if "!OK:~-2!"=="00" echo   [!OK!] procesando...
        )
    )
)

REM Procesar archivos especiales sin extension clasica
for %%N in (".env.example" ".gitignore" ".gitattributes" "postcss.config.cjs" "eslint.config.mjs") do (
    if exist "%PROJECT_ROOT%\%%N" (
        set "relpath=%%N"
        for /f %%a in ('type "%PROJECT_ROOT%\%%N" ^| find /c /v ""') do set "lines=%%a"
        for %%S in ("%PROJECT_ROOT%\%%N") do set "fsize=%%~zS"

        (
        echo ================================================================================================
        echo  !relpath!
        echo ================================================================================================
        echo  Lineas:    !lines!
        echo  Bytes:     !fsize!
        echo ================================================================================================
        echo ----- inicio del archivo -----
        echo.
        type "%PROJECT_ROOT%\%%N"
        echo.
        echo ----- fin del archivo -----
        echo.
        echo.
        ) >> "%OUTPUT_FILE%"

        set /a OK+=1
        set /a TOTAL_LINES+=!lines!
    )
)

REM Resumen final
for %%A in ("%OUTPUT_FILE%") do set "FINAL_SIZE=%%~zA"
set /a FINAL_KB=%FINAL_SIZE%/1024

(
echo ================================================================================================
echo  RESUMEN FINAL
echo ================================================================================================
echo  Archivos concatenados OK:  %OK%
echo  Total lineas de codigo:    %TOTAL_LINES%
echo  Tamano del archivo final:  %FINAL_KB% KB
echo  Archivo de salida:         %OUTPUT_FILE%
echo ================================================================================================
echo.
echo  SIGUIENTE PASO:
echo    1. Sube el archivo a Claude / GPT / Gemini
echo    2. Pidele que audite o implemente una feature
echo    3. El LLM tiene TODO el contexto en un solo archivo
echo ================================================================================================
) >> "%OUTPUT_FILE%"

echo.
echo ========================================================
echo   Resumen
echo ========================================================
echo   Archivos OK:        %OK%
echo   Total lineas:       %TOTAL_LINES%
echo   Tamano final:       %FINAL_KB% KB
echo   Archivo salida:     %OUTPUT_FILE%
echo.

set /p OPEN="Abrir el archivo generado? (s/N): "
if /i "%OPEN%"=="s" notepad "%OUTPUT_FILE%"

echo.
echo Listo!
pause
