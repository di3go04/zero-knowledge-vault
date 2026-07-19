#!/bin/bash
# Genera un único .txt con TODO el código fuente del proyecto
set -uo pipefail

PROJECT_ROOT="/home/z/my-project"
OUTPUT_FILE="/home/z/my-project/download/zk-vault-codigo-completo.txt"
COUNT_FILE="/tmp/zk-concat-count.txt"

# Reiniciar contadores
echo "0" > "$COUNT_FILE"
echo "0" > /tmp/zk-concat-lines.txt
echo "0" > /tmp/zk-concat-bytes.txt

# Encabezado
cat > "$OUTPUT_FILE" << 'HEADER'
================================================================================
 ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
================================================================================
================================================================================


HEADER

# Función para procesar un archivo (escribe directamente al output)
process_file() {
  local file="$1"
  local relpath="${file#$PROJECT_ROOT/}"

  # Excluir por nombre
  local basename
  basename=$(basename "$file")
  case "$basename" in
    "bun.lock"|"package-lock.json"|"yarn.lock"|"tsconfig.tsbuildinfo"|"dev.log"|"server.log"|"next-env.d.ts"|"custom.db")
      return
      ;;
  esac

  # Verificar extensión
  local ext="${file##*.}"
  local valid_ext=0
  case "$ext" in
    ts|tsx|js|jsx|mjs|cjs|json|prisma|md|css|scss|yml|yaml|toml|sh|bat|ps1)
      valid_ext=1
      ;;
  esac

  # Archivos especiales sin extensión clásica
  case "$basename" in
    ".env.example"|".gitignore"|".gitattributes"|"postcss.config.cjs"|"eslint.config.mjs")
      valid_ext=1
      ;;
  esac

  if [ $valid_ext -eq 0 ]; then return; fi

  # Procesar
  if [ -f "$file" ] && [ -r "$file" ]; then
    local lines
    local size
    lines=$(wc -l < "$file")
    size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    {
      echo "================================================================================"
      echo "  $relpath"
      echo "================================================================================"
      echo "  Lineas:    $lines"
      echo "  Bytes:     $size"
      echo "================================================================================"
      echo "----- inicio del archivo -----"
      echo ""
      cat "$file"
      echo ""
      echo "----- fin del archivo -----"
      echo ""
      echo ""
    } >> "$OUTPUT_FILE"

    # Actualizar contadores (atomic con flock)
    local cur_ok cur_lines cur_bytes
    cur_ok=$(cat "$COUNT_FILE")
    cur_lines=$(cat /tmp/zk-concat-lines.txt)
    cur_bytes=$(cat /tmp/zk-concat-bytes.txt)
    echo $((cur_ok + 1)) > "$COUNT_FILE"
    echo $((cur_lines + lines)) > /tmp/zk-concat-lines.txt
    echo $((cur_bytes + size)) > /tmp/zk-concat-bytes.txt
  fi
}

# Exportar para que find -exec pueda usarla
export -f process_file
export PROJECT_ROOT OUTPUT_FILE COUNT_FILE

# Recorrer recursivamente (excluir directorios pesados en el find)
find "$PROJECT_ROOT" -type f \
  -not -path "*/node_modules/*" \
  -not -path "*/.next/*" \
  -not -path "*/.git/*" \
  -not -path "*/coverage/*" \
  -not -path "*/skills/*" \
  -not -path "*/upload/*" \
  -not -path "*/tool-results/*" \
  -not -path "*/dist/*" \
  -not -path "*/build/*" \
  -not -path "*/out/*" \
  -not -path "*/.zscripts/*" \
  2>/dev/null > /tmp/zk-file-list.txt

# Procesar cada archivo
while IFS= read -r file; do
  process_file "$file"
done < /tmp/zk-file-list.txt

# Resumen final
OK=$(cat "$COUNT_FILE")
TOTAL_LINES=$(cat /tmp/zk-concat-lines.txt)
TOTAL_BYTES=$(cat /tmp/zk-concat-bytes.txt)
FINAL_SIZE=$(stat -c%s "$OUTPUT_FILE")
FINAL_KB=$((FINAL_SIZE / 1024))

{
echo "================================================================================"
echo " RESUMEN FINAL"
echo "================================================================================"
echo " Archivos concatenados OK:  $OK"
echo " Total lineas de codigo:    $TOTAL_LINES"
echo " Total bytes de codigo:     $TOTAL_BYTES"
echo " Tamano del archivo final:  ${FINAL_KB} KB"
echo "================================================================================"
} >> "$OUTPUT_FILE"

# Limpiar temporales
rm -f /tmp/zk-concat-count.txt /tmp/zk-concat-lines.txt /tmp/zk-concat-bytes.txt /tmp/zk-file-list.txt

echo "OK: $OK archivos | $TOTAL_LINES lineas | ${FINAL_KB} KB"
echo "Archivo: $OUTPUT_FILE"
