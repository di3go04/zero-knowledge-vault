#!/bin/bash
# MEJORA 32/39: Backup automático de BD con cifrado
# Uso: ./scripts/backup.sh
# Cron: 0 3 * * * /path/to/scripts/backup.sh

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
DB_PATH="${DB_PATH:-./db/custom.db}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-$(openssl rand -base64 32)}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/vault_backup_$TIMESTAMP.db.enc"

mkdir -p "$BACKUP_DIR"

echo "📦 Creando backup cifrado: $BACKUP_FILE"

# Copiar BD (SQLite file copy es atómico si WAL está desactivado)
cp "$DB_PATH" "/tmp/vault_backup_$TIMESTAMP.db"

# Cifrar con AES-256-CBC
openssl enc -aes-256-cbc -salt \
  -in "/tmp/vault_backup_$TIMESTAMP.db" \
  -out "$BACKUP_FILE" \
  -pass pass:"$ENCRYPTION_KEY"

# Limpiar temporal
rm -f "/tmp/vault_backup_$TIMESTAMP.db"

# Limpiar backups antiguos (>30 días)
find "$BACKUP_DIR" -name "vault_backup_*.db.enc" -mtime +30 -delete

echo "✅ Backup creado: $BACKUP_FILE"
echo "   Tamaño: $(du -h "$BACKUP_FILE" | cut -f1)"
echo "   Para restaurar: openssl enc -d -aes-256-cbc -in $BACKUP_FILE -out restored.db -pass pass:KEY"
