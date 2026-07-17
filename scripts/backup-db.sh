#!/bin/bash
# Backup script for Zero-Knowledge Vault
# Usage: ./scripts/backup-db.sh [output-dir]
# Supports SQLite and PostgreSQL

set -euo pipefail

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATABASE_URL="${DATABASE_URL:-file:./db/custom.db}"

mkdir -p "$OUTPUT_DIR"

echo "🔐 Starting backup at $TIMESTAMP"

if [[ "$DATABASE_URL" == postgresql://* ]]; then
  echo "📦 Backing up PostgreSQL..."
  PGPASSWORD="${DATABASE_URL#*:}"  # crude extraction, use proper URL parsing in prod
  DB_NAME="zkvault"
  pg_dump "$DATABASE_URL" | gzip > "$OUTPUT_DIR/zkvault_pg_$TIMESTAMP.sql.gz"
  echo "✅ PostgreSQL backup: $OUTPUT_DIR/zkvault_pg_$TIMESTAMP.sql.gz"
elif [[ "$DATABASE_URL" == file:* ]]; then
  DB_PATH="${DATABASE_URL#file:}"
  echo "📦 Backing up SQLite: $DB_PATH..."
  if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "$OUTPUT_DIR/zkvault_sqlite_$TIMESTAMP.db"
    sqlite3 "$DB_PATH" ".backup '$OUTPUT_DIR/zkvault_sqlite_$TIMESTAMP.db'"
    echo "✅ SQLite backup: $OUTPUT_DIR/zkvault_sqlite_$TIMESTAMP.db"
  else
    echo "⚠️  Database file not found: $DB_PATH"
  fi
fi

# Keep only last 7 backups
find "$OUTPUT_DIR" -name "zkvault_*" -mtime +7 -delete

echo "🎉 Backup complete!"
