#!/bin/bash
set -euo pipefail
BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DB_URL="${DATABASE_URL:-file:./db/custom.db}"
if [[ "$DB_URL" == postgresql://* ]]; then
  pg_dump "$DB_URL" > "$BACKUP_DIR/db-$TIMESTAMP.sql"
  echo "✓ Postgres backup: $BACKUP_DIR/db-$TIMESTAMP.sql"
elif [[ "$DB_URL" == file:* ]]; then
  DB_PATH="${DB_URL#file:}"
  cp "$DB_PATH" "$BACKUP_DIR/db-$TIMESTAMP.db"
  echo "✓ SQLite backup: $BACKUP_DIR/db-$TIMESTAMP.db"
fi
echo "To restore: psql \$DATABASE_URL < $BACKUP_DIR/db-$TIMESTAMP.sql"
