#!/bin/bash
set -euo pipefail

echo "🚀 Deployando Zero-Knowledge Vault..."

# 1. Verificar dependencias
command -v bun >/dev/null 2>&1 || { echo "❌ Bun no instalado"; exit 1; }

# 2. Instalar dependencias
echo "📦 Instalando dependencias..."
bun install --frozen-lockfile

# 3. Generar Prisma client
echo "🗄️ Generando Prisma client..."
bunx prisma generate

# 4. Push schema a BD
echo "📋 Sincronizando schema..."
bunx prisma db push

# 5. Build
echo "🔨 Build..."
bun run build

# 6. Docker (opcional)
if [ "${1:-}" = "--docker" ]; then
  echo "🐳 Build Docker..."
  docker build -t zk-vault:latest .
  echo "🐳 Iniciando con docker-compose..."
  docker compose up -d
  echo "✅ Deployado en Docker: http://localhost:3000"
else
  echo "▶️ Iniciando servidor..."
  NODE_ENV=production bun .next/standalone/server.js
fi

echo "✅ Deploy completo"
