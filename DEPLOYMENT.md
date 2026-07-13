# Deployment Guide

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Node.js / Bun | 20+ / 1.0+ |
| Redis (optional, recommended) | 6+ |
| HTTPS | TLS 1.2+ (required for Web Crypto) |

## Environment Variables

```bash
# Required
DATABASE_URL=file:./db/vault.db
SESSION_SECRET=<min 32 chars, use: openssl rand -base64 48>

# Optional (Redis — enables distributed blacklist, rate limiting, challenge store)
REDIS_URL=redis://localhost:6379

# Optional (Stripe billing)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_TEAM_PRICE_ID=price_...
STRIPE_BUSINESS_PRICE_ID=price_...

# Optional (SSO)
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://yourdomain.com/api/auth/oidc/callback

# Optional
DECOY_HMAC_KEY=<use: openssl rand -base64 32>
LOG_LEVEL=info
CORS_ORIGINS=https://yourdomain.com
```

## Local Development

```bash
bun install
bunx prisma db push
bun run dev
```

## Docker Deployment

```bash
docker compose up -d
# App: http://localhost:3000
# Health: http://localhost:3000/api/health
```

## Production Build

```bash
bun install
bunx prisma generate
bunx prisma db push
bun run build
NODE_ENV=production bun .next/standalone/server.js
```

## Database Migration (SQLite → PostgreSQL)

1. Export data: `bun scripts/migrate.ts`
2. Change `DATABASE_URL` to `postgresql://...`
3. Run: `bunx prisma db push`
4. Import data to PostgreSQL

## Versions

- Next.js 16.1.3
- Prisma 6.19.2
- TypeScript 5.x
- @noble/post-quantum 0.6.1
- Zod 4.x
