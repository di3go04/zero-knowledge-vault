# TRACKING-FIX5 — Corrección de 5 módulos marcados como "hecho" pero con implementación de juguete

| # | Módulo | Problema detectado | Estado | Nota / commit |
|---|--------|---------------------|--------|----------------|
| 1 | src/lib/sentry.ts | No importa @sentry/nextjs, solo hace console.log/error disfrazado de Sentry | pendiente | |
| 2 | src/lib/api-key-auth.ts | Las API keys viven en un Map en memoria, no en la base de datos — en serverless (Vercel) se pierden entre instancias/cold starts | pendiente | |
| 3 | src/lib/dead-mans-switch.ts | Estado en Map en memoria, sin persistencia, sin cron real, sin envío de email/notificación | pendiente | |
| 4 | src/lib/onepassword-adapter.ts | Dice parsear .1pux (que es un ZIP) pero no descomprime nada — solo mapea JSON ya extraído a mano | pendiente | |
| 5 | src/app/api/metrics/route.ts + metrics-store | Contadores en variables en memoria (let requestCount = 0), active_connections hardcodeado en 1 — no acumula nada real entre requests serverless | pendiente | |
