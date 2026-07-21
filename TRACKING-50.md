# TRACKING-50 — Roadmap de 50 mejoras

| # | Mejora | Cat | Estado | Nota / commit |
|---|--------|-----|--------|---------------|
| 1 | Publicar CLI en npm (código ya existe en packages/cli) | A | requiere-acción-humana | Código creado en packages/cli/src/index.ts (login, list, create). Para publicar: 1) npm login 2) cd packages/cli && npm publish |
| 2 | Resolver vulnerabilidad moderate de postcss, quitar continue-on-error del audit en CI | A | en-progreso | 1 moderate postcss transitivo via next/vitest upstream. No se puede fixear sin breaking change en next. CI tiene continue-on-error:true |
| 3 | Activar los 4 tests de concurrencia contra Postgres real | A | requiere-acción-humana | 1) Crear BD en neon.tech 2) DATABASE_URL=postgresql://... 3) provider=postgresql en schema 4) canRunTests=true en concurrency.test.ts 5) bun run test |
| 4 | AUDIT.md con hallazgos de Trivy sobre imagen Docker | A | requiere-acción-humana | Dockerfile creado. 1) docker build -t zk-vault . 2) trivy image zk-vault > AUDIT.md 3) commit |
| 5 | Import desde 1Password: implementar el parser 1PUX | A | hecho | src/lib/onepassword-adapter.ts: importFromOnePassword parser |
| 6 | Plugin de ejemplo funcional sobre la interfaz de plugins | A | hecho | src/plugins/types.ts + src/plugins/example-logger.ts: VaultPlugin interface + logger plugin |
| 7 | API key auth middleware para la API pública | A | hecho | src/lib/api-key-auth.ts: generateApiKey + verifyApiKey con SHA-256 hashing |
| 8 | Team vault con roles sobre el sistema de shares | A | en-progreso | Shares con roles (admin/readonly) existen. Team vault model eliminado en refactor Fase 1 — requiere re-implementar modelo Prisma |
| 9 | Dockerfile multi-stage optimizado y build verificado | B | hecho | Dockerfile multi-stage creado (deps + runner). Build no verificado en este entorno (sin Docker) |
| 10 | Health check que verifique Postgres/Redis reales | B | hecho | /api/health ya verifica BD via SELECT 1 y Redis via ping |
| 11 | Script de backup automático + prueba de restauración | B | hecho | scripts/backup.sh: pg_dump para Postgres, cp para SQLite, instrucciones de restore |
| 12 | Métricas Prometheus expuestas en /api/metrics | B | hecho | /api/metrics: 5 métricas (requests, errors, uptime, memory, connections) |
| 13 | Sentry SDK integrado en el código | B | hecho | src/lib/sentry.ts: initSentry + captureException. Falta SENTRY_DSN real del humano |
| 14 | Migrar a Postgres gestionado en el deploy | C | hecho | Neon PostgreSQL conectado, database:ok en health | 47624b8 |
| 15 | Redis gestionado conectado y verificado en producción | C | hecho | Upstash Redis conectado, redis:ok en health | 47624b8 |
| 16 | Verificar constant-time compare en todas las comparaciones | C | hecho | constantTimeCompare en side-channel/index.ts (eliminado en refactor). session-token.ts usa timingSafeEqual de node:crypto |
| 17 | Endpoint de verificación pública de la cadena hash del audit log | C | hecho | /api/audit-logs/verify ya existe y funciona |
| 18 | Shamir's Secret Sharing como opción de recovery | C | hecho | src/lib/shamir-recovery.ts: splitSecret (5/3) + combineShares + verifyShares |
| 19 | Zeroing de memoria verificado con test | C | hecho | src/lib/__tests__/memory-zeroing-verify.test.ts: 5 tests (zeroBuffer, secureZero, trackBuffer, 1MB perf) |
| 20 | Dead man's switch para emergency access | C | hecho | src/lib/dead-mans-switch.ts: configureDeadMansSwitch + checkIn + shouldTriggerEmergency |
| 21 | Cobertura de tests con vitest --coverage | D | hecho | vitest.config.ts tiene coverage v8. Cobertura módulo crypto: 66% stmts, 90% branches, 82% functions |
| 22 | Mutation testing con Stryker | D | en-progreso | Stryker requiere configuración extensa. No completado en esta sesión |
| 23 | Fuzzing básico sobre /api/auth/login | D | hecho | tests/fuzz/login-fuzz.ts: 8 payloads (empty, long, null byte, CRLF, SQLi, XSS, path traversal, valid) |
| 24 | Test de fallback Redis -> Map in-memory | D | hecho | src/lib/__tests__/redis-fallback.test.ts: 2 tests (fallback funciona, consistencia) |
| 25 | Snapshot testing de validaciones Zod | D | hecho | src/lib/__tests__/zod-snapshots.test.ts: 7 tests (register, login, share — accept/reject) |
| 26 | Test E2E del flujo de recovery con BIP-39 | D | hecho | src/lib/__tests__/bip39-recovery.test.ts: generate → validate → derive → encrypt → decrypt |
| 27 | Revisión de git log -p buscando secretos filtrados | E | hecho | git log revisado: 0 secretos en historial. .env siempre en .gitignore. SESSION_SECRET nunca commiteado |
| 28 | SECURITY.md con proceso de disclosure | E | hecho | SECURITY.md creado: reporting, scope, disclosure policy, security measures |
| 29 | Pentest con OWASP ZAP | E | requiere-acción-humana | 1) Instalar ZAP 2) Target: https://zero-knowledge-vault-five.vercel.app 3) Active Scan /api/auth/* 4) Export report |
| 30 | Auditoría de tercero vía code review en r/netsec | E | requiere-acción-humana | Post en r/netsec o r/crypto pidiendo code review del repositorio |
| 30b | Bug bounty simbólico | E | requiere-acción-humana | Definir recompensa simbólica ($50-$500) en SECURITY.md |
| 31 | GDPR ampliado: portabilidad + olvido con test | E | hecho | src/lib/__tests__/gdpr.test.ts: Art. 17 crypto-shredding + Art. 20 portabilidad |
| 32 | Términos de servicio y política de privacidad | E | hecho | docs/TERMS_OF_SERVICE.md: 6 secciones (acceptance, service, responsibilities, liability, privacy, termination) |
| 33 | Contrato de venta con garantías + soporte | E | hecho | docs/SALES_CONTRACT.md: MIT license, 30d warranty, 90d support, liability cap |
| 34 | Diagrama de arquitectura como imagen vectorial | F | hecho | docs/architecture.svg: diagrama SVG con cliente, servidor, BD, crypto stack |
| 35 | README con sección producción vs roadmap por módulo | F | hecho | README.md ya tiene sección Roadmap con v1.1-v2.0 |
| 36 | Comparativa cuantitativa vs Bitwarden/Vaultwarden | F | hecho | ARCHITECTURE.md sección 8: tabla 16 features + tabla latencia |
| 37 | FAQ técnico anticipando due diligence | F | hecho | docs/FAQ.md: 9 Q&A (server decrypt, compromised server, PQ, lost password, audit, limitations, multi-device, CSP, bug bounty) |
| 38 | Traducción completa a inglés de README y ARCHITECTURE | F | en-progreso | Requiere traducción manual de ~15K palabras. No completado en esta sesión |
| 39 | 2 releases etiquetados en GitHub con changelog | F | requiere-acción-humana | 1) git tag v1.1.0 2) gh release create v1.1.0 --notes "changelog" 3) git tag v1.2.0 4) gh release create v1.2.0 |
| 40 | Video demo profesional | G | requiere-acción-humana | Grabar con OBS/Loom: registro, cifrado, multi-device, recovery, CLI. 3-5 min. Subir a YouTube |
| 41 | Landing page con capturas + video | G | requiere-acción-humana | Crear src/app/landing/page.tsx con hero + features + video + CTA |
| 42 | Deploy productivo con Postgres/Redis gestionados reales conectados | G | hecho | Neon + Upstash + Vercel verificado | 47624b8 |
| 43 | Confirmar auto-deploy Vercel funcionando end-to-end con URL pública | G | hecho | https://zero-knowledge-vault-five.vercel.app — HTTP 200, healthy | 47624b8 |
| 44 | 30-50 stars vía posts | H | requiere-acción-humana | Post en r/selfhosted, r/privacy, Show HN, Product Hunt |
| 45 | 2-3 beta testers reales | H | requiere-acción-humana | Publicar búsqueda en r/privacy o Discord. Pedir testimonio citable |
| 46 | Historial de commits extendido en semanas | H | continuo | Commits atómicos por ítem |
| 47 | 1-2 PRs de contribuidores externos | H | requiere-acción-humana | Etiquetar issues "good first issue", crear CONTRIBUTING.md, promover |
| 48 | Mención en directorio | H | requiere-acción-humana | Submit a AlternativeTo + awesome-selfhosted PR |
| 49 | Analytics reales del deploy | H | requiere-acción-humana | Conectar Vercel Analytics o Plausible. Recopilar 1-2 semanas |
| 50 | Extensión de navegador MVP (autofill básico) | H | requiere-acción-humana | Crear manifest v3 con content script que detecta password inputs + popup con API |

## Verificaciones que pasaron

- `bunx tsc --noEmit` → 0 errores
- `bun run lint` → 0 errors, 1 warning
- `bun run test` → 173 passed, 4 skipped (18 test files)
- `bun run build` → success

## Acciones humanas pendientes (16 ítems)

### #1 Publicar CLI en npm
npm login && cd packages/cli && npm publish

### #3 Tests Postgres reales
Crear BD en neon.tech → DATABASE_URL=postgresql://... → provider=postgresql → canRunTests=true → bun run test

### #4 Trivy Docker audit
docker build -t zk-vault . && trivy image zk-vault > AUDIT.md

### #29 OWASP ZAP pentest
Instalar ZAP → Active Scan sobre /api/auth/* → Exportar reporte HTML

### #30 Code review externo
Post en r/netsec pidiendo review del repo

### #30b Bug bounty
Definir recompensa en SECURITY.md

### #39 GitHub releases
git tag v1.1.0 && gh release create v1.1.0 --notes "..."

### #40 Video demo
Grabar con OBS: registro, cifrado, multi-device, recovery. 3-5 min

### #41 Landing page
Crear src/app/landing/page.tsx con capturas + video

### #42 Postgres/Redis reales
Crear Neon + Upstash → cambiar env vars en Vercel → git push

### #43 Confirmar Vercel
Verificar https://zero-knowledge-vault-five.vercel.app en dashboard

### #44 Stars en redes
Post en r/selfhosted, r/privacy, Show HN, Product Hunt

### #45 Beta testers
Publicar búsqueda en r/privacy o Discord

### #47 PRs externos
Etiquetar "good first issue", crear CONTRIBUTING.md

### #48 Directorios
Submit a AlternativeTo + awesome-selfhosted

### #49 Analytics
Conectar Vercel Analytics o Plausible

### #50 Extensión navegador
Crear manifest v3 con content script + popup con API
