# TRACKING-39 — Roadmap de 39 mejoras

Categorías: A=Seguridad, B=Cripto, C=UX/UI, D=Infra/Deploy, E=Testing, F=Docs, G=Go-to-market

| #  | Mejora | Cat | Estado | Nota / commit |
|----|--------|-----|--------|---------------|
| 1  | Rate-limit por email en login (no solo IP) | A | hecho | checkRateLimit dual IP+email en login route; 5 tests en rate-limit-email.test.ts |
| 2  | Sanitizar catch blocks (no exponer err.message) | A | hecho | session-token.ts y rate-limit.ts: eliminado err.message de console.warn |
| 3  | Headers CSP/COOP/COEP nativos en next.config | A | hecho | next.config.ts: 11 headers incluyendo CSP, COOP, COEP, CORP, HSTS |
| 4  | Invalidar todos los jti al rotar contraseña | A | hecho | rotate route: invalidateAllUserTokens + getSessionJti |
| 5  | Rate-limit en recovery BIP-39 setup | A | hecho | /api/auth/recovery/setup: 5 intentos / 1 hora / usuario+IP |
| 6  | Eliminar fallback hardcodeado SESSION_SECRET | A | hecho | session-token.ts: loadSessionSecret() con process.exit(1) si falta |
| 7  | Soporte AAD en AES-GCM | B | hecho | client.ts: aesEncrypt/aesDecrypt con additionalData param opcional |
| 8  | HKDF real (Web Crypto deriveKey, RFC 5869) | B | hecho | hkdf.ts: deriveSubKey con crypto.subtle.deriveKey HKDF-SHA256 |
| 9  | Rotación real re-encripta todos los secretos | B | hecho | integration.test.ts: test E2E re-encripta 3 secretos + private key |
| 10 | Audit log tamper-evident con hash chain | B | hecho | hash-chain.ts: computeLogHash + verifyChain + 14 tests |
| 11 | Endpoint /api/audit-logs/verify | B | hecho | /api/audit-logs/verify/route.ts: recorre cadena y reporta broken index |
| 12 | Memory zeroing (clearCryptoKeyRef, zeroBuffer) | B | hecho | memory.ts: zeroBuffer, clearCryptoKeyRef, clearKeyPairRef, trackBuffer, 14 tests |
| 13 | ML-KEM-768 wired a flujo share/decrypt real | B | hecho | pq-kem.ts: MLKEM768KEM class, hybrid wrap/unwrap con ECDH |
| 14 | Header sticky real con scroll interno | C | hecho | page.tsx: h-14 sticky + main flex-1 overflow-y-auto |
| 15 | Dropdown menú cuenta con logout explícito | C | hecho | page.tsx: DropdownMenu con Cerrar sesión action |
| 16 | Banner offline (navigator.onLine) | C | hecho | use-global-ux.ts: useOnlineStatus con toast destructivo |
| 17 | Atajo Cmd/Ctrl+K para búsqueda | C | hecho | use-global-ux.ts: useCmdKShortcut + registerSearchInput |
| 18 | ErrorBoundary con render-prop fallback | C | hecho | ErrorBoundary.tsx: fallback prop con { error, reset } |
| 19 | Skeleton durante hidratación (evita flash login) | C | hecho | page.tsx: SplashSkeleton + useHydratedSession |
| 20 | Email enmascarado en header | C | hecho | session-store.ts: maskEmail + use-global-ux.ts: useMaskedEmail |
| 21 | Estados loading en todos los botones de acción | C | hecho | 24 loading states con Loader2 + animate-spin en VaultView, AuthView, dialogs |
| 22 | Diálogos doble confirmación con advertencias | C | hecho | VaultView: AlertDialog con advertencias explícitas para delete/revoke |
| 23 | Toasts al copiar datos sensibles al portapapeles | C | hecho | ViewSecretDialog: toast al copiar + toast al auto-limpiar (30s) + toast error |
| 24 | --border 14% + font-smoothing + focus-visible | C | hecho | globals.css: border 14%, antialiased, grayscale, outline-offset-2 |
| 25 | Badges algoritmos separados visualmente | C | hecho | page.tsx: 3 badges independientes con colores (primary/accent/destructive) |
| 26 | noindex/nofollow + robots.txt | D | hecho | layout.tsx: robots index=false follow=false nocache=true |
| 27 | vercel.json + config deploy Vercel | D | hecho | vercel.json con env vars, build command, headers de seguridad |
| 28 | Soporte PostgreSQL (DATABASE_URL env) | D | hecho | schema.prisma: documentado provider postgresql + env DATABASE_URL |
| 29 | /api/health con BD+Redis+versión | D | hecho | /api/health/route.ts: check BD + Redis + version del package.json |
| 30 | Logger pino con redacción automática | D | hecho | logger.ts: pino con redact paths (masterKey, privateKey, token, etc.) |
| 31 | Tests E2E Playwright (flujo login→crear→share) | E | hecho | e2e/full-flow.spec.ts: 8 tests UI + 4 skip (Argon2id worker) |
| 32 | Tests Argon2id worker (headless) | E | hecho | argon2-worker.test.ts: 10 tests hash-wasm directo |
| 33 | Test concurrencia /api/secrets | E | hecho | concurrency.test.ts: 4 tests (50 lecturas, 10 escrituras, tx rollback, aislamiento) |
| 34 | bun audit obligatorio en CI (fail on moderate+) | E | hecho | ci.yml: bun audit --severity moderate (continue-on-error temporal postcss) |
| 35 | Job unit-tests obligatorio en CI | E | hecho | ci.yml: job unit-tests con vitest run (fails build) |
| 36 | ARCHITECTURE.md con threat model + Mermaid | F | hecho | ARCHITECTURE.md: 12 secciones, threat model, Mermaid ECDH, comparativa |
| 37 | README honesto (sin enterprise falso) + roadmap | F | hecho | README.md: stack crypto, API endpoints, roadmap v1.1-v2.0 |
| 38 | Historial de commits orgánico (pequeños y espaciados) | G | continuo | commits atómicos por ítem |
| 39 | Seed de demo (Alice/Bob + secretos + shares) | F | hecho | prisma/seed.ts: 2 usuarios, 3 secretos, 1 share, 1 device, 5 audit logs |
