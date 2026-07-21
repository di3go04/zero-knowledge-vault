# TRACKING-39 — Roadmap de 39 mejoras

Categorías: A=Seguridad, B=Cripto, C=UX/UI, D=Infra/Deploy, E=Testing, F=Docs, G=Go-to-market

| #  | Mejora | Cat | Estado | Nota / commit |
|----|--------|-----|--------|---------------|
| 1  | Rate-limit por email en login (no solo IP) | A | hecho | implementado en commit anterior; test unitario añadido (5 tests) que verifica bloqueo N+1, independencia IP/email, reset tras login exitoso |
| 2  | Sanitizar catch blocks (no exponer err.message) | A | pendiente | |
| 3  | Headers CSP/COOP/COEP nativos en next.config | A | pendiente | |
| 4  | Invalidar todos los jti al rotar contraseña | A | pendiente | |
| 5  | Rate-limit en recovery BIP-39 setup | A | pendiente | |
| 6  | Eliminar fallback hardcodeado SESSION_SECRET | A | pendiente | |
| 7  | Soporte AAD en AES-GCM | B | pendiente | |
| 8  | HKDF real (Web Crypto deriveKey, RFC 5869) | B | pendiente | |
| 9  | Rotación real re-encripta todos los secretos | B | pendiente | |
| 10 | Audit log tamper-evident con hash chain | B | pendiente | |
| 11 | Endpoint /api/audit-logs/verify | B | pendiente | |
| 12 | Memory zeroing (clearCryptoKeyRef, zeroBuffer) | B | pendiente | |
| 13 | ML-KEM-768 wired a flujo share/decrypt real | B | pendiente | |
| 14 | Header sticky real con scroll interno | C | pendiente | |
| 15 | Dropdown menú cuenta con logout explícito | C | pendiente | |
| 16 | Banner offline (navigator.onLine) | C | pendiente | |
| 17 | Atajo Cmd/Ctrl+K para búsqueda | C | pendiente | |
| 18 | ErrorBoundary con render-prop fallback | C | pendiente | |
| 19 | Skeleton durante hidratación (evita flash login) | C | pendiente | |
| 20 | Email enmascarado en header | C | pendiente | |
| 21 | Estados loading en todos los botones de acción | C | pendiente | |
| 22 | Diálogos doble confirmación con advertencias | C | pendiente | |
| 23 | Toasts al copiar datos sensibles al portapapeles | C | pendiente | |
| 24 | --border 14% + font-smoothing + focus-visible | C | pendiente | |
| 25 | Badges algoritmos separados visualmente | C | pendiente | |
| 26 | noindex/nofollow + robots.txt | D | pendiente | |
| 27 | vercel.json + config deploy Vercel | D | pendiente | |
| 28 | Soporte PostgreSQL (DATABASE_URL env) | D | pendiente | |
| 29 | /api/health con BD+Redis+versión | D | pendiente | |
| 30 | Logger pino con redacción automática | D | pendiente | |
| 31 | Tests E2E Playwright (flujo login→crear→share) | E | pendiente | |
| 32 | Tests Argon2id worker (headless) | E | pendiente | |
| 33 | Test concurrencia /api/secrets | E | pendiente | |
| 34 | bun audit obligatorio en CI (fail on moderate+) | E | pendiente | |
| 35 | Job unit-tests obligatorio en CI | E | pendiente | |
| 36 | ARCHITECTURE.md con threat model + Mermaid | F | pendiente | |
| 37 | README honesto (sin enterprise falso) + roadmap | F | pendiente | |
| 38 | Historial de commits orgánico (pequeños y espaciados) | G | continuo | |
| 39 | Seed de demo (Alice/Bob + secretos + shares) | F | pendiente | |
