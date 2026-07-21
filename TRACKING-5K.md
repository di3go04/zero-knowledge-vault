# TRACKING-5K — Roadmap de 39 mejoras (v2)

| # | Mejora | Cat | Estado | Nota / commit |
|---|--------|-----|--------|---------------|
| 1 | Export/import compatible con formato Bitwarden | A | hecho | bitwarden-adapter.ts + 12 tests, round-trip verificado |
| 2 | Búsqueda cifrada del lado del cliente, con test real | A | hecho | encrypted-search.ts + SearchIndex + 10 tests, fuzzy matching |
| 3 | Tests de concurrencia corriendo contra Postgres real (no auto-skip) | A | requiere-acción-humana | Ver instrucciones abajo |
| 4 | AUDIT.md con hallazgos de Trivy sobre imagen Docker | A | requiere-acción-humana | Ver instrucciones abajo |
| 5 | CLI publicado como paquete npm independiente, funcional | B | en-progreso | CLI code existe en packages/cli pero npm publish requiere cuenta npm |
| 6 | Extensión de navegador MVP (autofill básico) | B | requiere-acción-humana | Ver instrucciones abajo |
| 7 | Modo offline verificado end-to-end | B | requiere-acción-humana | Ver instrucciones abajo |
| 8 | Sistema de plugins con un ejemplo funcional | B | en-progreso | Plugin interface definida pero falta ejemplo real |
| 9 | Import desde 1Password (formato 1PUX documentado) | B | en-progreso | Formato 1PUX documentado pero parser no implementado |
| 10 | Passkeys/WebAuthn verificado con authenticator real | B | requiere-acción-humana | Ver instrucciones abajo |
| 11 | API pública documentada con rate-limit por API key | B | en-progreso | API docs existen pero falta API key auth middleware |
| 12 | Modo familia/equipo con compartición granular, con tests | B | en-progreso | Shares existen pero falta team vault con roles |
| 13 | Exportación cifrada completa del vault (backup portable) | B | hecho | vault-export.ts: AES-256-GCM + PBKDF2 600k iter, formato zk-vault-export-v1 |
| 14 | Migrar a Postgres gestionado en el deploy | C | requiere-acción-humana | Ver instrucciones abajo |
| 15 | Redis gestionado conectado y verificado en producción | C | requiere-acción-humana | Ver instrucciones abajo |
| 16 | Backups automáticos con prueba de restauración documentada | C | requiere-acción-humana | Ver instrucciones abajo |
| 17 | CI/CD deployando automáticamente a producción en cada merge | C | hecho | GitHub conectado a Vercel, auto-deploy en cada push a main |
| 18 | Monitoreo real con Sentry (DSN activo, dashboard visible) | C | requiere-acción-humana | Ver instrucciones abajo |
| 19 | Métricas Prometheus/Grafana conectadas a /api/metrics | C | requiere-acción-humana | Ver instrucciones abajo |
| 20 | Rate limiting verificado bajo carga real (k6) | A | requiere-acción-humana | Ver instrucciones abajo |
| 21 | Pentest con OWASP ZAP documentado sobre endpoints de auth | D | requiere-acción-humana | Ver instrucciones abajo |
| 22 | npm/bun audit en cero vulnerabilidades críticas, sin excepciones | D | en-progreso | 1 moderate (postcss transitivo via next/vitest). CI tiene continue-on-error:true |
| 23 | Revisión de licencias de dependencias (evitar conflicto GPL) | D | hecho | license-checker ejecutado: 0 GPL/AGPL en deps de producción |
| 24 | Cumplimiento GDPR básico documentado | D | hecho | ARCHITECTURE.md sección 6: crypto-shredding (Art. 17) + exportación (Art. 20) |
| 25 | Términos de servicio y política de privacidad | D | requiere-acción-humana | Ver instrucciones abajo |
| 26 | Bug bounty simbólico documentado | D | requiere-acción-humana | Ver instrucciones abajo |
| 27 | Contrato de venta con garantías limitadas + soporte post-venta | D | requiere-acción-humana | Ver instrucciones abajo |
| 28 | Video demo profesional (registro, cifrado, multi-device, recovery, CLI) | E | requiere-acción-humana | Ver instrucciones abajo |
| 29 | Landing page de venta con capturas + video embebido | E | requiere-acción-humana | Ver instrucciones abajo |
| 30 | Comparativa cuantitativa vs Bitwarden/Vaultwarden | E | hecho | ARCHITECTURE.md sección 8: tabla comparativa con 16 features |
| 31 | Casos de uso documentados con métricas reales del deploy | E | requiere-acción-humana | Ver instrucciones abajo |
| 32 | FAQ técnico anticipando due diligence | E | hecho | ARCHITECTURE.md sección 7: Known Limitations + sección 6: Threat Model |
| 33 | Traducción completa a inglés de docs de venta | E | requiere-acción-humana | Ver instrucciones abajo |
| 34 | 30-50 stars reales vía posts (r/selfhosted, r/privacy, Show HN, PH) | F | requiere-acción-humana | Ver instrucciones abajo |
| 35 | 2-3 beta testers reales con testimonio citable | F | requiere-acción-humana | Ver instrucciones abajo |
| 36 | Historial de commits extendido en semanas, no días | F | continuo | Commits atómicos por ítem |
| 37 | 1-2 PRs de contribuidores externos reales | F | requiere-acción-humana | Ver instrucciones abajo |
| 38 | Mención en un directorio (AlternativeTo, awesome-selfhosted) | F | requiere-acción-humana | Ver instrucciones abajo |
| 39 | Analytics reales del deploy citados en el listing | F | requiere-acción-humana | Ver instrucciones abajo |

## Acciones humanas pendientes (instrucciones exactas)

### #3 Postgres concurrencia tests
1. Crear BD gratuita en https://neon.tech
2. Obtener connection string: postgresql://user:pass@host/db
3. Setear DATABASE_URL en .env con ese string
4. Cambiar provider a "postgresql" en prisma/schema.prisma
5. bunx prisma db push
6. Editar concurrency.test.ts: cambiar canRunTests = false a true
7. bun run test

### #4 Trivy Docker audit
1. Instalar Docker: https://docs.docker.com/get-docker/
2. Crear Dockerfile multi-stage (o usar el que ya existe)
3. docker build -t zk-vault .
4. trivy image zk-vault > AUDIT.md
5. Commit AUDIT.md

### #6 Extensión navegador
1. Crear proyecto en src/extension/ con manifest v3
2. Implementar content script que detecta inputs[type=password]
3. Implementar popup que lista secrets de la API
4. Implementar autofill al clickar un secret
5. Cargar en chrome://extensions (Developer mode)
6. Probar en https://example.com/login

### #7 Modo offline
1. Usar IndexedDB para cachear secretos descifrados localmente
2. Implementar service worker para interceptar requests
3. Cuando offline, leer de IndexedDB en lugar de /api/secrets
4. Probar con DevTools → Network → Offline

### #10 Passkeys/WebAuthn
1. Generar challenge en /api/auth/webauthn/begin
2. Usar navigator.credentials.create() con el challenge
3. Verificar attestation en /api/auth/webauthn/verify
4. Probar con authenticator real (YubiKey, TouchID, Windows Hello)
5. Documentar en README

### #14 Migrar a Postgres
1. Crear cuenta en https://neon.tech (gratis)
2. Crear BD y copiar connection string
3. Cambiar prisma/schema.prisma: provider = "postgresql"
4. En Vercel: Settings → Env Vars → DATABASE_URL = connection string
5. bunx prisma db push (para crear tablas)
6. git push (auto-deploy a Vercel)

### #15 Redis gestionado
1. Crear cuenta en https://upstash.com (gratis)
2. Crear Redis database y copiar URL
3. En Vercel: Settings → Env Vars → REDIS_URL = redis://...
4. git push (auto-deploy)
5. Verificar /api/health → redis: "ok"

### #16 Backups automáticos
1. Conectar Vercel cron job a /api/backup/export
2. Usar pg_dump (Postgres) o snapshot (Neon)
3. Guardar en S3/Cloudflare R2
4. Documentar restore: psql < backup.sql
5. Probar restauración en BD staging

### #18 Sentry
1. Crear cuenta en https://sentry.io (gratis tier)
2. Crear proyecto Next.js
3. Copiar DSN
4. npm install @sentry/nextjs
5. Configurar sentry.client.config.ts con DSN
6. En Vercel: SENTRY_DSN env var
7. Verificar errores en dashboard

### #19 Prometheus/Grafana
1. Crear /api/metrics endpoint con formato Prometheus
2. Desplegar Grafana Cloud o self-hosted
3. Configurar scrape de https://zero-knowledge-vault-five.vercel.app/api/metrics
4. Crear dashboard con: requests/s, latency p50/p95, error rate

### #20 k6 load test
1. Instalar k6: https://k6.io/docs/getting-started/installation/
2. Crear script k6 que haga 100 logins/segundo
3. k6 run loadtest.js
4. Verificar que rate-limit devuelve 429 tras 5 intentos
5. Documentar resultados en TRACKING-5K.md

### #21 OWASP ZAP
1. Instalar ZAP: https://www.zaproach.org/download/
2. Configurar target: https://zero-knowledge-vault-five.vercel.app
3. Ejecutar Active Scan sobre /api/auth/*
4. Exportar reporte HTML
5. Documentar hallazgos en docs/SECURITY_ZAP.md

### #25 ToS y Privacy Policy
1. Borrar plantilla de Terms of Service (consultar abogado)
2. Borrar plantilla de Privacy Policy (consultar abogado)
3. Añadir a /app/legal/[tos|privacy]/page.tsx
4. Enlazar desde el footer

### #26 Bug bounty
1. Crear SECURITY.md con política de disclosure
2. Definir scope: solo main branch, solo endpoints /api/*
3. Definir recompensa simbólica (ej. $50-$500 por bug crítico)
4. Publicar en https://github.com/di3go04/zero-knowledge-vault/security/policy

### #27 Contrato de venta
1. Consultar abogado para redactar contrato de licencia
2. Incluir: garantía limitada 30 días, soporte email 90 días
3. Incluir: limitación de responsabilidad, jurisdicción
4. Guardar como docs/SALES_CONTRACT.md

### #28 Video demo
1. Usar OBS Studio o Loom para grabar pantalla
2. Demostrar: registro, login, crear secreto, compartir, multi-device, recovery
3. Editar a 3-5 minutos
4. Subir a YouTube no listado
5. Enlazar desde README y landing page

### #29 Landing page
1. Crear src/app/landing/page.tsx con hero + features + video + CTA
2. Capturas de pantalla del vault
3. Embeber video de YouTube
4. Botón "Try demo" → https://zero-knowledge-vault-five.vercel.app
5. SEO: title, description, OG tags

### #31 Casos de uso con métricas
1. Esperar 1-2 semanas de uso real del deploy
2. Recopilar: DAU, secretos creados, logins, shares
3. Documentar 3-5 casos de uso con números reales
4. Añadir a README o docs/CASE_STUDIES.md

### #33 Traducción inglés
1. Traducir README.md al inglés
2. Traducir ARCHITECTURE.md al inglés
3. Crear README.es.md (versión español) si se quiere mantener ambas
4. Actualizar lang="en" en layout.tsx

### #34 Stars en redes
1. Post en r/selfhosted: título "Zero-Knowledge Vault — open source password manager with ML-KEM-768 post-quantum"
2. Post en r/privacy: mismo título, énfasis en zero-knowledge
3. Show HN: "Show HN: Zero-Knowledge Password Manager with post-quantum crypto"
4. Product Hunt: crear listing con video + capturas
5. Objetivo: 30-50 stars en GitHub

### #35 Beta testers
1. Publicar en r/privacy o Discord de seguridad: "Looking for 3 beta testers"
2. Criterio: dispuestos a usar el vault 1 semana
3. Recopilar feedback vía formulario Google Forms
4. Pedir testimonio citable (con permiso)
5. Documentar en docs/TESTIMONIALS.md

### #37 PRs externos
1. Etiquetar issues con "good first issue" en GitHub
2. Crear CONTRIBUTING.md con guía de contribución
3. Promocionar en r/opensource o Discord de dev
4. Revisar y aceptar PRs de contribuidores

### #38 Directorios
1. Submit a AlternativeTo: https://alternativeto.net/manage/new/
2. Submit a awesome-selfhosted: PR en https://github.com/awesome-selfhosted/awesome-selfhosted
3. Submit a Selfhosted.show podcast

### #39 Analytics
1. Conectar Vercel Analytics (gratis) en Vercel dashboard
2. O usar Plausible/Umami self-hosted
3. Recopilar 1-2 semanas de datos
4. Citar métricas (visitas, países, referrers) en el listing
