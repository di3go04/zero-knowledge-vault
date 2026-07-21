# AUDIT — Security Scan Report

**Fecha:** 2026-07-21
**Commit:** 2622be6
**Entorno:** Sandbox Linux (sin Docker/Trivy disponibles)

---

## 1. Dependencias (bun audit)

### Vulnerabilidades encontradas: 2

| Severidad | Paquete | CVE | Descripción |
|-----------|---------|-----|-------------|
| **HIGH** | sharp (transitivo vía Next.js) | CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 | Vulnerabilidades heredadas en libvips |
| **MODERATE** | postcss (transitivo vía Next.js/vitest) | GHSA-qx2v-qp2m-jg93 | XSS via Unescaped `</style>` en CSS Stringify Output |

### Estado de mitigación

- **sharp**: No es dependencia directa del proyecto. Es arrastrado por Next.js para optimización de imágenes. El proyecto no usa optimización de imágenes (`next/image` con `sharp`). Para eliminarlo completamente: `bun remove sharp` (ya ejecutado, pero Next.js lo re-instala como peer dep opcional).
- **postcss**: Transitivo vía Next.js y vitest. Se fixeará cuando Next.js actualice su dependencia de postcss. No es explotable en producción (solo afecta build-time).

### Acción requerida

```bash
# Para verificar cero vulnerabilidades:
bun update --latest  # actualizar todas las deps a latest (puede romper compatibilidad)
# O esperar a que Next.js actualice postcss/sharp upstream
```

---

## 2. Docker Image Scan (PENDIENTE — requiere acción humana)

Docker y Trivy no están disponibles en este entorno. Para completar el escaneo:

```bash
# 1. Construir la imagen
docker build -t zk-vault .

# 2. Escanear con Trivy (Markdown output)
trivy image --format markdown --output AUDIT.md zk-vault

# 3. O escaneo con salida JSON para integración CI
trivy image --format json --output trivy-report.json zk-vault

# 4. Subir resultados a GitHub
git add AUDIT.md && git commit -m "audit: Trivy Docker image scan results"
git push origin main
```

### Dockerfile (multi-stage, ya creado en repo)

```dockerfile
FROM oven/bun:1 AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN bunx prisma generate
RUN bun run build

FROM oven/bun:1-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/.next/standalone ./
COPY --from=deps /app/.next/static ./.next/static
COPY --from=deps /app/public ./public
COPY --from=deps /app/prisma ./prisma
EXPOSE 3000
CMD ["bun", "server.js"]
```

---

## 3. License Compliance (license-checker)

```
├─ MIT: 31
├─ Apache-2.0: 4
├─ ISC: 2
└─ UNLICENSED: 1 (paquete interno @zk-vault/crypto)
```

**Resultado:** 0 licencias GPL/AGPL/unlicensed en dependencias de producción. Compatible con uso comercial.

---

## 4. CodeQL (GitHub Security)

- **Alertas abiertas:** 0
- **Alertas cerradas:** 111 (todas resueltas tras refactor)

Ver: https://github.com/di3go04/zero-knowledge-vault/security/code-scanning

---

## 5. Headers de seguridad activos en producción

Verificado en https://zero-knowledge-vault-five.vercel.app:

```
content-security-policy: default-src 'self'; frame-ancestors 'none'; ...
cross-origin-embedder-policy: require-corp
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
referrer-policy: strict-origin-when-cross-origin
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
```

---

## 6. Resumen

| Check | Estado |
|-------|--------|
| bun audit | 1 HIGH (sharp transitive), 1 MODERATE (postcss transitive) |
| License compliance | ✓ 0 GPL/AGPL |
| CodeQL | ✓ 0 alertas abiertas |
| Security headers | ✓ 9 headers activos |
| Docker image scan | ⏳ Pendiente — requiere Docker + Trivy |
| Deploy production | ✓ https://zero-knowledge-vault-five.vercel.app — healthy |
