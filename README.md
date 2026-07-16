# Zero-Knowledge Vault

Gestor de Contraseñas Zero-Knowledge para Equipos — cifrado end-to-end en el navegador con Web Crypto API.

> **El servidor es un *crypto-blind store***: solo almacena blobs cifrados, sales públicas, IVs y llaves públicas. Nunca recibe ni puede descifrar contraseñas maestras, llaves privadas, llaves AES simétricas, ni el contenido de ningún secreto.

---

## Tabla de Contenidos

- [Visión General](#visión-general)
- [Garantías Zero-Knowledge](#garantías-zero-knowledge)
- [Arquitectura Técnica](#arquitectura-técnica)
- [Prerrequisitos de Entorno](#prerrequisitos-de-entorno)
- [Instalación y Ejecución](#instalación-y-ejecución)
- [Variables de Entorno](#variables-de-entorno)
- [Flujo Multi-Device](#flujo-multi-device)
- [Testing](#testing)
- [Seguridad](#seguridad)
- [Auditoría del Código](#auditoría-del-código)

---

## Visión General

Zero-Knowledge Vault es un gestor de contraseñas para equipos donde **todo el cifrado ocurre en el navegador** del cliente usando Web Crypto API. El servidor actúa como un almacén ciego (*crypto-blind store*) que persiste blobs cifrados sin poder interpretarlos.

### ¿Qué significa Zero-Knowledge aquí?

| El servidor NUNCA recibe | El servidor SÍ almacena |
|---|---|
| Contraseña maestra | Email del usuario (para login) |
| Llave maestra derivada (PBKDF2/Argon2id) | Salt público + iteraciones KDF |
| Llave privada RSA en claro | Llave privada RSA **cifrada** (AES-256-GCM) |
| Llave AES simétrica de secretos | Llaves AES **envueltas** (RSA-OAEP) |
| Contenido de secretos | Blobs cifrados (AES-256-GCM) |
| Frase BIP-39 de recuperación | Backup cifrado con recovery key |
| Contenido de logs de auditoría | Logs cifrados (AES-256-GCM) |

**Si la base de datos se compromete**, el atacante obtiene solo blobs cifrados que requieren:
- La contraseña maestra (para PBKDF2/Argon2id → masterKey → descifrar privateKey)
- O la frase BIP-39 de recuperación (256 bits de entropía)

Sin ninguno de los dos, los datos son criptográficamente inaccesibles.

---

## Garantías Zero-Knowledge

1. **Cifrado AES-256-GCM en el cliente** — título, contenido y llave privada RSA se cifran antes de salir del navegador.
2. **KDF Argon2id** (memory-hard, 64 MiB) — resistente a ataques GPU/ASIC. Fallback honesto a PBKDF2 (600k iteraciones) si el Web Worker falla.
3. **RSA-OAEP 2048-bit** — cifrado asimétrico para envolver (wrap) llaves AES compartidas entre usuarios.
4. **ECDH P-256** — intercambio de llaves para Multi-Device Sync.
5. **ECDSA P-256 Challenge-Response** — el flujo Enroll Device verifica posesión de la privateKey ECDH.
6. **BIP-39 (24 palabras, 256 bits)** — backup de recuperación cifrado.
7. **Proof-of-Possession (RSA-PSS)** en registro — previene sustitución de publicKey.
8. **TOFU con fingerprint SHA-256** — el cliente verifica que la publicKey del destinatario coincide con la del servidor.
9. **Login decoy anti-enumeración** — usuarios inexistentes reciben respuesta idéntica a usuarios reales.
10. **Tokens HMAC-signed (HS256) con jti** — logout server-side real con blacklist Redis.
11. **Rate limiting** en endpoints sensibles (login, enroll/verify, enroll/lookup, enroll/init).
12. **Validación Zod estricta** en 14 endpoints — rechaza cualquier payload que no sea base64 válido con longitud de blob AES-GCM.
13. **Memory zeroing** en todos los diálogos UI — `clearCryptoKeyRef`, `clearKeyPairRef`, `zeroBuffer`.
14. **Audit log cifrado** — logs generados y cifrados en el cliente con llave derivada de masterKey.
15. **Redis adaptadores** (blacklist, rate-limit, challenge-store) con fallback transparente a Map in-memory.

---

## Arquitectura Técnica

### Stack

| Capa | Tecnología |
|------|-----------|
| Framework | Next.js 16 (App Router, Turbopack) |
| Lenguaje | TypeScript 5 (strict) |
| UI | Tailwind CSS 4 + shadcn/ui (New York) |
| BD | Prisma ORM + SQLite |
| Criptografía | Web Crypto API (PBKDF2, Argon2id, AES-256-GCM, RSA-OAEP, RSA-PSS, ECDH, ECDSA) |
| KDF | Argon2id vía `hash-wasm` en Web Worker |
| Recuperación | BIP-39 (24 palabras) |
| Blacklist | Redis (`ioredis`) con fallback Map in-memory |
| Validación | Zod (14 schemas centralizados) |
| Tests E2E | Playwright |
| Estado | Zustand (memoria no persistente) |

### Endpoints REST (16 + health)

| Endpoint | Método | Descripción | Auth |
|----------|--------|-------------|------|
| `/api/auth/register` | POST | Registro con PoP RSA-PSS | No |
| `/api/auth/login` | POST | Login + emite sessionToken HS256 | No |
| `/api/auth/logout` | POST | Revoca jti en blacklist | Sí |
| `/api/auth/rotate` | POST | Rota contraseña maestra | Sí |
| `/api/auth/recovery/setup` | POST | Configura backup BIP-39 | Sí |
| `/api/auth/recovery/recover` | POST | Recupera cuenta con frase BIP-39 | No |
| `/api/secrets` | GET/POST | Lista/Crea secretos cifrados | Sí |
| `/api/secrets/[id]` | DELETE | Borra secreto (owner-only) | Sí |
| `/api/shares` | POST/DELETE | Comparte/Revoca share | Sí |
| `/api/devices/enroll/init` | POST | Dispositivo B inicia enrollment | No |
| `/api/devices/enroll/lookup` | GET | Dispositivo A busca por enrollCode | Sí |
| `/api/devices/enroll/complete` | POST | Dispositivo A envía wrappedKey | Sí |
| `/api/devices/enroll/poll` | POST | Dispositivo B pide challenge | No |
| `/api/devices/enroll/poll/verify` | POST | Dispositivo B verifica challenge ECDSA | No |
| `/api/devices/list` | GET | Lista dispositivos autorizados | Sí |
| `/api/devices/[id]` | DELETE | Revoca dispositivo | Sí |
| `/api/users/lookup` | GET | Busca usuario por email | No |
| `/api/users/list` | GET | Lista usuarios del equipo | Sí |
| `/api/audit-logs` | GET/POST | Lista/Crea logs cifrados | Sí |

### Tablas Prisma (6)

```
User              — id, email, name
UserKeyMaterial   — kdfAlgorithm, kdfSalt, kdfIterations, kdfMemoryKiB, kdfParallelism,
                    publicKeyJwk, publicKeyFingerprint, popSignature,
                    encryptedPrivateKeyJwk, privateKeyIv,
                    recoverySalt, recoveryIterations, encryptedPrivateKeyForRecovery, recoveryIv, recoveryEnabled
Secret            — ownerId, encryptedTitle, titleIv, encryptedData, dataIv
SecretKeyShare    — secretId, recipientId, wrappedSymmetricKey
Device            — userId, deviceName, publicKeyECDH, publicKeyECDHFingerprint,
                    enrollerPublicKeyECDH, wrappedPrivateKeyForDevice, wrappedPrivateKeyIv,
                    enrollCode, enrollCodeExpiresAt, revokedAt
AuditLog          — userId, encryptedEvent, eventIv, eventCategory
```

### Web Worker (Argon2id)

- **Archivo**: `src/lib/argon2-worker.ts`
- **Librería**: `hash-wasm` (compatible con Turbopack)
- **Parámetros OWASP 2024**: `m=64 MiB, t=3, p=4`
- **Timeout**: 10s (no cuelga el worker indefinidamente)
- **Fallback**: si el worker falla, `deriveMasterKey` propaga el error y `performRegistration` hace fallback honesto a PBKDF2 (reporta `kdfAlgorithm="pbkdf2"` al servidor)

---

## Prerrequisitos de Entorno

### Desarrollo local

| Requisito | Versión mínima | Notas |
|-----------|----------------|-------|
| **Bun** | 1.0+ | Runtime recomendado (más rápido que Node) |
| **Node.js** | 20+ | Alternativo a Bun |
| **Navegador** | Chrome 94+, Firefox 90+, Safari 15+ | Soporte Web Crypto API + WASM |

### Producción

| Requisito | Versión | Obligatorio |
|-----------|---------|-------------|
| **Redis** | 6+ | Recomendado (blacklist distribuida, rate-limit, challenge-store). Sin Redis, usa Map in-memory (single-process) |
| **Node.js** | 20+ | Para servidor Next.js standalone |
| **HTTPS** | TLS 1.2+ | Obligatorio (sin HTTPS, Web Crypto API no está disponible en algunos navegadores) |

### Navegadores soportados (WASM)

| Navegador | Argon2id (WASM) | Fallback PBKDF2 |
|-----------|-----------------|-----------------|
| Chrome 94+ | ✅ | Automático si WASM falla |
| Firefox 90+ | ✅ | Automático |
| Safari 15+ | ✅ | Automático |
| Edge 94+ | ✅ | Automático |
| iOS Safari 15+ | ✅ | Automático |

---

## Instalación y Ejecución

### Desarrollo

```bash
# 1. Clonar el repositorio
git clone <repo-url>
cd zero-knowledge-vault

# 2. Instalar dependencias
bun install

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores (ver sección Variables de Entorno)

# 4. Inicializar base de datos
bun run db:push

# 5. Iniciar servidor de desarrollo
bun run dev
# Servidor disponible en http://localhost:3000
```

### Producción

```bash
# 1. Build
bun run build

# 2. Iniciar servidor standalone
bun run start

# O con Node.js:
NODE_ENV=production node .next/standalone/server.js
```

### Scripts disponibles

| Script | Descripción |
|--------|-------------|
| `bun run dev` | Servidor de desarrollo (puerto 3000) |
| `bun run build` | Build de producción |
| `bun run start` | Servidor de producción standalone |
| `bun run lint` | ESLint (debe pasar con 0 errores) |
| `bun run db:push` | Sincronizar schema Prisma con BD |
| `bun run db:generate` | Regenerar Prisma Client |
| `bun run db:reset` | Resetear BD (¡borra todos los datos!) |

### Tests E2E

```bash
# Instalar Playwright
npx playwright install

# Asegurar que el dev server está corriendo
bun run dev &

# Ejecutar tests E2E
npx playwright test

# Modo interactivo
npx playwright test --ui

# Solo el test multi-device
npx playwright test scripts/e2e-multi-device.spec.ts
```

---

## Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```bash
# === Base de datos ===
DATABASE_URL=file:/home/z/my-project/db/custom.db

# === Sesión ===
# Secreto para firmar tokens HS256. MÍNIMO 32 caracteres.
# Generar con: openssl rand -base64 48
SESSION_SECRET=zk-vault-session-secret-change-in-prod-min-32-chars!!

# === Redis (OPCIONAL — sin esto, usa Map in-memory) ===
# Si está definido, se usa para:
#   - Blacklist de tokens revocados (logout server-side)
#   - Rate limiting distribuido
#   - Challenge store ECDSA (multi-instancia)
REDIS_URL=redis://localhost:6379

# === Decoy login (OPCIONAL) ===
# Clave HMAC para generar respuestas decoy deterministas en login de
# usuarios inexistentes. Cambiar en producción.
DECOY_HMAC_KEY=zk-vault-decoy-static-key-change-me
```

### Variables por entorno

| Variable | Desarrollo | Producción | Descripción |
|----------|-----------|------------|-------------|
| `DATABASE_URL` | `file:./db/custom.db` | `postgresql://...` | SQLite en dev, PostgreSQL en prod |
| `SESSION_SECRET` | Cualquier string 32+ chars | Aleatorio seguro | Firma de tokens HS256 |
| `REDIS_URL` | *(no definida)* | `redis://redis:6379` | Sin definir = Map in-memory |
| `DECOY_HMAC_KEY` | Default | Aleatorio seguro | Anti-enumeración login |

### Flags internos (no variables de entorno)

| Flag | Ubicación | Default | Descripción |
|------|-----------|---------|-------------|
| `PREFER_ARGON2` | `crypto-client.ts` | `true` | Intenta Argon2id primero, fallback honesto a PBKDF2 |
| `USE_ARGON2` | *(eliminado)* | — | Reemplazado por `PREFER_ARGON2` con fallback automático |

---

## Flujo Multi-Device

El flujo Multi-Device permite que un usuario acceda desde un dispositivo nuevo sin comprometer la llave privada maestra.

### Roles

- **Dispositivo A**: ya autenticado, autoriza al nuevo dispositivo.
- **Dispositivo B**: nuevo, quiere acceder a la cuenta.

### Flujo paso a paso

```
┌─────────────────┐                    ┌─────────────────┐
│  Dispositivo B  │                    │  Dispositivo A  │
│  (nuevo)        │                    │  (autenticado)  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
   1. Genera par ECDH efímero (P-256)          │
         │                                      │
   2. POST /api/devices/enroll/init            │
      { email, publicKeyECDH }                 │
         │                                      │
         │◄─────────────────────────────────────│
         │  { enrollCode: "123456", deviceId }  │
         │                                      │
   3. Muestra enrollCode al usuario             │
         │                                      │
         │           Usuario introduce código   │
         │           en Dispositivo A           │
         │                                      │
         │                 4. GET /api/devices/enroll/lookup?code=123456
         │◄─────────────────────────────────────│
         │                 { publicKeyECDH, fingerprint } (de B)
         │                                      │
         │                 5. Genera par ECDH efímero (A)
         │                    Deriva shared secret: A.priv × B.pub
         │                    Envuelve privateKey RSA con shared secret
         │                                      │
         │                 6. POST /api/devices/enroll/complete
         │                    { enrollCode, wrappedPrivateKey,
         │                      enrollerPublicKeyECDH }
         │                                      │
         │  (polling)                           │
   7. POST /api/devices/enroll/poll             │
      { deviceId }                              │
         │◄─────────────────────────────────────│
         │  { challenge: "nonce_32_bytes" }     │
         │                                      │
   8. Firma challenge con ECDSA P-256           │
      (privateKey ECDH de B)                    │
         │                                      │
   9. POST /api/devices/enroll/poll/verify      │
      { deviceId, challenge, signature }        │
         │◄─────────────────────────────────────│
         │  { wrappedPrivateKey,                │
         │    enrollerPublicKeyECDH }           │
         │                                      │
  10. Deriva shared secret: B.priv × A.pub      │
      (usando enrollerPublicKeyECDH)            │
         │                                      │
  11. Desenvuelve privateKey RSA                │
      (AES-256-GCM con shared secret)           │
         │                                      │
  12. Guarda privateKey en sesión               │
      → redirige al dashboard                   │
```

### Campo `enrollerPublicKeyECDH`

**¿Por qué es necesario?** El Dispositivo B necesita derivar el mismo shared secret ECDH que el Dispositivo A usó para envolver la privateKey. Para ello, B necesita la publicKey efímera de A.

**Flujo del dato**:
1. Dispositivo A genera par ECDH efímero.
2. A deriva shared secret: `A.privateKey × B.publicKey`.
3. A envuelve privateKey RSA con el shared secret.
4. A envía al servidor: `wrappedPrivateKey` + `enrollerPublicKeyECDH` (publicKey efímera de A).
5. Servidor guarda `enrollerPublicKeyECDH` en la tabla `Device`.
6. Dispositivo B recibe `enrollerPublicKeyECDH` del servidor (en `poll/verify`).
7. B deriva el mismo shared secret: `B.privateKey × A.publicKey`.
8. B desenvuelve la privateKey RSA.

**El servidor nunca ve**: la privateKey ECDH de A, la privateKey ECDH de B, el shared secret, ni la privateKey RSA en claro.

---

## Testing

### Tests E2E (Playwright)

```bash
# Instalar Playwright
npx playwright install

# Ejecutar todos los tests
npx playwright test
```

**Cobertura**:
- **Multi-Device E2E**: registro → crear secreto → enroll device → verificar challenge-response → descifrar
- **No-leak assertion**: interceptor de red verifica que la contraseña maestra NUNCA aparece en peticiones `/api/*`
- **Validación Zod**: 6 tests que verifican 400/401 en payloads inválidos
- **Rate limiting**: verifica 429 tras exceder límite

### Lint

```bash
bun run lint
# Debe pasar con 0 errores y 0 warnings
```

---

## Seguridad

### Modelo de amenazas

| Amenaza | Mitigación |
|---------|------------|
| **BD comprometida** | Solo blobs cifrados. Sin contraseña maestra → sin PBKDF2/Argon2id → sin descifrado |
| **MITM activo** | TOFU con fingerprint SHA-256 + HTTPS obligatorio |
| **Servidor malicioso** | Sustitución de publicKey detectada por PoP + TOFU |
| **Fuerza bruta offline** | Argon2id (64 MiB memory-hard) + rate limiting |
| **Fuerza bruta ECDSA** | Rate limiting 5/min en `poll/verify` |
| **Enumeración de emails** | Login decoy determinista (HMAC-SHA-256) |
| **Sesión comprometida** | Logout server-side real (Redis blacklist con jti + TTL) |
| **Dispositivo perdido** | Revocación de dispositivo + rotación de contraseña maestra |
| **Contraseña olvidada** | Recovery Key BIP-39 (24 palabras, 256 bits) |

### Reporte de auditoría

Ver `docs/SECURITY_AUDIT_REPORT.md` para el reporte formal de seguridad.

---

## Auditoría del Código

Cualquier revisor (humano o IA) puede auditar el código sistemáticamente y producir una lista de 30+ mejoras concretas.

### Auditoría con un comando

```bash
bun install
bun run audit:full
```

Genera un reporte Markdown en `audit-reports/latest.md` con: SAST (ESLint + Semgrep), SCA (bun audit + Snyk), secret scanning (gitleaks), container scanning (Trivy), auditoría criptográfica específica, verificación de la propiedad zero-knowledge, complejidad ciclomática, dead-code, type-coverage, SBOM (CycloneDX), inventario de endpoints, higiene del historial git, y más.

### Auditorías específicas

```bash
bun run audit:crypto    # Primitivas criptográficas (requeridas + prohibidas)
bun run audit:zk        # Verifica que el servidor nunca reciba plaintext
bun run audit:deps      # Dependencias (bun audit)
bun run semgrep         # SAST con reglas OWASP/CWE
bun run gitleaks        # Secret scanning
bun run complexity      # Complejidad ciclomática > 15
bun run deadcode        # Código muerto (ts-prune)
bun run typecov         # Type-coverage %
bun run sbom            # SBOM CycloneDX 1.5
```

### CI automático

Cada push a `main` y cada PR ejecutan automáticamente:

- **CodeQL** con query pack `security-and-quality` → `.github/workflows/codeql.yml`
- **Semgrep** con reglas OWASP/CWE personalizadas → `.github/workflows/semgrep.yml`
- **Supply Chain**: Snyk, bun audit, Trivy (fs + Docker + IaC), license-checker → `.github/workflows/supply-chain.yml`
- **Gitleaks** sobre historial git completo → `.github/workflows/secrets.yml`

Los resultados SARIF se suben a la pestaña **Security → Code scanning alerts** del repositorio.

### Documentación para auditores

- `AUDITING.md` — guía paso a paso para auditar el código (humano o IA)
- `SECURITY_CHECKLIST.md` — 120 puntos verificables con scoring
- `docs/AI_AUDIT_PROMPT.md` — prompt listo para alimentar a cualquier LLM y obtener 30+ hallazgos estructurados
- `ARCHITECTURE.md` — modelo de amenazas y stack criptográfico
- `docs/SECURITY_AUDIT_REPORT.md` — reporte formal de seguridad

### Flujo recomendado para un auditor externo

```bash
git clone https://github.com/di3go04/zero-knowledge-vault.git
cd zero-knowledge-vault
bun install
bun run audit:full
# 1. Leer audit-reports/latest.md
# 2. Leer AUDITING.md y SECURITY_CHECKLIST.md
# 3. Revisar manualmente src/lib/crypto-client.ts y src/lib/crypto-server.ts
# 4. Usar docs/AI_AUDIT_PROMPT.md con cualquier LLM para obtener 30+ hallazgos
# 5. Abrir PR con la rama audit/<nombre>-<fecha>
```

---

## Licencia

MIT
