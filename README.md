# Zero-Knowledge Vault

Gestor de contraseñas Zero-Knowledge con cifrado end-to-end en el navegador usando Web Crypto API.

> **El servidor es un *crypto-blind store***: solo almacena blobs cifrados, sales públicas, IVs y llaves públicas. Nunca recibe ni puede descifrar contraseñas maestras, llaves privadas, llaves AES simétricas, ni el contenido de ningún secreto.

---

## Tabla de Contenidos

- [Visión General](#visión-general)
- [Garantías Zero-Knowledge](#garantías-zero-knowledge)
- [Stack Criptográfico](#stack-criptográfico)
- [Arquitectura](#arquitectura)
- [Instalación y Ejecución](#instalación-y-ejecución)
- [Variables de Entorno](#variables-de-entorno)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Auditoría del Código](#auditoría-del-código)
- [Roadmap](#roadmap)
- [Licencia](#licencia)

---

## Visión General

Zero-Knowledge Vault es un gestor de contraseñas donde **todo el cifrado ocurre en el navegador** del cliente usando Web Crypto API. El servidor actúa como un almacén ciego (*crypto-blind store*) que persiste blobs cifrados sin poder interpretarlos.

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
- La contraseña maestra (para PBKDF2/Argon2id → masterKey → descifrar privateKey), o
- La frase BIP-39 de recuperación (256 bits de entropía).

Sin ninguno de los dos, los datos son criptográficamente inaccesibles.

---

## Garantías Zero-Knowledge

1. **Cifrado AES-256-GCM en el cliente** — título, contenido y llave privada RSA se cifran antes de salir del navegador.
2. **KDF Argon2id** (memory-hard, 64 MiB) con fallback honesto a PBKDF2 (600k iteraciones) si el Web Worker falla.
3. **RSA-OAEP 2048** para envolver llaves AES con la llave pública del destinatario.
4. **ECDH P-256** para sync multi-device — cada dispositivo autorizado recibe la llave privada RSA envuelta con una llave derivada vía ECDH.
5. **ECDSA P-256** para challenge-response en enrollment de dispositivos.
6. **ML-KEM-768** (post-cuantico) en flujo activo de share/decrypt — hybrid KEM con ECDH clásico.
7. **HKDF-SHA256** para derivar sub-llaves independientes (audit, device, share, metadata).
8. **BIP-39 recovery** — 24 palabras (256 bits de entropía) como backup de la llave privada RSA.
9. **Zeroization de memoria** — `clearCryptoKeyRef`, `zeroBuffer`, `FinalizationRegistry` para material transitorio.
10. **Audit log tamper-evident** — cadena de hashes SHA-256, verificable vía `/api/audit-logs/verify`.
11. **AAD en AES-GCM** — contexto criptográfico asociado a cada cifrado (defensa contra ciphertext swapping).
12. **Rate limiting** con Redis o Map fallback en endpoints sensibles.
13. **Session tokens HS256** con `jti` + blacklist server-side para logout real.

---

## Stack Criptográfico

| Capa | Algoritmo | Uso |
|------|-----------|-----|
| KDF | Argon2id (m=64MiB, t=3, p=4) | Derivar masterKey de la contraseña |
| KDF fallback | PBKDF2-SHA256 (600k iter) | Si Argon2id no está disponible |
| Subkey derivation | HKDF-SHA256 | audit, device, share, metadata subkeys |
| Symmetric | AES-256-GCM (96-bit IV, AAD) | Cifrar blobs y llaves privadas |
| Asymmetric wrap | RSA-OAEP 2048 (SHA-256) | Envolver llaves AES para shares |
| Signatures | RSA-PSS 2048 (SHA-256, salt=32) | Proof-of-Possession en registro |
| Multi-device | ECDH P-256 | Derivar shared key entre dispositivos |
| Device enrollment | ECDSA P-256 (SHA-256) | Challenge-response |
| Post-quantum | ML-KEM-768 | Hybrid KEM con ECDH para shares futuros |
| Recovery | BIP-39 (24 palabras, 256 bits) | Backup de la llave privada RSA |
| Audit chain | SHA-256 hash chain | Tamper-evident audit logs |

Todas las operaciones usan **Web Crypto API** (`crypto.subtle`) — sin dependencias criptográficas externas excepto `hash-wasm` (Argon2id en Web Worker) y `@noble/post-quantum` (ML-KEM-768).

---

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLIENTE (navegador)                      │
│                                                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │ AuthView    │   │ VaultView   │   │ AuditLogViewer      │   │
│  └──────┬──────┘   └──────┬──────┘   └──────────┬──────────┘   │
│         │                 │                     │               │
│         └────────┬────────┴─────────────────────┘               │
│                  ▼                                                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              src/lib/crypto/                            │    │
│  │  client.ts   server.ts   rotation.ts   memory.ts        │    │
│  │  hkdf.ts     pq-kem.ts   hash-chain.ts  argon2-worker   │    │
│  └────────────────────┬────────────────────────────────────┘    │
│                       │                                          │
│         Web Crypto API (crypto.subtle)                          │
└───────────────────────┬──────────────────────────────────────────┘
                        │ HTTPS (solo blobs cifrados)
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│                          SERVIDOR (Next.js)                      │
│                                                                  │
│  /api/auth/{register,login,logout,rotate}                       │
│  /api/secrets          /api/secrets/[id]                        │
│  /api/shares           /api/audit-logs                          │
│  /api/audit-logs/verify                                          │
│  /api/devices/{enroll/*,list,[id]}                              │
│  /api/health                                                     │
│                                                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │ Prisma      │   │ Pino logger │   │ Rate limiter        │   │
│  │ (SQLite/PG) │   │ (redacted)  │   │ (Redis/Map)         │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Instalación y Ejecución

### Prerrequisitos

- **Node.js 18+** o **Bun 1.3+** (recomendado)
- **OpenSSL** (para generar secretos)

### Pasos

```bash
# 1. Clonar el repo
git clone https://github.com/di3go04/zero-knowledge-vault.git
cd zero-knowledge-vault

# 2. Instalar dependencias
bun install

# 3. Configurar entorno
cp .env.example .env
# Editar .env y cambiar SESSION_SECRET por algo aleatorio:
#   openssl rand -base64 48

# 4. Inicializar base de datos
bun run db:push

# 5. Generar Prisma client
bun run db:generate

# 6. Iniciar en desarrollo
bun run dev
# → http://localhost:3000
```

### Scripts disponibles

```bash
bun run dev          # Servidor de desarrollo (http://localhost:3000)
bun run build        # Build de producción
bun run start        # Servidor de producción
bun run lint         # ESLint
bun run typecheck    # TypeScript sin emit
bun run test         # Vitest (119 tests)
bun run test:watch   # Vitest en modo watch
bun run test:coverage # Coverage report
bun run db:push      # Aplicar schema a la BD
bun run db:generate  # Generar Prisma client
bun run db:migrate   # Crear migración
bun run db:reset     # Resetear BD
```

---

## Variables de Entorno

Ver [`.env.example`](./.env.example) para la lista completa. Las obligatorias son:

- `DATABASE_URL` — SQLite (dev) o PostgreSQL (prod)
- `SESSION_SECRET` — Mínimo 32 caracteres, aleatorio

Opcionales: `REDIS_URL`, `DECOY_HMAC_KEY`, `LOG_LEVEL`.

---

## API Endpoints

### Autenticación
- `POST /api/auth/register` — Registro (recibe solo blobs cifrados + publicKey)
- `POST /api/auth/login` — Login (decoy si el usuario no existe, anti-enumeración)
- `POST /api/auth/logout` — Logout (blacklist del session token)
- `POST /api/auth/rotate` — Rotación de contraseña maestra

### Secretos
- `GET  /api/secrets` — Listar secretos propios + compartidos
- `POST /api/secrets` — Crear secreto (cifrado cliente)
- `GET  /api/secrets/[id]` — Obtener secreto específico
- `DELETE /api/secrets/[id]` — Borrar secreto (solo owner)

### Shares
- `POST   /api/shares` — Compartir secreto con otro usuario
- `DELETE /api/shares` — Revocar share (owner) o auto-salir (destinatario)

### Audit logs (tamper-evident)
- `GET  /api/audit-logs` — Listar logs cifrados
- `POST /api/audit-logs` — Crear log cifrado (extiende hash chain)
- `GET  /api/audit-logs/verify` — Verificar integridad de la cadena

### Multi-device
- `POST /api/devices/enroll/init` — Iniciar enrollment de nuevo dispositivo
- `POST /api/devices/enroll/lookup` — Buscar código de enrollment
- `POST /api/devices/enroll/poll` — Polling del dispositivo nuevo
- `POST /api/devices/enroll/complete` — Completar enrollment (ECDH)
- `POST /api/devices/enroll/poll/verify` — Verificar challenge ECDSA
- `GET  /api/devices/list` — Listar dispositivos autorizados
- `DELETE /api/devices/[id]` — Revocar dispositivo

### Salud
- `GET /api/health` — Status de BD + Redis + versión

---

## Testing

```bash
# Ejecutar los 119 tests
bun run test

# Con coverage
bun run test:coverage
```

### Cobertura actual (módulo crypto)

| Archivo | Statements | Branches | Functions |
|---------|-----------|----------|-----------|
| hkdf.ts | 100% | 100% | 100% |
| rotation.ts | 100% | 100% | 100% |
| hash-chain.ts | 100% | 100% | 100% |
| server.ts | 96.79% | 82.35% | 100% |
| memory.ts | 71.66% | 81.25% | 100% |
| client.ts | 57.1% | 94.11% | 81.03% |
| **Total** | **67.52%** | **90%** | **86.74%** |

Las líneas no cubiertas en `client.ts` son paths de Argon2id worker que solo se ejercen en navegador real con Web Worker.

### Suites de tests (8 archivos, 119 tests)

- `hkdf.test.ts` (7) — HKDF-SHA256 derivation
- `memory.test.ts` (14) — zeroization de buffers y CryptoKeys
- `client.test.ts` (42) — KDF, AES-GCM, RSA-OAEP, ECDH, ECDSA, PoP, BIP-39
- `server.test.ts` (21) — verification server-side, decoy login
- `rotation.test.ts` (4) — rotación de pares RSA
- `extras.test.ts` (10) — recovery, audit, fingerprint cache
- `integration.test.ts` (7) — flujos end-to-end
- `hash-chain.test.ts` (14) — tamper-evident audit chain

---

## Auditoría del Código

El núcleo criptográfico está en `src/lib/crypto/`:

```
src/lib/crypto/
├── client.ts           # Crypto del lado cliente (KDF, AES-GCM, RSA-OAEP, ECDH, ECDSA)
├── server.ts           # Verificación server-side (PoP, decoy, ECDSA challenge)
├── rotation.ts         # Rotación de pares RSA
├── memory.ts           # Zeroization de memoria
├── hkdf.ts             # HKDF-SHA256 subkey derivation
├── pq-kem.ts           # ML-KEM-768 post-cuantico (hybrid con ECDH)
├── hash-chain.ts       # Tamper-evident audit log chain
├── argon2-worker.ts    # Web Worker para Argon2id (hash-wasm)
└── index.ts            # Re-exports de la API pública
```

Archivos clave para auditar manualmente:

1. `src/lib/crypto/client.ts` — corazón criptográfico
2. `src/lib/crypto/server.ts` — verificaciones del servidor
3. `prisma/schema.prisma` — modelo de datos (6 modelos)
4. `src/app/api/auth/register/route.ts` — flujo de registro
5. `src/app/api/auth/login/route.ts` — flujo de login con decoy

---

## Roadmap

Funcionalidades planeadas, en orden de prioridad:

### v1.1 (Q1 2026)
- [ ] WebAuthn / Passkeys como segundo factor
- [ ] Importador desde 1Password / Bitwarden / LastPass
- [ ] Extension de navegador (Chrome / Firefox)
- [ ] App móvil (React Native / Expo)

### v1.2 (Q2 2026)
- [ ] Team vaults (carpetas compartidas con llave AES rotativa)
- [ ] Roles granulares por secreto (read-only, admin)
- [ ] Aprobaciones de doble control para secretos sensibles
- [ ] Auditoría SIEM (webhook a Splunk / Elastic)

### v1.3 (Q3 2026)
- [ ] SSO OIDC (Google, Microsoft, Okta)
- [ ] SCIM 2.0 para provisionamiento automático
- [ ] Travel mode (oculta vaults sensibles al cruzar fronteras)
- [ ] Dark web monitoring (HIBP integration)

### v2.0 (Q4 2026)
- [ ] Migración completa a ML-KEM-1024 + Kyber + Dilithium
- [ ] ZK-proofs para auditoría sin revelar contenido
- [ ] Shamir Secret Sharing (5/3 threshold) para recovery avanzado
- [ ] App de escritorio (Tauri / Electron)

**No planeado** (fuera de scope):
- SAML, LDAP, DLP, eDiscovery, retention policies, break-glass, multitenancy estricta. Si necesitas estas features enterprise, este no es el proyecto correcto.

---

## Licencia

MIT
