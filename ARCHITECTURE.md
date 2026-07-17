# Architecture — Zero-Knowledge Vault

## Visión general

El sistema es un gestor de contraseñas zero-knowledge: todo el cifrado ocurre en el navegador del cliente usando Web Crypto API. El servidor es un *crypto-blind store* que persiste blobs cifrados sin poder interpretarlos.

## Componentes

### Cliente (navegador)

- **React 19 + Next.js 16** — UI y routing
- **`src/lib/crypto/`** — módulo criptográfico completo
  - `client.ts` — KDF (Argon2id/PBKDF2), AES-GCM, RSA-OAEP, ECDH, ECDSA, BIP-39, PoP
  - `server.ts` — verificaciones server-side (no exporta a client bundle)
  - `hkdf.ts` — HKDF-SHA256 para subkeys (audit, device, share, metadata)
  - `rotation.ts` — rotación de wrapped keys
  - `memory.ts` — zeroization de CryptoKey y buffers
  - `pq-kem.ts` — ML-KEM-768 (post-cuantum) hybrid con ECDH
  - `hash-chain.ts` — tamper-evident audit log chain
  - `argon2-worker.ts` — Web Worker para Argon2id (hash-wasm)
- **Componentes UI**: AuthView, VaultView, ViewSecretDialog, CreateSecretDialog, ShareSecretDialog, RotatePasswordDialog, EnrollDeviceDialog, AuditLogViewer, RecoverySetupDialog

### Servidor (Next.js API routes)

- **`/api/auth/*`** — registro, login (con decoy anti-enumeración), logout, rotación
- **`/api/secrets/*`** — CRUD de blobs cifrados
- **`/api/shares`** — compartir/revocar shares (RSA-OAEP wrapped AES keys)
- **`/api/audit-logs`** + `/verify` — logs cifrados + verificación de cadena
- **`/api/devices/*`** — enrollment multi-device via ECDH P-256
- **`/api/health`** — healthcheck (BD + Redis + versión)

### Persistencia

- **Prisma ORM** — abstracción de base de datos
- **SQLite** en desarrollo, **PostgreSQL** recomendado en producción
- **Redis** (opcional) — rate limiting distribuido, blacklist de tokens, challenge store

## Modelo de datos (6 modelos)

```
User
  ├─ UserKeyMaterial (1:1)  — kdfSalt, publicKeyJwk, encryptedPrivateKeyJwk, mlKemPublicKey, recoveryKey
  ├─ Secret[] (1:N)          — encryptedTitle, encryptedData, IVs (cifrado con masterKey)
  │    └─ SecretKeyShare[]   — wrappedSymmetricKey (RSA-OAEP con publicKey del destinatario)
  ├─ Device[] (1:N)          — publicKeyECDH, wrappedPrivateKeyForDevice (ECDH-derived key)
  └─ AuditLog[] (1:N)        — encryptedEvent, prevHash, logHash (hash chain)
```

**El servidor nunca almacena**:
- Contraseña maestra (solo se usa en cliente para derivar masterKey)
- Llave maestra (solo existe como CryptoKey no-extractable en memoria del cliente)
- Llave privada RSA en claro (se cifra con masterKey antes de enviarla)
- Llaves AES simétricas (se envuelven con RSA-OAEP antes de enviarlas)
- Contenido de secretos (solo blobs AES-GCM ciphertext)
- Frase BIP-39 de recovery (solo se muestra una vez al usuario)

## Flujo de registro

```
Cliente                                      Servidor
  │                                            │
  ├─ generar par RSA-2048                      │
  ├─ generar par ECDH P-256                    │
  ├─ generar par ML-KEM-768                    │
  ├─ derivar kdfSalt (16 bytes aleatorios)     │
  ├─ Argon2id(password, kdfSalt) → masterKey   │
  ├─ AES-GCM(masterKey, privateKeyJwk) → blob  │
  ├─ RSA-PSS(privateKey, {email, fp, salt})    │
  │                                            │
  ├─ POST /api/auth/register ─────────────────►│
  │   body: { email, kdfSalt, kdfParams,       │
  │           publicKeyJwk, encryptedPrivJwk,   │
  │           privateKeyIv, popSignature,       │
  │           mlKemPublicKey,                   │
  │           encryptedMlKemPrivateKey }        │
  │                                            │
  │                                            ├─ validar Zod schema
  │                                            ├─ verificar PoP signature
  │                                            ├─ calcular fingerprint
  │                                            ├─ crear User + UserKeyMaterial
  │                                            │
  │◄────────────────── { userId, email, fp } ──┤
  │                                            │
  ├─ generar mnemonic BIP-39 (24 palabras)     │
  ├─ derivar recoveryKey de mnemonic            │
  ├─ AES-GCM(recoveryKey, privateKeyJwk)        │
  │                                            │
  ├─ POST /api/auth/recovery/setup ────────────►│
  │   body: { encryptedPrivateKeyForRecovery,   │
  │           recoverySalt, recoveryIterations, │
  │           recoveryIv }                      │
  │                                            │
  │                                            ├─ actualizar UserKeyMaterial
  │                                            │
  │◄────────────────── { ok: true } ───────────┤
```

## Flujo de login

```
Cliente                                      Servidor
  │                                            │
  ├─ POST /api/auth/login ────────────────────►│
  │   body: { email }                           │
  │                                            │
  │                                            ├─ rate limit check (5/15min/IP+email)
  │                                            ├─ buscar user por email
  │                                            │
  │            ┌────── si user existe ──────┐   │
  │            │                              │   │
  │            ├─ reset rate limit            │   │
  │            ├─ issue session token (HS256)  │   │
  │            ├─ devolver kdfParams +        │   │
  │            │  encryptedPrivateKeyJwk +    │   │
  │            │  publicKeyJwk + sessionToken │   │
  │            │                              │   │
  │            └── si user NO existe ────────┐ │   │
  │                                          │ │   │
  │            ├─ NO reset rate limit         │ │   │
  │            ├─ generar decoy response      │ │   │
  │            │  (HMAC-deterministic)        │ │   │
  │            ├─ devolver decoy kdfParams +  │ │   │
  │            │  decoy encryptedPrivateKey + │ │   │
  │            │  decoy publicKey             │ │   │
  │            │  (no sessionToken)           │ │   │
  │            │                              │ │   │
  │◄──────────── { kdfParams, encryptedKey, ─┤ │   │
  │              publicKey, sessionToken? }   │   │
  │                                            │
  ├─ Argon2id(password, kdfSalt) → masterKey   │
  ├─ AES-GCM.decrypt(masterKey, encryptedKey)  │
  │  → privateKey (CryptoKey)                  │
  │                                            │
  │  Si falla → password incorrecto            │
  │  Si OK → privateKey lista para usar         │
```

## Flujo multi-device (ECDH P-256)

```
Dispositivo A (logueado)              Servidor              Dispositivo B (nuevo)
       │                                 │                          │
       │                                 │  ┌─ generar ECDH P-256  │
       │                                 │  │  pair (privB, pubB)  │
       │                                 │  │                       │
       │                                 │◄─┤ POST enroll/init     │
       │                                 │  │ { pubB, deviceName }  │
       │                                 │  │                       │
       │                                 │  ├─ generar enrollCode   │
       │                                 │  │  (6 dígitos)          │
       │                                 │  ├─ guardar Device       │
       │                                 │  │  (pubB, enrollCode)   │
       │                                 │  │                       │
       │                                 ├──►│ { enrollCode }        │
       │                                 │  │                       │
       │ GET devices/enroll/lookup       │  │                       │
       │   ?code=XXXXXX                  │  │                       │
       │                                 │  │                       │
       │◄────────── { deviceB: pubB } ───┤  │                       │
       │                                 │  │                       │
       ├─ generar par ECDH P-256         │  │                       │
       │  efímero (privA, pubA)          │  │                       │
       ├─ sharedKey = ECDH(privA, pubB)  │  │                       │
       ├─ wrappedBlob = AES-GCM(         │  │                       │
       │     sharedKey, userPrivateKey)  │  │                       │
       │                                 │  │                       │
       │ POST enroll/complete            │  │                       │
       │   { enrollCode, pubA,           │  │                       │
       │     wrappedBlob, iv }           │  │                       │
       │                                 │  │                       │
       │                                 ├─ guardar pubA + wrappedBlob
       │                                 │  │  en Device            │
       │                                 │  │                       │
       │                                 │  │◄─ poll enroll/poll    │
       │                                 │  │   { enrollCode }      │
       │                                 │  │                       │
       │                                 │  ├──► { pubA,            │
       │                                 │  │     wrappedBlob, iv } │
       │                                 │  │                       │
       │                                 │  ├─ sharedKey =          │
       │                                 │  │  ECDH(privB, pubA)    │
       │                                 │  ├─ userPrivateKey =     │
       │                                 │  │  AES-GCM.decrypt(     │
       │                                 │  │     sharedKey,        │
       │                                 │  │     wrappedBlob)      │
       │                                 │  │                       │
       │                                 │  └─ userPrivateKey lista  │
```

El servidor nunca ve la sharedKey ni la userPrivateKey — ambas existen solo en los dos dispositivos.

## Threat model

### Activos protegidos
- Llave maestra derivada del password
- Llave privada RSA del usuario
- Llaves AES simétricas de secretos
- Contenido de secretos (título + data)
- Contenido de audit logs
- Frase BIP-39 de recovery

### Adversarios considerados
- **Red pasiva**: MITM que intercepta HTTPS — mitigado por TLS + HSTS
- **Red activa**: MITM que modifica tráfico — mitigado por PoP signature en registro
- **Servidor comprometido**: operador malicioso con acceso a BD — mitigado por zero-knowledge (BD solo tiene blobs cifrados)
- **Cliente comprometido**: malware en el navegador — mitigado por memory zeroing + auto-lock + tab lock
- **Admin comprometido**: administrador con acceso a endpoints — mitigado por rate limiting + audit logs tamper-evident
- **Atacante post-cuantico**: harvest-now-decrypt-later — mitigado por ML-KEM-768 en shares

### Ataques mitigados
- Enumeración de usuarios: decoy login responses indistinguibles
- Brute force offline: Argon2id (memory-hard, 64 MiB)
- Brute force online: rate limiting 5/15min/IP+email
- Ciphertext swapping: AAD en AES-GCM (context binding)
- Token replay: jti + Redis blacklist
- Audit log tampering: SHA-256 hash chain + /verify endpoint
- IV reuse: IV aleatorio de 96 bits por operación
- Weak passwords: zxcvbn score + recomendaciones

### Limitaciones conocidas
- No hay protección contra malware con acceso al DOM (XSS)
- No hay protección contra GPU-based Argon2id cracking (asumido: Argon2id con 64 MiB es costoso)
- Memory zeroing de strings es best-effort (JS strings son inmutables)
- El recovery phrase BIP-39 es single point of failure si se almacena digitalmente

## Stack tecnológico

| Capa | Tecnología |
|------|------------|
| Frontend | Next.js 16, React 19, Tailwind CSS 4, shadcn/ui |
| Backend | Next.js API routes (Node.js runtime) |
| ORM | Prisma 6 |
| DB | SQLite (dev) / PostgreSQL (prod) |
| Cache | Redis (opcional, para rate limit distribuido) |
| Logger | pino (JSON, con redacción) |
| Tests | Vitest 2 |
| Crypto | Web Crypto API + hash-wasm + @noble/post-quantum |
| KDF | Argon2id (preferido) / PBKDF2 (legacy) |
