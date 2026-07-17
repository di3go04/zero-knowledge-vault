# API Reference

## Authentication

All API endpoints (except `auth/register`, `auth/login`, `auth/recovery/recover`, `devices/enroll/init`, `devices/enroll/poll`, `devices/enroll/poll/verify`, `users/lookup`, `health`, and `webauthn/login/begin`) require a Bearer token in the `Authorization` header.

```
Authorization: Bearer <session_token>
```

The session token is a **HS256-signed JWT** with 1-hour TTL, obtained from `POST /api/auth/login` or `POST /api/auth/webauthn/login/complete`. Tokens can be revoked server-side via logout.

## Common Responses

| Status                  | Description                             |
| ----------------------- | --------------------------------------- |
| `400 Bad Request`       | Invalid request body or parameters      |
| `401 Unauthorized`      | Missing or invalid authentication token |
| `404 Not Found`         | Resource not found (non-revealing)      |
| `429 Too Many Requests` | Rate limit exceeded                     |

Error bodies follow this shape:

```json
{
  "error": "Human-readable error message",
  "retryAfter": 900
}
```

---

## Auth

### POST /api/auth/register

Register a new user with Proof-of-Possession (RSA-PSS). The client generates an RSA key pair, encrypts the private key with the master password, and signs a PoP message to prove possession of the private key.

**Request:**

```json
{
  "email": "alice@example.com",
  "name": "Alice",
  "kdfAlgorithm": "argon2id",
  "kdfSalt": "a3NuU2FsdFZhbHVlMTIzNA==",
  "kdfIterations": 600000,
  "kdfMemoryKiB": 65536,
  "kdfParallelism": 4,
  "publicKeyJwk": {
    "kty": "RSA",
    "n": "base64url-modulus",
    "e": "AQAB",
    "ext": true,
    "key_ops": ["wrapKey", "unwrapKey"],
    "alg": "RSA-OAEP-2048"
  },
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "popSignature": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA...",
  "encryptedPrivateKeyJwk": "QUVTMjU2LUdDTS1jaXBoZXJ0ZXh0...",
  "privateKeyIv": "MTIzNDU2Nzg5MDEy"
}
```

**Response:** `201 Created`

```json
{
  "userId": "cm9vdF9hYmMxMjM0",
  "email": "alice@example.com",
  "name": "Alice",
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "createdAt": "2025-06-15T10:30:00.000Z"
}
```

**Errors:** `400`, `403` (PoP verification failed), `409` (email already registered), `429`

---

### POST /api/auth/login

Authenticate with email. Returns the user's encrypted key material and a session token. If the email does not exist, returns a decoy response (same structure, undecryptable) to prevent email enumeration.

Rate-limited: **5 attempts per 15 min per IP+email**.

**Request:**

```json
{
  "email": "alice@example.com"
}
```

**Response:** `200 OK`

```json
{
  "userId": "user_abc123",
  "email": "alice@example.com",
  "name": "Alice",
  "kdfAlgorithm": "argon2id",
  "kdfSalt": "a3NuU2FsdFZhbHVlMTIzNA==",
  "kdfIterations": 600000,
  "kdfMemoryKiB": 65536,
  "kdfParallelism": 4,
  "encryptedPrivateKeyJwk": "QUVTMjU2LUdDTS1jaXBoZXJ0ZXh0...",
  "privateKeyIv": "MTIzNDU2Nzg5MDEy",
  "publicKeyJwk": { "kty": "RSA", ... },
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "sessionToken": "eyJhbGciOiJIUzI1NiJ9...",
  "expiresAt": 1718461800,
  "isDecoy": false
}
```

**Errors:** `400`, `429`

---

### POST /api/auth/logout

Revokes the current session token by adding its JTI to the server-side blacklist with TTL equal to remaining expiration time. Idempotent — returns 200 even if the token is already expired or revoked.

**Auth:** Required

**Response:** `200 OK`

```json
{
  "loggedOut": true,
  "jti": "token-jti-uuid",
  "ttlSeconds": 3600,
  "note": "Token revocado hasta expiración natural."
}
```

---

### POST /api/auth/rotate

Rotates the master password by re-encrypting the same RSA private key with a new key derived from the new password. Requires a new PoP signature using the existing public key. The public key does NOT change — existing wrapped keys and shares remain valid.

**Auth:** Required

**Request:**

```json
{
  "newKdfAlgorithm": "pbkdf2",
  "newKdfSalt": "base64-salt",
  "newKdfIterations": 600000,
  "newKdfMemoryKiB": null,
  "newKdfParallelism": null,
  "newEncryptedPrivateKeyJwk": "QUVTMjU2LUdDTS1jaXBoZXJ0ZXh0...",
  "newPrivateKeyIv": "MTIzNDU2Nzg5MDEy",
  "newPopSignature": "base64-signature"
}
```

**Response:** `200 OK`

```json
{
  "rotated": true,
  "userId": "user_abc123",
  "newKdfAlgorithm": "pbkdf2",
  "newKdfSalt": "base64-salt",
  "newKdfIterations": 600000,
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "note": "Contraseña maestra rotada. La llave pública RSA no cambió."
}
```

**Errors:** `400`, `401`, `403` (PoP verification failed), `404`, `429`

---

### GET /api/auth/rotation-status

Returns the timestamp of the last key rotation for the authenticated user. Clients can use this to enforce periodic rotation policies.

**Auth:** Required

**Response:** `200 OK`

```json
{
  "lastKeyRotationAt": "2025-06-15T10:30:00.000Z"
}
```

`lastKeyRotationAt` is `null` if the user has never rotated their master password.

**Errors:** `401`, `429`

---

### POST /api/auth/recovery/setup

Stores an encrypted backup of the RSA private key that can be recovered using a BIP-39 mnemonic phrase. The backup is encrypted with a key derived from the mnemonic.

**Auth:** Required

**Request:**

```json
{
  "recoverySalt": "base64-salt",
  "recoveryIterations": 600000,
  "encryptedPrivateKeyForRecovery": "AES-256-GCM-encrypted-private-key...",
  "recoveryIv": "base64-iv"
}
```

**Response:** `200 OK`

```json
{
  "recoveryEnabled": true,
  "note": "Backup de recuperación configurado. Guarda tus 24 palabras en un lugar seguro."
}
```

**Errors:** `400`, `401`, `404`, `429`

---

### POST /api/auth/recovery/recover

Two-step recovery flow. First call with `action: "get-blob"` to retrieve the encrypted recovery blob. Decrypt client-side with the BIP-39 mnemonic, re-encrypt with a new master password, and call with `action: "complete"` to finalize.

**Step 1 — Request:**

```json
{
  "action": "get-blob",
  "email": "alice@example.com"
}
```

**Step 1 — Response:** `200 OK`

```json
{
  "recoveryEnabled": true,
  "recoverySalt": "base64-salt",
  "recoveryIterations": 600000,
  "encryptedPrivateKeyForRecovery": "AES-256-GCM-encrypted-blob...",
  "recoveryIv": "base64-iv",
  "isDecoy": false
}
```

**Step 2 — Request:**

```json
{
  "action": "complete",
  "email": "alice@example.com",
  "newKdfAlgorithm": "argon2id",
  "newKdfSalt": "base64-salt",
  "newKdfIterations": 600000,
  "newKdfMemoryKiB": 65536,
  "newKdfParallelism": 4,
  "newEncryptedPrivateKeyJwk": "re-encrypted-private-key...",
  "newPrivateKeyIv": "base64-iv",
  "newPopSignature": "base64-signature"
}
```

**Step 2 — Response:** `200 OK`

```json
{
  "recovered": true,
  "userId": "user_abc123",
  "email": "alice@example.com",
  "note": "Cuenta recuperada exitosamente."
}
```

**Errors:** `400`, `403` (PoP verification failed), `404`, `429`

---

## WebAuthn

### POST /api/auth/webauthn/register/begin

Generates WebAuthn registration options (challenge, RP info, etc.) for the authenticated user. Returns `PublicKeyCredentialCreationOptions` compatible with `@simplewebauthn/server`.

**Auth:** Required

**Response:** `200 OK`

```json
{
  "challenge": "AACJzZQAAAA",
  "rp": {
    "name": "ZK Vault",
    "id": "localhost"
  },
  "user": {
    "id": "dXNlcl9pZA",
    "name": "alice@example.com",
    "displayName": "Alice"
  },
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {},
  "attestation": "none"
}
```

**Errors:** `401`, `404`

---

### POST /api/auth/webauthn/register/complete

Verifies the WebAuthn registration response and stores the new credential for the authenticated user.

**Auth:** Required

**Request:**

```json
{
  "credential": {/* PublicKeyCredential from browser */},
  "deviceName": "Mi YubiKey"
}
```

**Response:** `200 OK`

```json
{
  "verified": true,
  "credentialId": "webauthn-cred-id-1"
}
```

**Errors:** `400`, `401`

---

### POST /api/auth/webauthn/login/begin

Generates WebAuthn authentication options (challenge, allowCredentials) for a user identified by email. Does NOT require prior authentication.

**Request:**

```json
{
  "email": "alice@example.com"
}
```

**Response:** `200 OK`

```json
{
  "challenge": "AACJzZQAAAA",
  "allowCredentials": [
    {
      "id": "webauthn-cred-id-1",
      "type": "public-key",
      "transports": ["internal", "usb"]
    }
  ],
  "userId": "user_abc123",
  "userVerification": "preferred"
}
```

**Errors:** `400`, `404` (no WebAuthn credentials for this user)

---

### POST /api/auth/webauthn/login/complete

Verifies the WebAuthn authentication response and issues a session token if successful. Returns the user's encrypted key material alongside the session token.

**Request:**

```json
{
  "credential": {/* PublicKeyCredential from browser */},
  "userId": "user_abc123"
}
```

**Response:** `200 OK`

```json
{
  "verified": true,
  "userId": "user_abc123",
  "email": "alice@example.com",
  "name": "Alice",
  "sessionToken": "eyJhbGciOiJIUzI1NiJ9...",
  "expiresAt": 1718461800,
  "kdfAlgorithm": "argon2id",
  "kdfSalt": "base64-salt",
  "kdfIterations": 600000,
  "kdfMemoryKiB": 65536,
  "kdfParallelism": 4,
  "encryptedPrivateKeyJwk": "QUVTMjU2LUdDTS1jaXBoZXJ0ZXh0...",
  "privateKeyIv": "base64-iv",
  "publicKeyJwk": null
}
```

**Errors:** `400`, `401`, `404`

---

### GET /api/auth/webauthn/credentials

Returns all WebAuthn credentials registered to the authenticated user.

**Auth:** Required

**Response:** `200 OK`

```json
[
  {
    "id": "wa-cred-uuid",
    "credentialId": "webauthn-cred-id-1",
    "deviceName": "Mi YubiKey",
    "credentialType": "cross-platform",
    "createdAt": "2025-06-15T10:30:00.000Z",
    "lastUsedAt": "2025-06-16T08:00:00.000Z"
  }
]
```

**Errors:** `401`

---

### DELETE /api/auth/webauthn/credentials?id=<credentialId>

Deletes a WebAuthn credential by ID. Only the owning user can delete their own credentials.

**Auth:** Required

**Query Parameters:**

| Param | Type   | Required | Description             |
| ----- | ------ | -------- | ----------------------- |
| `id`  | string | yes      | Credential ID to delete |

**Response:** `200 OK`

```json
{
  "deleted": true
}
```

**Errors:** `400`, `401`

---

## Secrets

### GET /api/secrets

Lists all secrets owned by or shared with the authenticated user. Returns only encrypted blobs — the server never sees plaintext. Supports pagination.

**Auth:** Required

**Query Parameters:**

| Param    | Type    | Default | Description                       |
| -------- | ------- | ------- | --------------------------------- |
| `offset` | integer | 0       | Number of items to skip           |
| `limit`  | integer | 50      | Maximum items to return (max 100) |

**Response:** `200 OK`

```json
{
  "secrets": [
    {
      "id": "secret_uuid",
      "ownerId": "user_abc123",
      "ownerEmail": "alice@example.com",
      "ownerName": "Alice",
      "ownedByMe": true,
      "encryptedTitle": "QUVTMjU2LUdDTS1jaXBoZXJ0ZXh0...",
      "titleIv": "base64-iv",
      "encryptedData": "AES-256-GCM-ciphertext...",
      "dataIv": "base64-iv",
      "encryptedMetadata": null,
      "metadataIv": null,
      "secretType": "password",
      "wrappedKey": "RSA-OAEP-wrapped-AES-key...",
      "createdAt": "2025-06-15T10:30:00.000Z",
      "sharedAt": "2025-06-15T10:30:00.000Z"
    }
  ],
  "pagination": {
    "offset": 0,
    "limit": 50,
    "total": 1,
    "hasMore": false
  }
}
```

**Errors:** `401`, `429`

---

### POST /api/secrets

Creates a new encrypted secret. All fields are client-encrypted blobs. The server cannot read the title, data, or metadata. A wrapped key share is created for the owner automatically.

**Auth:** Required

**Request:**

```json
{
  "encryptedTitle": "AES-256-GCM-encrypted-title...",
  "titleIv": "base64-iv-12-bytes",
  "encryptedData": "AES-256-GCM-encrypted-data...",
  "dataIv": "base64-iv-12-bytes",
  "wrappedKeyForOwner": "RSA-OAEP-2048-wrapped-AES-key...",
  "secretType": "password",
  "encryptedMetadata": "optional-encrypted-metadata...",
  "metadataIv": "optional-base64-iv"
}
```

`secretType` enum: `password`, `note`, `ssh-key`, `api-key`, `certificate`, `database`

**Response:** `201 Created`

```json
{
  "secretId": "secret_uuid",
  "createdAt": "2025-06-15T10:30:00.000Z"
}
```

**Errors:** `400`, `401`, `404`, `429`

---

### DELETE /api/secrets/{id}

Permanently deletes a secret and all associated key shares. Only the owner can delete a secret. Returns 404 (not 403) for non-owners to avoid revealing secret existence.

**Auth:** Required

**Path Parameters:**

| Param | Type   | Description |
| ----- | ------ | ----------- |
| `id`  | string | Secret ID   |

**Response:** `200 OK`

```json
{
  "secretId": "secret_uuid",
  "deleted": true,
  "note": "Secreto y todas sus shares eliminados."
}
```

**Errors:** `400`, `401`, `404`, `429`

---

## Shares

### POST /api/shares

Creates or updates a key share for a secret. The owner wraps the symmetric AES key with the recipient's RSA public key and sends the wrapped key to the server. Only the secret owner can create shares.

**Auth:** Required

**Request:**

```json
{
  "secretId": "secret_uuid",
  "recipientId": "recipient_user_uuid",
  "wrappedSymmetricKey": "RSA-OAEP-wrapped-AES-key-256-bytes-base64"
}
```

**Response:** `200 OK`

```json
{
  "shareId": "share_uuid",
  "secretId": "secret_uuid",
  "recipientId": "recipient_user_uuid",
  "recipientEmail": "bob@example.com",
  "recipientFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "createdAt": "2025-06-15T10:30:00.000Z"
}
```

**Errors:** `400`, `401`, `403` (only owner can share), `404`, `429`

---

### DELETE /api/shares

Revokes a user's access to a secret. Two modes:

- **Owner revokes a recipient** (offboarding)
- **Recipient performs a self-leave**

Only the owner can revoke other users. Recipients can only revoke themselves. The owner cannot revoke their own access.

**Auth:** Required

**Request:**

```json
{
  "secretId": "secret_uuid",
  "recipientId": "recipient_user_uuid"
}
```

**Response:** `200 OK`

```json
{
  "secretId": "secret_uuid",
  "recipientId": "recipient_user_uuid",
  "revoked": true,
  "mode": "owner-revoke",
  "note": "Share revocado. El destinatario ya no puede descifrar este secreto."
}
```

`mode` enum: `owner-revoke`, `self-leave`

**Errors:** `400`, `401`, `403`, `404`, `429`

---

## Devices

### POST /api/devices/enroll/init

Starts the enrollment flow for a new device. The new device (B) registers its ECDH public key and receives a 6-digit enrollment code. No authentication required. Rate-limited.

**Request:**

```json
{
  "email": "alice@example.com",
  "deviceName": "Nuevo Portátil",
  "publicKeyECDH": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url-x-coordinate",
    "y": "base64url-y-coordinate",
    "ext": true
  },
  "publicKeyECDHFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"
}
```

**Response:** `200 OK`

```json
{
  "deviceId": "device_uuid",
  "enrollCode": "482931",
  "expiresAt": "2025-06-15T10:35:00.000Z",
  "note": "Código de enrolamiento válido por 5 minutos."
}
```

**Errors:** `400`, `404`, `429`

---

### GET /api/devices/enroll/lookup?code=<6-digit-code>

Used by the already-authenticated device (A) to look up the new device's (B) ECDH public key by enrollment code. This allows device A to wrap the private key for device B.

**Auth:** Required

**Query Parameters:**

| Param  | Type   | Required | Description             |
| ------ | ------ | -------- | ----------------------- |
| `code` | string | yes      | 6-digit enrollment code |

**Response:** `200 OK`

```json
{
  "deviceId": "device_uuid",
  "deviceName": "Nuevo Portátil",
  "publicKeyECDH": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url-x-coordinate",
    "y": "base64url-y-coordinate"
  },
  "publicKeyECDHFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "enrollCodeExpiresAt": "2025-06-15T10:35:00.000Z"
}
```

**Errors:** `400`, `401`, `404`, `429`

---

### POST /api/devices/enroll/complete

The authenticated device (A) provides the wrapped RSA private key encrypted for device B's ECDH key. The server stores the wrapped key and clears the enrollment code.

**Auth:** Required

**Request:**

```json
{
  "enrollCode": "482931",
  "wrappedPrivateKeyForDevice": "ECDH-wrapped-RSA-private-key-base64",
  "wrappedPrivateKeyIv": "base64-iv-12-bytes",
  "enrollerPublicKeyECDH": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url-x-coordinate-of-A",
    "y": "base64url-y-coordinate-of-A"
  }
}
```

**Response:** `200 OK`

```json
{
  "deviceId": "device_uuid",
  "deviceName": "Nuevo Portátil",
  "enrolled": true,
  "note": "Dispositivo enrolado. El nuevo dispositivo debe verificar el challenge ECDSA para recibir la llave envuelta."
}
```

**Errors:** `400`, `401`, `403` (code belongs to a different user), `404`, `429`

---

### POST /api/devices/enroll/poll

The new device (B) polls this endpoint to check if enrollment was completed and to receive a cryptographic challenge (32-byte nonce). The challenge must be signed with the device's ECDH private key.

**Request:**

```json
{
  "deviceId": "device_uuid"
}
```

**Response:** `200 OK` (enrolled)

```json
{
  "enrolled": true,
  "deviceId": "device_uuid",
  "deviceName": "Nuevo Portátil",
  "challenge": "32-byte-random-nonce-base64",
  "challengeExpiresIn": 60,
  "publicKeyECDHFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
  "nextStep": "Firma el challenge con ECDSA P-256 y llama a /api/devices/enroll/poll/verify"
}
```

**Response:** `200 OK` (not yet enrolled)

```json
{
  "enrolled": false,
  "message": "Enrolamiento aún no completado. Esperando al dispositivo A."
}
```

**Errors:** `400`, `403` (device revoked), `404`, `429`

---

### POST /api/devices/enroll/poll/verify

The new device (B) submits its signed challenge to prove possession of the ECDH private key. If the signature verifies, the server returns the wrapped RSA private key and associated material.

Challenge is one-time use. Rate-limited to **5 attempts/min**.

**Request:**

```json
{
  "deviceId": "device_uuid",
  "challenge": "challenge-from-poll-endpoint",
  "signature": "ECDSA-P-256-signature-base64"
}
```

**Response:** `200 OK`

```json
{
  "enrolled": true,
  "deviceId": "device_uuid",
  "deviceName": "Nuevo Portátil",
  "wrappedPrivateKeyForDevice": "ECDH-wrapped-private-key...",
  "wrappedPrivateKeyIv": "base64-iv",
  "publicKeyECDH": {},
  "enrollerPublicKeyECDH": {},
  "note": "Challenge verificado. Deriva el shared secret ECDH para desenvovler la llave privada."
}
```

**Errors:** `400`, `403` (challenge verification failed), `404`, `429`

---

### GET /api/devices/list

Lists all non-revoked devices registered to the authenticated user. Supports pagination.

**Auth:** Required

**Query Parameters:**

| Param    | Type    | Default | Description                       |
| -------- | ------- | ------- | --------------------------------- |
| `offset` | integer | 0       | Number of items to skip           |
| `limit`  | integer | 50      | Maximum items to return (max 100) |

**Response:** `200 OK`

```json
{
  "devices": [
    {
      "id": "device_uuid",
      "deviceName": "Mi Portátil",
      "publicKeyECDHFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
      "enrolledAt": "2025-06-15T10:30:00.000Z",
      "lastSeenAt": "2025-06-16T08:00:00.000Z"
    }
  ],
  "pagination": {
    "offset": 0,
    "limit": 50,
    "total": 1,
    "hasMore": false
  }
}
```

**Errors:** `401`, `429`

---

### DELETE /api/devices/{id}

Revokes a device by marking it as revoked (soft delete for audit). The device can no longer poll or decrypt new data.

**Auth:** Required

**Path Parameters:**

| Param | Type   | Description |
| ----- | ------ | ----------- |
| `id`  | string | Device ID   |

**Response:** `200 OK`

```json
{
  "deviceId": "device_uuid",
  "revoked": true,
  "note": "Dispositivo revocado. Si tenía copia local de la llave privada, deberías rotar tu contraseña maestra."
}
```

**Errors:** `400`, `401`, `404`, `429`

---

## Users

### GET /api/users/lookup?email=<email>

Looks up a user's public key and fingerprint by email. Used to wrap symmetric keys with the recipient's RSA public key before sharing. No authentication required (public keys are public).

**Query Parameters:**

| Param   | Type   | Required | Description        |
| ------- | ------ | -------- | ------------------ |
| `email` | string | yes      | User email address |

**Response:** `200 OK`

```json
{
  "userId": "user_uuid",
  "email": "alice@example.com",
  "name": "Alice",
  "publicKeyJwk": { "kty": "RSA", "n": "...", "e": "AQAB" },
  "publicKeyFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"
}
```

**Errors:** `400`, `404`, `429`

---

### GET /api/users/list

Lists all registered users (excluding the authenticated user). Returns ID, email, name, and public key fingerprint for each user.

**Auth:** Required

**Response:** `200 OK`

```json
{
  "users": [
    {
      "id": "user_uuid",
      "email": "bob@example.com",
      "name": "Bob",
      "publicKeyFingerprint": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    }
  ]
}
```

**Errors:** `401`, `429`

---

## Audit Logs

### GET /api/audit-logs

Returns encrypted audit log entries for the authenticated user. Logs form an immutable hash chain (each entry references the SHA-256 of the previous entry's ciphertext). Supports filtering by category.

**Auth:** Required

**Query Parameters:**

| Param      | Type    | Default | Description                                                               |
| ---------- | ------- | ------- | ------------------------------------------------------------------------- |
| `category` | string  | —       | Filter by event category: `auth`, `secret`, `share`, `device`, `recovery` |
| `limit`    | integer | 100     | Maximum number of logs to return (max 200)                                |

**Response:** `200 OK`

```json
{
  "logs": [
    {
      "id": "log_uuid",
      "encryptedEvent": "AES-256-GCM-ciphertext...",
      "eventIv": "base64-iv",
      "eventCategory": "auth",
      "previousEventHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "eventSignature": null,
      "createdAt": "2025-06-15T10:30:00.000Z"
    }
  ]
}
```

**Errors:** `401`, `429`

---

### POST /api/audit-logs

Creates a new encrypted audit log entry. The client encrypts the event details with AES-256-GCM using a key derived from the master key. The server links it into an immutable hash chain.

**Auth:** Required

**Request:**

```json
{
  "encryptedEvent": "AES-256-GCM-encrypted-event...",
  "eventIv": "base64-iv-12-bytes",
  "eventCategory": "auth",
  "eventSignature": "optional-signature-for-non-repudiation"
}
```

`eventCategory` enum: `auth`, `secret`, `share`, `device`, `recovery`

**Response:** `201 Created`

```json
{
  "logId": "log_uuid",
  "createdAt": "2025-06-15T10:30:00.000Z",
  "previousEventHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "note": "Log cifrado añadido a la cadena inmutable."
}
```

**Errors:** `400`, `401`, `429`

---

## Emergency Access

### POST /api/emergency-access

Creates an emergency access grant. The grant has a configurable time-lock delay (default 72 hours). The beneficiary must wait for the delay to expire before recovering the grantor's encrypted private key.

**Auth:** Required

**Request:**

```json
{
  "beneficiaryEmail": "bob@example.com",
  "message": "Acceso de emergencia por si algo me pasa.",
  "delayHours": 72
}
```

**Response:** `201 Created`

```json
{
  "id": "grant_uuid",
  "beneficiaryId": "beneficiary_uuid",
  "beneficiaryEmail": "bob@example.com",
  "beneficiaryName": "Bob",
  "status": "pending",
  "delayHours": 72,
  "message": "Acceso de emergencia por si algo me pasa.",
  "createdAt": "2025-06-15T10:30:00.000Z"
}
```

**Errors:** `400`, `401`, `404`, `409` (grant already exists), `429`

---

### GET /api/emergency-access

Lists all emergency access grants where the authenticated user is either the grantor or the beneficiary. Returns both active and historical grants.

**Auth:** Required

**Response:** `200 OK`

```json
{
  "asGrantor": [
    {
      "id": "grant_uuid",
      "grantorId": "grantor_uuid",
      "beneficiaryId": "beneficiary_uuid",
      "status": "pending",
      "delayHours": 72,
      "message": null,
      "claimedAt": null,
      "completedAt": null,
      "createdAt": "2025-06-15T10:30:00.000Z",
      "grantor": { "id": "...", "email": "...", "name": "..." },
      "beneficiary": { "id": "...", "email": "...", "name": "..." }
    }
  ],
  "asBeneficiary": []
}
```

`status` enum: `pending`, `active`, `completed`, `cancelled`

**Errors:** `401`, `429`

---

### POST /api/emergency-access/{id}

Performs an action on an emergency access grant:

- `claim`: Beneficiary initiates access (starts the time-lock delay)
- `cancel`: Grantor cancels a pending grant
- `recover`: Beneficiary recovers the encrypted private key after the time-lock expires

**Auth:** Required

**Path Parameters:**

| Param | Type   | Description               |
| ----- | ------ | ------------------------- |
| `id`  | string | Emergency access grant ID |

**Request:**

```json
{
  "action": "claim"
}
```

**Response:** `200 OK` (claim)

```json
{
  "status": "active",
  "claimedAt": "2025-06-15T10:30:00.000Z",
  "releaseAt": "2025-06-18T10:30:00.000Z"
}
```

**Response:** `200 OK` (recover)

```json
{
  "status": "completed",
  "recoveryBlob": "encrypted-private-key-blob...",
  "recoveryIv": "base64-iv",
  "recoverySalt": "base64-salt",
  "recoveryIterations": 600000,
  "grantorId": "grantor_uuid",
  "remainingSeconds": 0
}
```

**Errors:** `400`, `401`, `403`, `404`, `423` (time-lock not yet expired), `429`

The `423` error includes `remainingSeconds`:

```json
{
  "error": "Time-lock not expired. 3600s remaining.",
  "remainingSeconds": 3600
}
```

---

### DELETE /api/emergency-access/{id}

Cancels a pending emergency access grant. Only the grantor can cancel. This is a convenience alias for `POST /api/emergency-access/{id}` with `action: "cancel"`.

**Auth:** Required

**Path Parameters:**

| Param | Type   | Description               |
| ----- | ------ | ------------------------- |
| `id`  | string | Emergency access grant ID |

**Response:** `200 OK`

```json
{
  "status": "cancelled"
}
```

**Errors:** `401`, `403` (only the grantor can cancel), `404`, `429`

---

## Health

### GET /api/health

Health check endpoint. Returns server status without requiring authentication.

**Response:** `200 OK`

```json
{
  "status": "ok",
  "timestamp": "2025-06-15T10:30:00.000Z",
  "version": "0.2.0"
}
```

---

## Rate Limiting

Rate limits are applied per endpoint with the following defaults:

| Endpoint                               | Limit       | Window              |
| -------------------------------------- | ----------- | ------------------- |
| `POST /api/auth/login`                 | 5 attempts  | 15 min per IP+email |
| `POST /api/devices/enroll/init`        | 10 requests | 15 min per IP+email |
| `GET /api/devices/enroll/lookup`       | 30 requests | 15 min per IP       |
| `POST /api/devices/enroll/poll/verify` | 5 attempts  | 1 min per device    |

When exceeded, the server returns `429 Too Many Requests` with a `retryAfter` field (seconds until retry).

---

## Pagination

List endpoints supporting pagination return a `pagination` object:

```json
{
  "offset": 0,
  "limit": 50,
  "total": 142,
  "hasMore": true
}
```

Clients should increment `offset` by `limit` for subsequent pages.

---

## Data Model

### Prisma Tables (7)

| Table                  | Description                                                            |
| ---------------------- | ---------------------------------------------------------------------- |
| `User`                 | User identity (id, email, name)                                        |
| `UserKeyMaterial`      | KDF parameters, RSA public key, encrypted private key, recovery backup |
| `Secret`               | Encrypted secret blobs (title, data, metadata)                         |
| `SecretKeyShare`       | RSA-OAEP wrapped symmetric keys per recipient                          |
| `Device`               | ECDH public keys, wrapped private keys, enrollment codes               |
| `AuditLog`             | Encrypted audit log entries with hash chain                            |
| `EmergencyAccessGrant` | Time-locked emergency access grants                                    |

### Prisma Schema Details

```
User              — id, email, name
UserKeyMaterial   — kdfAlgorithm, kdfSalt, kdfIterations, kdfMemoryKiB, kdfParallelism,
                    publicKeyJwk, publicKeyFingerprint, popSignature,
                    encryptedPrivateKeyJwk, privateKeyIv,
                    recoverySalt, recoveryIterations, encryptedPrivateKeyForRecovery,
                    recoveryIv, recoveryEnabled
Secret            — ownerId, encryptedTitle, titleIv, encryptedData, dataIv,
                    encryptedMetadata, metadataIv, secretType
SecretKeyShare    — secretId, recipientId, wrappedSymmetricKey
Device            — userId, deviceName, publicKeyECDH, publicKeyECDHFingerprint,
                    enrollerPublicKeyECDH, wrappedPrivateKeyForDevice, wrappedPrivateKeyIv,
                    enrollCode, enrollCodeExpiresAt, revokedAt
AuditLog          — userId, encryptedEvent, eventIv, eventCategory,
                    previousEventHash, eventSignature
EmergencyAccessGrant — grantorId, beneficiaryId, status, delayHours, message,
                       claimedAt, completedAt, createdAt
```
