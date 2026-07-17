# Immutable Audit Log System

## Overview

Zero-Knowledge Vault implements an **immutable, client-encrypted audit log**
system. Every security-relevant action is logged and encrypted before leaving
the browser, ensuring the server can verify integrity without reading contents.

## Zero-Knowledge Property

The audit log system maintains the zero-knowledge guarantee:

| The server stores | The server NEVER sees |
|---|---|
| Encrypted event blob (AES-256-GCM) | Event plaintext |
| Event IV (random 12 bytes) | AES symmetric key |
| Event category (low-entropy enum) | Decrypted details |
| User ID (to associate logs) | Master key |

## Encryption Flow

1. User performs an action (login, create secret, share, etc.)
2. Client derives an **audit encryption key** from the master key:
   ```
   auditKey = HKDF(masterKey, "zk-vault-audit-log-v1")
   ```
3. Client encrypts the event JSON with AES-256-GCM using `auditKey`
4. Client sends the ciphertext + IV + category to the server
5. Server stores the blob — cannot decrypt it

## Verification

- The server validates the AES-GCM blob structure (length check)
- The `eventCategory` field allows the server to index logs without decryption
- Clients can decrypt their own audit logs on demand

## Available Categories

| Category | Description |
|----------|-------------|
| `login` | User authentication |
| `logout` | Session termination |
| `secret_create` | New secret created |
| `secret_read` | Secret accessed |
| `secret_update` | Secret modified |
| `secret_delete` | Secret removed |
| `share_create` | Secret shared with user |
| `share_revoke` | Share access revoked |
| `device_enroll` | New device enrolled |
| `device_revoke` | Device revoked |
| `recovery_setup` | Recovery phrase configured |
| `recovery_use` | Account recovered |
| `password_rotate` | Master password changed |
| `approval_request` | Share approval requested |
| `approval_response` | Share approved/denied |

## Audit Log API

- `POST /api/audit-logs` — Create a new audit log entry
- `GET /api/audit-logs` — List audit logs (decrypted client-side)
- Each entry is immutable once created (no DELETE/UPDATE)

## Integrity Chain

For production deployments, consider adding a **hash chain** to the audit log:

1. Each log entry includes `previousHash: SHA-256(previousEntry)`
2. The server periodically publishes the latest hash
3. Clients can verify no entries have been tampered with

This is documented as a future enhancement (see `docs/SECURITY_AUDIT_REPORT.md`).
