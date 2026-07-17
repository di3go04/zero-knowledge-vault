# Key Rotation System

## Overview

Zero-Knowledge Vault enforces **automatic master password rotation** for
security best practices. The system tracks when the master password was
last changed and warns the user before expiration.

## Rotation Policy

| Setting           | Value                            |
| ----------------- | -------------------------------- |
| Rotation interval | 30 days                          |
| Warning period    | 3 days before expiry             |
| Enforcement       | Warning only (no forced lockout) |

## How It Works

1. When the user changes their master password, the `passwordChangedAt`
   timestamp is updated on the `UserKeyMaterial` record.
2. On each login, the client checks the timestamp.
3. If within the 3-day warning window, a banner is shown in the UI.
4. If past 30 days, the banner becomes more prominent.

## API Endpoints

- `GET /api/auth/rotation-status` — Returns { daysRemaining, needsRotation }
- `POST /api/auth/rotate` — Rotates master password (re-encrypts all keys)

## Client-Side Check

The rotation check happens in `src/lib/key-rotation.ts`:

```
checkRotationStatus(lastRotation: Date): {
  daysRemaining: number
  needsRotation: boolean
  inWarningWindow: boolean
}
```

## Future Enhancements

- Admin-enforced rotation policies
- Automatic rotation scheduling
- Rotation history audit log
