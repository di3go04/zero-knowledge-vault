/**
 * =====================================================================
 * validation-schemas.ts — Esquemas Zod para validación server-side.
 * =====================================================================
 * Endurecimiento de validación: rechaza activamente cualquier dato que
 * no sea un blob cifrado válido. Verifica:
 *   - Que los strings sean Base64 válido (charset + padding)
 *   - Que al decodificar tengan la longitud esperada de un blob AES-GCM
 *     (IV 12 bytes + ciphertext + tag 16 bytes)
 *   - Que no sean strings vacíos ni JSON plano
 *
 * Usado en todos los endpoints de secrets, shares y devices.
 * =====================================================================
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Valida que un string sea Base64 estándar (con padding) o URL-safe.
 * Rechaza strings vacíos y JSON.
 */
const base64String = z
  .string()
  .min(1, "No puede estar vacío")
  .max(200_000, "Excede el tamaño máximo")
  .regex(
    /^[A-Za-z0-9+/=_-]+$/,
    "Debe ser Base64 válido (solo A-Z, a-z, 0-9, +, /, =, -, _)",
  );

/**
 * Valida un blob AES-256-GCM cifrado.
 * Estructura: IV (12 bytes) + ciphertext + tag (16 bytes) → mínimo 28 bytes.
 * Al decodificar base64, verificamos que la longitud esté en rango.
 *
 * En la práctica, el servidor solo puede validar la longitud decodificada
 * porque no tiene la llave para verificar el tag. Pero la longitud mínima
 * filtra la mayoría de ataques (strings vacíos, JSON, etc.).
 */
const aesGcmBlob = (minDecodedBytes: number = 28, maxDecodedBytes: number = 64 * 1024) =>
  base64String.refine(
    (s) => {
      try {
        const decoded = Buffer.from(s, "base64");
        return decoded.length >= minDecodedBytes && decoded.length <= maxDecodedBytes;
      } catch {
        return false;
      }
    },
    `Debe decodificar a ${minDecodedBytes}-${maxDecodedBytes} bytes (blob AES-GCM)`,
  );

/**
 * Valida un IV de AES-GCM (exactamente 12 bytes = 96 bits).
 */
const aesGcmIv = base64String.refine(
  (s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length === 12;
    } catch {
      return false;
    }
  },
  "IV debe ser exactamente 12 bytes (96 bits, GCM recomendado)",
);

/**
 * Valida una llave wrapped con RSA-OAEP-2048 (exactamente 256 bytes).
 */
const rsaWrappedKey = base64String.refine(
  (s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length === 256; // RSA-2048 = 256 bytes
    } catch {
      return false;
    }
  },
  "WrappedKey debe ser exactamente 256 bytes (RSA-OAEP-2048)",
);

/**
 * Valida un salt de KDF (16-64 bytes).
 */
const kdfSalt = base64String.refine(
  (s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length >= 16 && decoded.length <= 64;
    } catch {
      return false;
    }
  },
  "Salt debe ser 16-64 bytes",
);

/**
 * Valida un fingerprint SHA-256 (64 hex chars).
 */
const fingerprint = z
  .string()
  .length(64, "Fingerprint debe ser 64 chars hex")
  .regex(/^[0-9a-f]{64}$/, "Fingerprint debe ser hex SHA-256 (64 chars)");

/**
 * Valida un email (RFC 5322 simplificado, max 320 chars).
 */
const email = z
  .string()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Email inválido");

/**
 * Valida un enrollCode (6 dígitos).
 */
const enrollCode = z
  .string()
  .length(6, "Código debe ser 6 dígitos")
  .regex(/^\d{6}$/, "Código debe ser solo dígitos");

/**
 * Valida una firma ECDSA P-256 (64-72 bytes DER o 64 bytes raw).
 */
const ecdsaSignature = base64String.refine(
  (s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      // ECDSA P-256 signature: 64 bytes (r,s) o 70-72 bytes (DER)
      return decoded.length >= 64 && decoded.length <= 72;
    } catch {
      return false;
    }
  },
  "Firma ECDSA debe ser 64-72 bytes",
);

// ---------------------------------------------------------------------------
// Schemas por endpoint
// ---------------------------------------------------------------------------

// -------- /api/secrets --------
export const createSecretSchema = z.object({
  encryptedTitle: aesGcmBlob(28, 64 * 1024),
  titleIv: aesGcmIv,
  encryptedData: aesGcmBlob(28, 64 * 1024),
  dataIv: aesGcmIv,
  wrappedKeyForOwner: rsaWrappedKey,
});

// -------- /api/shares --------
export const createShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  recipientId: z.string().min(1).max(100),
  wrappedSymmetricKey: rsaWrappedKey,
});

export const revokeShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  recipientId: z.string().min(1).max(100),
});

// -------- /api/devices/enroll/init --------
export const enrollInitSchema = z.object({
  email,
  deviceName: z.string().min(1).max(80),
  publicKeyECDH: z.object({
    kty: z.literal("EC"),
    crv: z.string().min(1),
    x: z.string().min(1),
    y: z.string().min(1),
    ext: z.boolean().optional(),
    key_ops: z.array(z.string()).optional(),
  }),
  publicKeyECDHFingerprint: fingerprint,
});

// -------- /api/devices/enroll/complete --------
export const enrollCompleteSchema = z.object({
  enrollCode,
  wrappedPrivateKeyForDevice: aesGcmBlob(28, 64 * 1024),
  wrappedPrivateKeyIv: aesGcmIv,
  enrollerPublicKeyECDH: z.object({
    kty: z.literal("EC"),
    crv: z.string().min(1),
    x: z.string().min(1),
    y: z.string().min(1),
    ext: z.boolean().optional(),
    key_ops: z.array(z.string()).optional(),
  }),
});

// -------- /api/devices/enroll/poll --------
export const enrollPollSchema = z.object({
  deviceId: z.string().min(1).max(100),
});

// -------- /api/devices/enroll/poll/verify --------
export const enrollVerifySchema = z.object({
  deviceId: z.string().min(1).max(100),
  challenge: base64String.refine(
    (s) => {
      try {
        const decoded = Buffer.from(s, "base64");
        return decoded.length === 32; // 32 bytes = 256 bits
      } catch {
        return false;
      }
    },
    "Challenge debe ser 32 bytes",
  ),
  signature: ecdsaSignature,
});

// -------- /api/auth/register --------
export const registerSchema = z.object({
  email,
  name: z.string().max(100).optional(),
  kdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  kdfSalt,
  kdfIterations: z.number().int().min(1).max(10_000_000),
  kdfMemoryKiB: z.number().int().min(16_384).max(1_048_576).optional(),
  kdfParallelism: z.number().int().min(1).max(16).optional(),
  publicKeyJwk: z.object({
    kty: z.literal("RSA"),
    n: z.string().min(1),
    e: z.string().min(1),
    ext: z.boolean().optional(),
    key_ops: z.array(z.string()).optional(),
    alg: z.string().optional(),
  }),
  publicKeyFingerprint: fingerprint,
  popSignature: base64String,
  encryptedPrivateKeyJwk: aesGcmBlob(28, 64 * 1024),
  privateKeyIv: aesGcmIv,
});

// -------- /api/auth/rotate --------
export const rotateSchema = z.object({
  newKdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  newKdfSalt,
  newKdfIterations: z.number().int().min(1).max(10_000_000),
  newKdfMemoryKiB: z.number().int().min(16_384).max(1_048_576).optional(),
  newKdfParallelism: z.number().int().min(1).max(16).optional(),
  newEncryptedPrivateKeyJwk: aesGcmBlob(28, 64 * 1024),
  newPrivateKeyIv: aesGcmIv,
  newPopSignature: base64String,
});

// -------- /api/auth/recovery/setup --------
export const recoverySetupSchema = z.object({
  recoverySalt: kdfSalt,
  recoveryIterations: z.number().int().min(100_000).max(10_000_000),
  encryptedPrivateKeyForRecovery: aesGcmBlob(28, 64 * 1024),
  recoveryIv: aesGcmIv,
});

// -------- /api/audit-logs --------
export const createAuditLogSchema = z.object({
  encryptedEvent: aesGcmBlob(28, 64 * 1024),
  eventIv: aesGcmIv,
  eventCategory: z.enum(["auth", "secret", "share", "device", "recovery"]),
});

// ---------------------------------------------------------------------------
// Helper para usar en endpoints
// ---------------------------------------------------------------------------

/**
 * Valida un payload contra un schema Zod. Devuelve:
 *   - { success: true, data } si es válido
 *   - { success: false, error } si no (con mensaje legible)
 */
export function validatePayload<T>(
  schema: z.ZodSchema<T>,
  payload: unknown,
):
  | { success: true; data: T }
  | { success: false; error: string } {
  const result = schema.safeParse(payload);
  if (result.success) {
    return { success: true, data: result.data };
  }
  // Formatear errores Zod en un solo string
  const errorMsg = result.error.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join("; ");
  return { success: false, error: errorMsg };
}

// ---------------------------------------------------------------------------
// Schemas para endpoints que faltaban (login, recovery/recover, query params)
// ---------------------------------------------------------------------------

// -------- /api/auth/login --------
export const loginSchema = z.object({
  email,
});

// -------- /api/auth/recovery/recover --------
// Dos modos: "get-blob" (obtiene blob de recuperación) y "complete" (restablece)
export const recoveryGetBlobSchema = z.object({
  email,
  action: z.literal("get-blob"),
});

export const recoveryCompleteSchema = z.object({
  email,
  action: z.literal("complete"),
  newKdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  newKdfSalt,
  newKdfIterations: z.number().int().min(1).max(10_000_000),
  newKdfMemoryKiB: z.number().int().min(16_384).max(1_048_576).optional(),
  newKdfParallelism: z.number().int().min(1).max(16).optional(),
  newEncryptedPrivateKeyJwk: aesGcmBlob(28, 64 * 1024),
  newPrivateKeyIv: aesGcmIv,
  newPopSignature: base64String,
});

// -------- Query param validators (GET endpoints) --------

/** Valida un query param `code` de 6 dígitos. */
export const queryEnrollCodeSchema = z.object({
  code: z
    .string()
    .min(1, "code requerido")
    .max(6)
    .regex(/^\d{6}$/, "code debe ser 6 dígitos"),
});

/** Valida un query param `email`. */
export const queryEmailSchema = z.object({
  email,
});

/** Valida un query param `category` para audit logs. */
export const queryCategorySchema = z.object({
  category: z
    .string()
    .optional()
    .refine(
      (v) => !v || ["auth", "secret", "share", "device", "recovery"].includes(v),
      "category debe ser uno de: auth, secret, share, device, recovery",
    ),
  limit: z
    .string()
    .optional()
    .refine(
      (v) => !v || (/^\d+$/.test(v) && parseInt(v, 10) > 0 && parseInt(v, 10) <= 200),
      "limit debe ser entero 1-200",
    ),
});

/** Valida un path param `id` (cuid). */
export const pathIdSchema = z
  .string()
  .min(1, "id requerido")
  .max(100, "id demasiado largo")
  .regex(/^[a-zA-Z0-9_-]+$/, "id debe ser alfanumérico");
