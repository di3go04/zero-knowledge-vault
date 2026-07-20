import { z } from "zod";

const base64String = z
  .string()
  .min(1, "No puede estar vacío")
  .max(200_000, "Excede el tamaño máximo")
  .regex(/^[A-Za-z0-9+/=_-]+$/, "Debe ser Base64 válido (solo A-Z, a-z, 0-9, +, /, =, -, _)");

const aesGcmBlob = (minDecodedBytes: number = 28, maxDecodedBytes: number = 64 * 1024) =>
  base64String.refine((s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length >= minDecodedBytes && decoded.length <= maxDecodedBytes;
    } catch {
      return false;
    }
  }, `Debe decodificar a ${minDecodedBytes}-${maxDecodedBytes} bytes (blob AES-GCM)`);

const aesGcmIv = base64String.refine((s) => {
  try {
    const decoded = Buffer.from(s, "base64");
    return decoded.length === 12;
  } catch {
    return false;
  }
}, "IV debe ser exactamente 12 bytes (96 bits, GCM recomendado)");

const rsaWrappedKey = base64String.refine((s) => {
  try {
    const decoded = Buffer.from(s, "base64");
    return decoded.length === 256;
  } catch {
    return false;
  }
}, "WrappedKey debe ser exactamente 256 bytes (RSA-OAEP-2048)");

const kemWrappedKey = base64String.refine(
  (s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length >= 1088 && decoded.length <= 2048;
    } catch { return false; }
  },
  "KEM wrapped key must be 1088-2048 bytes (ML-KEM-768 hybrid)",
);

const wrappedKey = z.union([rsaWrappedKey, kemWrappedKey]);

const kdfSalt = base64String.refine((s) => {
  try {
    const decoded = Buffer.from(s, "base64");
    return decoded.length >= 16 && decoded.length <= 64;
  } catch {
    return false;
  }
}, "Salt debe ser 16-64 bytes");

const fingerprint = z
  .string()
  .length(64, "Fingerprint debe ser 64 chars hex")
  .regex(/^[0-9a-f]{64}$/, "Fingerprint debe ser hex SHA-256 (64 chars)");

const email = z
  .string()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Email inválido");

const enrollCode = z
  .string()
  .length(6, "Código debe ser 6 dígitos")
  .regex(/^\d{6}$/, "Código debe ser solo dígitos");

const ecdsaSignature = base64String.refine((s) => {
  try {
    const decoded = Buffer.from(s, "base64");
    return decoded.length >= 64 && decoded.length <= 72;
  } catch {
    return false;
  }
}, "Firma ECDSA debe ser 64-72 bytes");

export const SECRET_TYPES = [
  "password",
  "note",
  "ssh-key",
  "api-key",
  "certificate",
  "database",
] as const;

export const createSecretSchema = z.object({
  encryptedTitle: aesGcmBlob(28, 64 * 1024),
  titleIv: aesGcmIv,
  encryptedData: aesGcmBlob(28, 64 * 1024),
  dataIv: aesGcmIv,
  wrappedKeyForOwner: wrappedKey,
});

export const createShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  recipientId: z.string().min(1).max(100),
  wrappedSymmetricKey: wrappedKey,
});

export const revokeShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  recipientId: z.string().min(1).max(100),
});

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

export const enrollPollSchema = z.object({
  deviceId: z.string().min(1).max(100),
});

export const enrollVerifySchema = z.object({
  deviceId: z.string().min(1).max(100),
  challenge: base64String.refine((s) => {
    try {
      const decoded = Buffer.from(s, "base64");
      return decoded.length === 32;
    } catch {
      return false;
    }
  }, "Challenge debe ser 32 bytes"),
  signature: ecdsaSignature,
});

export const registerSchema = z.object({
  email,
  name: z.string().max(100).optional(),
  kdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  kdfSalt,
  kdfIterations: z.number().int().min(310_000).max(1_000_000),
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
  mlKemPublicKey: base64String.optional(),
  encryptedMlKemPrivateKey: aesGcmBlob(28, 64 * 1024).optional(),
  mlKemPrivateKeyIv: aesGcmIv.optional(),
  website: z.string().max(0).optional(),
});

export const rotateSchema = z.object({
  newKdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  newKdfSalt: kdfSalt,
  newKdfIterations: z.number().int().min(310_000).max(1_000_000),
  newKdfMemoryKiB: z.number().int().min(16_384).max(1_048_576).optional(),
  newKdfParallelism: z.number().int().min(1).max(16).optional(),
  newEncryptedPrivateKeyJwk: aesGcmBlob(28, 64 * 1024),
  newPrivateKeyIv: aesGcmIv,
  newPopSignature: base64String,
});

export const recoverySetupSchema = z.object({
  recoverySalt: kdfSalt,
  recoveryIterations: z.number().int().min(100_000).max(10_000_000),
  encryptedPrivateKeyForRecovery: aesGcmBlob(28, 64 * 1024),
  recoveryIv: aesGcmIv,
});

export const createAuditLogSchema = z.object({
  encryptedEvent: aesGcmBlob(28, 64 * 1024),
  eventIv: aesGcmIv,
  eventCategory: z.enum(["auth", "secret", "share", "device", "recovery"]),
});

export function validatePayload<T>(
  schema: z.ZodSchema<T>,
  payload: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(payload);
  if (result.success) {
    return { success: true, data: result.data };
  }
  const errorMsg = result.error.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join("; ");
  return { success: false, error: errorMsg };
}

export const loginSchema = z.object({
  email,
});

export const recoveryGetBlobSchema = z.object({
  email,
  action: z.literal("get-blob"),
});

export const recoveryCompleteSchema = z.object({
  email,
  action: z.literal("complete"),
  newKdfAlgorithm: z.enum(["argon2id", "pbkdf2"]),
  newKdfSalt: kdfSalt,
  newKdfIterations: z.number().int().min(310_000).max(1_000_000),
  newKdfMemoryKiB: z.number().int().min(16_384).max(1_048_576).optional(),
  newKdfParallelism: z.number().int().min(1).max(16).optional(),
  newEncryptedPrivateKeyJwk: aesGcmBlob(28, 64 * 1024),
  newPrivateKeyIv: aesGcmIv,
  newPopSignature: base64String,
});

export const queryEnrollCodeSchema = z.object({
  code: z
    .string()
    .min(1, "code requerido")
    .max(6)
    .regex(/^\d{6}$/, "code debe ser 6 dígitos"),
});

export const queryEmailSchema = z.object({
  email,
});

export const queryCategorySchema = z.object({
  category: z
    .string()
    .optional()
    .refine(
      (v) => !v || ["auth", "secret", "share", "device", "recovery"].includes(v),
      "category debe ser uno de: auth, secret, share, device, recovery"
    ),
  limit: z
    .string()
    .optional()
    .refine(
      (v) => !v || (/^\d+$/.test(v) && parseInt(v, 10) > 0 && parseInt(v, 10) <= 200),
      "limit debe ser entero 1-200"
    ),
});

export const paginationSchema = z.object({
  offset: z
    .string()
    .optional()
    .refine((v) => !v || (/^\d+$/.test(v) && parseInt(v, 10) >= 0), "offset debe ser entero >= 0"),
  limit: z
    .string()
    .optional()
    .refine(
      (v) => !v || (/^\d+$/.test(v) && parseInt(v, 10) > 0 && parseInt(v, 10) <= 100),
      "limit debe ser entero 1-100"
    ),
});

export function parsePagination(searchParams: URLSearchParams): { offset: number; limit: number } {
  const rawOffset = searchParams.get("offset") ?? "0";
  const rawLimit = searchParams.get("limit") ?? "50";
  const offset = Math.max(0, parseInt(rawOffset, 10) || 0);
  const limit = Math.min(100, Math.max(1, parseInt(rawLimit, 10) || 50));
  return { offset, limit };
}

export const pathIdSchema = z
  .string()
  .min(1, "id requerido")
  .max(100, "id demasiado largo")
  .regex(/^[a-zA-Z0-9_-]+$/, "id debe ser alfanumérico");

export const createEmergencyAccessSchema = z.object({
  beneficiaryEmail: z.string().email().min(3).max(320),
  message: z.string().max(500).optional(),
  delayHours: z.number().int().min(1).max(8760).default(72),
});

export const claimEmergencyAccessSchema = z.object({
  action: z.enum(["claim", "cancel", "recover"]),
});

export const scimUserSchema = z.object({
  schemas: z.array(z.string()).optional(),
  userName: z.string().min(1).max(255),
  name: z
    .object({
      givenName: z.string().optional(),
      familyName: z.string().optional(),
    })
    .optional(),
  emails: z
    .array(
      z.object({
        value: z.string().email(),
        primary: z.boolean().optional(),
      })
    )
    .optional(),
  active: z.boolean().optional(),
  externalId: z.string().max(255).optional(),
});

export const ssoProviderSchema = z.object({
  providerType: z.enum(["saml", "oidc"]),
  providerName: z.string().min(1).max(100),
  issuerUrl: z.string().url().max(500),
  clientId: z.string().max(500).optional(),
  clientSecret: z.string().max(2000).optional(),
  metadataUrl: z.string().url().max(500).optional(),
  metadataXml: z.string().max(100_000).optional(),
  attributeMapping: z.string().max(10_000).optional(),
  enabled: z.boolean().optional(),
});

export const ssoProviderUpdateSchema = ssoProviderSchema.partial();

export const directoryConnectorSchema = z.object({
  name: z.string().min(1).max(100),
  providerType: z.enum(["ldap", "active-directory"]),
  url: z.string().min(1).max(500),
  baseDn: z.string().min(1).max(500),
  bindDn: z.string().min(1).max(500),
  bindPassword: z.string().min(1).max(2000),
  userSearchFilter: z.string().max(500).optional(),
  groupSearchFilter: z.string().max(500).optional(),
  syncIntervalSec: z.number().int().min(60).max(86400).optional(),
  enabled: z.boolean().optional(),
});

export const directoryConnectorUpdateSchema = directoryConnectorSchema.partial();

export const roleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  isSystem: z.boolean().optional(),
});

export const roleUpdateSchema = roleSchema.partial();

export const permissionSchema = z.object({
  action: z.string().min(1).max(100),
  resource: z.string().min(1).max(100),
  conditions: z.string().max(5000).optional(),
});

export const userRoleAssignmentSchema = z.object({
  roleId: z.string().min(1).max(100),
});

export const groupSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
});

export const groupUpdateSchema = groupSchema.partial();

export const groupMemberSchema = z.object({
  userId: z.string().min(1).max(100),
  role: z.enum(["member", "admin"]).optional(),
});

export const groupPolicySchema = z.object({
  policyType: z.enum(["password", "session", "mfa", "sharing"]),
  policyValue: z.string().min(1),
  enabled: z.boolean().optional(),
});

export const groupPolicyUpdateSchema = groupPolicySchema.partial();

export const approvalRequestSchema = z.object({
  action: z.enum(["share", "export", "emergency-access", "admin-action"]),
  resourceType: z.enum(["secret", "vault", "setting"]),
  resourceId: z.string().max(100).optional(),
  reason: z.string().min(1).max(2000),
});

export const approvalDecisionSchema = z.object({
  decision: z.enum(["approved", "rejected"]),
  comment: z.string().max(2000).optional(),
});

export const breakGlassSchema = z.object({
  reason: z.string().min(1).max(2000),
});

export const breakGlassDecisionSchema = z.object({
  decision: z.enum(["approved", "denied"]),
});

export const webhookSchema = z.object({
  name: z.string().min(1).max(100),
  url: z.string().url().max(500),
  secret: z.string().max(500).optional(),
  events: z.array(z.string().min(1)).min(1),
  enabled: z.boolean().optional(),
  retryCount: z.number().int().min(0).max(10).optional(),
  timeoutMs: z.number().int().min(1000).max(30000).optional(),
});

export const webhookUpdateSchema = webhookSchema.partial();

export const complianceReportSchema = z.object({
  reportType: z.enum(["soc2", "hipaa", "gdpr", "custom", "admin-audit"]),
  periodStart: z.string().datetime(),
  periodEnd: z.string().datetime(),
  parameters: z.string().max(10_000).optional(),
});

export const eDiscoverySearchSchema = z.object({
  targetEmail: z.string().email().optional(),
  targetUserId: z.string().max(100).optional(),
  reason: z.string().min(1).max(2000),
  dataTypes: z
    .array(z.enum(["audit-logs", "secrets", "devices", "shares", "user-profile", "sessions"]))
    .min(1),
});

export const dlpRuleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  pattern: z.string().min(1).max(2000),
  action: z.enum(["block", "alert", "mask", "audit"]),
  resourceType: z.enum(["secret", "note", "all"]).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  enabled: z.boolean().optional(),
});

export const dlpRuleUpdateSchema = dlpRuleSchema.partial();

export const retentionPolicySchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  resourceType: z.enum(["audit-log", "secret", "session", "export"]),
  retentionDays: z.number().int().min(1).max(36500),
  action: z.enum(["delete", "archive", "anonymize"]).optional(),
  enabled: z.boolean().optional(),
});

export const retentionPolicyUpdateSchema = retentionPolicySchema.partial();

export const roleScopeSchema = z.object({
  scopeType: z.enum(["global", "group", "vault"]),
  scopeValue: z.string().max(100).optional(),
});

export const rolePermissionOverrideSchema = z.object({
  permissionKey: z.string().min(1).max(100),
  granted: z.boolean().optional(),
});

export const directorySyncConfigSchema = z.object({
  provider: z.enum(["azure-ad", "google-workspace", "okta", "onelogin"]),
  name: z.string().min(1).max(100),
  clientId: z.string().min(1).max(500),
  clientSecret: z.string().min(1).max(2000),
  tenantId: z.string().max(500).optional(),
  domain: z.string().max(500).optional(),
  syncIntervalSec: z.number().int().min(60).max(86400).optional(),
  enabled: z.boolean().optional(),
});

export const directorySyncConfigUpdateSchema = directorySyncConfigSchema.partial();

export const slaMonitorSchema = z.object({
  name: z.string().min(1).max(100),
  endpoint: z.string().url().max(500),
  method: z.enum(["GET", "POST", "HEAD"]).optional(),
  expectedStatus: z.number().int().min(100).max(599).optional(),
  intervalSec: z.number().int().min(30).max(86400).optional(),
  timeoutMs: z.number().int().min(1000).max(60000).optional(),
  enabled: z.boolean().optional(),
});

export const slaMonitorUpdateSchema = slaMonitorSchema.partial();

export const tenantSchema = z.object({
  name: z.string().min(1).max(200),
  slug: z
    .string()
    .min(2)
    .max(100)
    .regex(/^[a-z0-9-]+$/, "slug must be lowercase alphanumeric with hyphens"),
  domain: z.string().max(500).optional(),
  plan: z.enum(["starter", "business", "enterprise"]).optional(),
  status: z.enum(["active", "suspended", "cancelled"]).optional(),
  maxUsers: z.number().int().min(1).max(100000).optional(),
  maxSecrets: z.number().int().min(1).max(1000000).optional(),
  features: z.string().max(10000).optional(),
});

export const tenantUpdateSchema = tenantSchema.partial();

export const tenantBrandingSchema = z.object({
  logoUrl: z.string().url().max(500).optional(),
  faviconUrl: z.string().url().max(500).optional(),
  primaryColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, "must be hex color")
    .optional(),
  secondaryColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, "must be hex color")
    .optional(),
  accentColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, "must be hex color")
    .optional(),
  companyName: z.string().max(200).optional(),
  supportUrl: z.string().url().max(500).optional(),
  supportEmail: z.string().email().optional(),
  customCss: z.string().max(50000).optional(),
  loginMessage: z.string().max(500).optional(),
});

export const apiKeySchema = z.object({
  name: z.string().min(1).max(100),
  permissions: z.array(z.string().min(1)).min(1),
  expiresAt: z.string().datetime().optional(),
});

export const apiKeyUpdateSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  permissions: z.array(z.string().min(1)).min(1).optional(),
  enabled: z.boolean().optional(),
  expiresAt: z.string().datetime().optional(),
});

export const userActionTokenSchema = z.object({
  userId: z.string().min(1).max(100),
  action: z.enum([
    "email-verify",
    "password-reset",
    "device-approve",
    "recovery-enable",
    "account-recover",
  ]),
  payload: z.string().max(5000).optional(),
  expiresInHours: z.number().int().min(1).max(720).default(24),
});

export const verifyActionTokenSchema = z.object({
  token: z.string().min(1).max(500),
});

export const oneTimeShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  wrappedSymmetricKey: rsaWrappedKey,
  maxViews: z.number().int().min(1).max(100).default(1),
  expiresInHours: z.number().int().min(1).max(720).default(24),
});

export const createTempVaultSchema = z.object({
  name: z.string().max(200).optional(),
  encryptedData: z.string().max(500_000).optional(),
  dataIv: z.string().max(1000).optional(),
  expiresInHours: z.number().int().min(1).max(8760).default(24),
});

export const updateTempVaultSchema = z.object({
  name: z.string().max(200).optional(),
  encryptedData: z.string().max(500_000).optional(),
  dataIv: z.string().max(1000).optional(),
  expiresInHours: z.number().int().min(1).max(8760).optional(),
});

export const createVersionSchema = z.object({
  encryptedData: z.string().min(1),
  dataIv: z.string().min(1),
  encryptedTitle: z.string().optional(),
  titleIv: z.string().optional(),
  encryptedDiff: z.string().optional(),
  diffIv: z.string().optional(),
  changelog: z.string().max(500).optional(),
});

export const createCommentSchema = z.object({
  content: z.string().min(1).max(100_000),
  contentIv: z.string().max(1000).optional(),
  mentions: z.array(z.string()).max(50).optional(),
  parentId: z.string().max(100).optional(),
});

export const updateCommentSchema = z.object({
  content: z.string().min(1).max(100_000).optional(),
  contentIv: z.string().max(1000).optional(),
  mentions: z.array(z.string()).max(50).optional(),
});

export const notificationUpdateSchema = z.object({
  read: z.boolean(),
});

export const notificationQuerySchema = z.object({
  read: z.string().optional(),
  limit: z.string().optional(),
});

export const activityQuerySchema = z.object({
  action: z.string().optional(),
  resourceType: z.string().optional(),
  limit: z.string().optional(),
  offset: z.string().optional(),
});

export const shareApprovalRequestSchema = z.object({
  secretId: z.string().min(1).max(100),
  approverId: z.string().min(1).max(100),
  recipientId: z.string().max(100).optional(),
  reason: z.string().max(2000).optional(),
});

export const shareApprovalDecisionSchema = z.object({
  decision: z.enum(["approved", "rejected"]),
  wrappedSymmetricKey: rsaWrappedKey.optional(),
  comment: z.string().max(2000).optional(),
});

export const tagSchema = z.object({
  name: z.string().min(1).max(50),
  color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, "must be hex color")
    .optional(),
  favorite: z.boolean().optional(),
});

export const secretTagSchema = z.object({
  tagId: z.string().min(1).max(100),
});

export const tagSearchSchema = z.object({
  q: z.string().optional(),
  limit: z.string().optional(),
});

export const importPasswordsSchema = z.object({
  source: z.enum([
    "bitwarden",
    "1password",
    "dashlane",
    "lastpass",
    "manual",
    "proton-pass",
    "keeper",
  ]),
  items: z
    .array(
      z.object({
        encryptedTitle: z.string().min(1),
        titleIv: z.string().min(1),
        encryptedData: z.string().min(1),
        dataIv: z.string().min(1),
        secretType: z.enum(SECRET_TYPES).default("password"),
        encryptedMetadata: z.string().optional(),
        metadataIv: z.string().optional(),
      })
    )
    .min(1)
    .max(1000),
});

export const emailShareSchema = z.object({
  secretId: z.string().min(1).max(100),
  recipientEmail: email,
  message: z.string().max(2000).optional(),
  expiresInHours: z.number().int().min(1).max(720).default(48),
});

export const accessRequestSchema = z.object({
  secretId: z.string().min(1).max(100),
  reason: z.string().max(2000).optional(),
});

export const accessRequestDecisionSchema = z.object({
  decision: z.enum(["approved", "denied"]),
  wrappedSymmetricKey: rsaWrappedKey.optional(),
  comment: z.string().max(2000).optional(),
});

export const shareAuditEventSchema = z.object({
  secretId: z.string().min(1).max(100),
  action: z.enum(["share", "revoke", "view", "claim", "approve", "deny", "request", "email-share"]),
  targetId: z.string().max(200).optional(),
  metadata: z.string().max(5000).optional(),
});
