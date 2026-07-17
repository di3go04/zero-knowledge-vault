import { describe, it, expect, beforeAll, vi } from "vitest";

// Mock next/server for auth-helper tests (must be hoisted before any imports)
vi.mock("next/server", () => {
  return {
    NextRequest: class MockNextRequest {
      readonly headers: Map<string, string>;
      constructor(input?: string | URL, init?: { headers?: Record<string, string> }) {
        this.headers = new Map(Object.entries(init?.headers ?? {}));
      }
    },
    NextResponse: {
      json: (body: unknown, init?: { status?: number }) => ({
        status: init?.status ?? 200,
        body,
        json: () => Promise.resolve(body),
      }),
    },
  };
});

// Set env before any module that imports @/lib/env
process.env.SESSION_SECRET = "test-secret-that-is-at-least-32-chars-long!!";
process.env.NODE_ENV = "test";

// ---------------------------------------------------------------------------
// Validation Schemas
// ---------------------------------------------------------------------------
describe("API Integration — Validation Schemas", () => {
  let schemas: typeof import("../validation-schemas");

  beforeAll(async () => {
    schemas = await import("../validation-schemas");
  });

  describe("registerSchema", () => {
    const validPayload = () => ({
      email: "user@example.com",
      name: "Test User",
      kdfAlgorithm: "argon2id" as const,
      kdfSalt: Buffer.from("a".repeat(32)).toString("base64"),
      kdfIterations: 600000,
      kdfMemoryKiB: 65536,
      kdfParallelism: 4,
      publicKeyJwk: { kty: "RSA" as const, n: "abc123", e: "AQAB" },
      publicKeyFingerprint: "a".repeat(64),
      popSignature: Buffer.from("sig").toString("base64"),
      encryptedPrivateKeyJwk: Buffer.alloc(28).toString("base64"),
      privateKeyIv: Buffer.alloc(12).toString("base64"),
    });

    it("accepts a valid payload", () => {
      const result = schemas.registerSchema.safeParse(validPayload());
      expect(result.success).toBe(true);
    });

    it("rejects payload with missing email", () => {
      const payload = validPayload();
      delete payload.email;
      const result = schemas.registerSchema.safeParse(payload);
      expect(result.success).toBe(false);
    });

    it("rejects invalid email format", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        email: "not-an-email",
      });
      expect(result.success).toBe(false);
    });

    it("rejects invalid kdf algorithm", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        kdfAlgorithm: "scrypt",
      });
      expect(result.success).toBe(false);
    });

    it("rejects kdf iterations out of range", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        kdfIterations: 0,
      });
      expect(result.success).toBe(false);
    });

    it("rejects missing publicKeyJwk fields", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        publicKeyJwk: { kty: "RSA" },
      });
      expect(result.success).toBe(false);
    });

    it("rejects invalid privateKeyIv length", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        privateKeyIv: Buffer.alloc(10).toString("base64"),
      });
      expect(result.success).toBe(false);
    });

    it("rejects invalid fingerprint format", () => {
      const result = schemas.registerSchema.safeParse({
        ...validPayload(),
        publicKeyFingerprint: "not-64-hex-chars",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("loginSchema", () => {
    it("accepts a valid email", () => {
      const result = schemas.loginSchema.safeParse({ email: "user@example.com" });
      expect(result.success).toBe(true);
    });

    it("rejects empty email", () => {
      const result = schemas.loginSchema.safeParse({ email: "ab" });
      expect(result.success).toBe(false);
    });

    it("rejects missing email", () => {
      const result = schemas.loginSchema.safeParse({});
      expect(result.success).toBe(false);
    });

    it("rejects email without domain", () => {
      const result = schemas.loginSchema.safeParse({ email: "user@" });
      expect(result.success).toBe(false);
    });
  });

  describe("createSecretSchema", () => {
    const validPayload = () => ({
      encryptedTitle: Buffer.alloc(28).toString("base64"),
      titleIv: Buffer.alloc(12).toString("base64"),
      encryptedData: Buffer.alloc(28).toString("base64"),
      dataIv: Buffer.alloc(12).toString("base64"),
      wrappedKeyForOwner: Buffer.alloc(256).toString("base64"),
      secretType: "password" as const,
    });

    it("accepts a valid payload", () => {
      const result = schemas.createSecretSchema.safeParse(validPayload());
      expect(result.success).toBe(true);
    });

    it("defaults secretType to password", () => {
      const payload = validPayload();
      delete payload.secretType;
      const result = schemas.createSecretSchema.safeParse(payload);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.secretType).toBe("password");
      }
    });

    it("rejects invalid IV length", () => {
      const result = schemas.createSecretSchema.safeParse({
        ...validPayload(),
        titleIv: Buffer.alloc(10).toString("base64"),
      });
      expect(result.success).toBe(false);
    });

    it("rejects encrypted blob that is too small", () => {
      const result = schemas.createSecretSchema.safeParse({
        ...validPayload(),
        encryptedTitle: Buffer.alloc(4).toString("base64"),
      });
      expect(result.success).toBe(false);
    });

    it("rejects invalid wrappedKey length", () => {
      const result = schemas.createSecretSchema.safeParse({
        ...validPayload(),
        wrappedKeyForOwner: Buffer.alloc(128).toString("base64"),
      });
      expect(result.success).toBe(false);
    });

    it("rejects non-base64 string", () => {
      const result = schemas.createSecretSchema.safeParse({
        ...validPayload(),
        encryptedTitle: "!!!not-base64!!!",
      });
      expect(result.success).toBe(false);
    });

    it("rejects empty string", () => {
      const result = schemas.createSecretSchema.safeParse({
        ...validPayload(),
        encryptedTitle: "",
      });
      expect(result.success).toBe(false);
    });

    it("accepts all valid secret types", () => {
      for (const st of schemas.SECRET_TYPES) {
        const result = schemas.createSecretSchema.safeParse({
          ...validPayload(),
          secretType: st,
        });
        expect(result.success).toBe(true);
      }
    });
  });

  describe("createShareSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.createShareSchema.safeParse({
        secretId: "secret-1",
        recipientId: "user-2",
        wrappedSymmetricKey: Buffer.alloc(256).toString("base64"),
      });
      expect(result.success).toBe(true);
    });

    it("rejects missing recipientId", () => {
      const result = schemas.createShareSchema.safeParse({
        secretId: "secret-1",
        wrappedSymmetricKey: Buffer.alloc(256).toString("base64"),
      });
      expect(result.success).toBe(false);
    });
  });

  describe("enrollInitSchema", () => {
    const validPayload = () => ({
      email: "user@example.com",
      deviceName: "My Laptop",
      publicKeyECDH: {
        kty: "EC" as const,
        crv: "P-256",
        x: "base64x",
        y: "base64y",
      },
      publicKeyECDHFingerprint: "a".repeat(64),
    });

    it("accepts a valid payload", () => {
      const result = schemas.enrollInitSchema.safeParse(validPayload());
      expect(result.success).toBe(true);
    });

    it("rejects missing deviceName", () => {
      const payload = validPayload();
      delete payload.deviceName;
      const result = schemas.enrollInitSchema.safeParse(payload);
      expect(result.success).toBe(false);
    });

    it("rejects invalid fingerprint", () => {
      const result = schemas.enrollInitSchema.safeParse({
        ...validPayload(),
        publicKeyECDHFingerprint: "short",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("enrollCompleteSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.enrollCompleteSchema.safeParse({
        enrollCode: "123456",
        wrappedPrivateKeyForDevice: Buffer.alloc(28).toString("base64"),
        wrappedPrivateKeyIv: Buffer.alloc(12).toString("base64"),
        enrollerPublicKeyECDH: {
          kty: "EC" as const,
          crv: "P-256",
          x: "base64x",
          y: "base64y",
        },
      });
      expect(result.success).toBe(true);
    });

    it("rejects invalid enroll code format", () => {
      const result = schemas.enrollCompleteSchema.safeParse({
        enrollCode: "abc",
        wrappedPrivateKeyForDevice: Buffer.alloc(28).toString("base64"),
        wrappedPrivateKeyIv: Buffer.alloc(12).toString("base64"),
        enrollerPublicKeyECDH: {
          kty: "EC" as const,
          crv: "P-256",
          x: "base64x",
          y: "base64y",
        },
      });
      expect(result.success).toBe(false);
    });
  });

  describe("enrollVerifySchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.enrollVerifySchema.safeParse({
        deviceId: "device-1",
        challenge: Buffer.alloc(32).toString("base64"),
        signature: Buffer.alloc(64).toString("base64"),
      });
      expect(result.success).toBe(true);
    });

    it("rejects invalid challenge length (needs 32 bytes)", () => {
      const result = schemas.enrollVerifySchema.safeParse({
        deviceId: "device-1",
        challenge: Buffer.alloc(16).toString("base64"),
        signature: Buffer.alloc(64).toString("base64"),
      });
      expect(result.success).toBe(false);
    });
  });

  describe("rotateSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.rotateSchema.safeParse({
        newKdfAlgorithm: "pbkdf2",
        newKdfSalt: Buffer.from("a".repeat(32)).toString("base64"),
        newKdfIterations: 600000,
        newEncryptedPrivateKeyJwk: Buffer.alloc(28).toString("base64"),
        newPrivateKeyIv: Buffer.alloc(12).toString("base64"),
        newPopSignature: Buffer.from("sig").toString("base64"),
      });
      expect(result.success).toBe(true);
    });
  });

  describe("recoverySetupSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.recoverySetupSchema.safeParse({
        recoverySalt: Buffer.from("a".repeat(32)).toString("base64"),
        recoveryIterations: 600000,
        encryptedPrivateKeyForRecovery: Buffer.alloc(28).toString("base64"),
        recoveryIv: Buffer.alloc(12).toString("base64"),
      });
      expect(result.success).toBe(true);
    });
  });

  describe("recoveryCompleteSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.recoveryCompleteSchema.safeParse({
        email: "user@example.com",
        action: "complete",
        newKdfAlgorithm: "argon2id",
        newKdfSalt: Buffer.from("a".repeat(32)).toString("base64"),
        newKdfIterations: 600000,
        newEncryptedPrivateKeyJwk: Buffer.alloc(28).toString("base64"),
        newPrivateKeyIv: Buffer.alloc(12).toString("base64"),
        newPopSignature: Buffer.from("sig").toString("base64"),
      });
      expect(result.success).toBe(true);
    });

    it("rejects missing action", () => {
      const result = schemas.recoveryCompleteSchema.safeParse({
        email: "user@example.com",
        newKdfAlgorithm: "argon2id",
        newKdfSalt: Buffer.from("a".repeat(32)).toString("base64"),
        newKdfIterations: 600000,
        newEncryptedPrivateKeyJwk: Buffer.alloc(28).toString("base64"),
        newPrivateKeyIv: Buffer.alloc(12).toString("base64"),
        newPopSignature: Buffer.from("sig").toString("base64"),
      });
      expect(result.success).toBe(false);
    });
  });

  describe("createAuditLogSchema", () => {
    it("accepts a valid payload", () => {
      const result = schemas.createAuditLogSchema.safeParse({
        encryptedEvent: Buffer.alloc(28).toString("base64"),
        eventIv: Buffer.alloc(12).toString("base64"),
        eventCategory: "auth",
      });
      expect(result.success).toBe(true);
    });

    it("rejects invalid eventCategory", () => {
      const result = schemas.createAuditLogSchema.safeParse({
        encryptedEvent: Buffer.alloc(28).toString("base64"),
        eventIv: Buffer.alloc(12).toString("base64"),
        eventCategory: "invalid",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("validatePayload helper", () => {
    it("returns success with data for valid payload", () => {
      const result = schemas.validatePayload(schemas.loginSchema, { email: "test@example.com" });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.email).toBe("test@example.com");
      }
    });

    it("returns error string for invalid payload", () => {
      const result = schemas.validatePayload(schemas.loginSchema, { email: "invalid" });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(typeof result.error).toBe("string");
        expect(result.error.length).toBeGreaterThan(0);
      }
    });
  });

  describe("pagination helpers", () => {
    it("parsePagination returns defaults for empty params", () => {
      const params = new URLSearchParams();
      const result = schemas.parsePagination(params);
      expect(result.offset).toBe(0);
      expect(result.limit).toBe(50);
    });

    it("parsePagination respects custom values", () => {
      const params = new URLSearchParams({ offset: "10", limit: "25" });
      const result = schemas.parsePagination(params);
      expect(result.offset).toBe(10);
      expect(result.limit).toBe(25);
    });

    it("parsePagination clamps limit to 100", () => {
      const params = new URLSearchParams({ limit: "999" });
      const result = schemas.parsePagination(params);
      expect(result.limit).toBe(100);
    });
  });

  describe("enterprise schemas", () => {
    it("scimUserSchema accepts a valid payload", () => {
      const result = schemas.scimUserSchema.safeParse({
        userName: "jdoe",
        name: { givenName: "John", familyName: "Doe" },
        emails: [{ value: "john@example.com", primary: true }],
        active: true,
      });
      expect(result.success).toBe(true);
    });

    it("ssoProviderSchema accepts a valid payload", () => {
      const result = schemas.ssoProviderSchema.safeParse({
        providerType: "oidc",
        providerName: "Azure AD",
        issuerUrl: "https://login.microsoftonline.com/tenant/v2.0",
        clientId: "client-123",
      });
      expect(result.success).toBe(true);
    });

    it("webhookSchema accepts a valid payload", () => {
      const result = schemas.webhookSchema.safeParse({
        name: "My Webhook",
        url: "https://example.com/hook",
        events: ["secret.created", "secret.deleted"],
        enabled: true,
      });
      expect(result.success).toBe(true);
    });

    it("complianceReportSchema accepts a valid payload", () => {
      const result = schemas.complianceReportSchema.safeParse({
        reportType: "soc2",
        periodStart: "2025-01-01T00:00:00Z",
        periodEnd: "2025-12-31T23:59:59Z",
      });
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------
describe("API Integration — Rate Limiter", () => {
  let rateLimit: typeof import("../rate-limit");

  beforeAll(async () => {
    rateLimit = await import("../rate-limit");
  });

  it("allows first request under the limit", async () => {
    const key = `rl-allow-${Date.now()}`;
    const result = await rateLimit.checkRateLimit(key, 5, 60000);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(4);
    expect(result.retryAfterSeconds).toBe(0);
  });

  it("tracks remaining requests as they are consumed", async () => {
    const key = `rl-remaining-${Date.now()}`;
    const r1 = await rateLimit.checkRateLimit(key, 3, 60000);
    expect(r1.remaining).toBe(2);

    const r2 = await rateLimit.checkRateLimit(key, 3, 60000);
    expect(r2.remaining).toBe(1);
  });

  it("blocks requests exceeding the limit", async () => {
    const key = `rl-block-${Date.now()}`;
    for (let i = 0; i < 3; i++) {
      await rateLimit.checkRateLimit(key, 3, 60000);
    }
    const result = await rateLimit.checkRateLimit(key, 3, 60000);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it("returns retryAfterSeconds when blocked", async () => {
    const key = `rl-retry-${Date.now()}`;
    for (let i = 0; i < 5; i++) {
      await rateLimit.checkRateLimit(key, 5, 60000);
    }
    const result = await rateLimit.checkRateLimit(key, 5, 60000);
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("resets rate limit for a key", async () => {
    const key = `rl-reset-${Date.now()}`;
    await rateLimit.checkRateLimit(key, 3, 60000);
    await rateLimit.checkRateLimit(key, 3, 60000);
    await rateLimit.checkRateLimit(key, 3, 60000);
    const blocked = await rateLimit.checkRateLimit(key, 3, 60000);
    expect(blocked.allowed).toBe(false);

    await rateLimit.resetRateLimit(key);
    const afterReset = await rateLimit.checkRateLimit(key, 3, 60000);
    expect(afterReset.allowed).toBe(true);
  });

  it("exposes predefined rate limit policies", () => {
    expect(rateLimit.RATE_LIMIT_POLICIES.login).toEqual({
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000,
    });
    expect(rateLimit.RATE_LIMIT_POLICIES.enrollVerify.maxAttempts).toBe(5);
    expect(rateLimit.RATE_LIMIT_POLICIES.enrollInit.maxAttempts).toBe(3);
    expect(rateLimit.RATE_LIMIT_POLICIES.secretCreate.maxAttempts).toBe(30);
    expect(rateLimit.RATE_LIMIT_POLICIES.default.maxAttempts).toBe(5);
  });

  it("gets client IP from x-forwarded-for header", () => {
    const req = {
      headers: new Map([["x-forwarded-for", "192.168.1.1, 10.0.0.1"]]),
    } as unknown as Request;
    const ip = rateLimit.getClientIp(req);
    expect(ip).toBe("192.168.1.1");
  });

  it("gets client IP from x-real-ip header when x-forwarded-for missing", () => {
    const req = { headers: new Map([["x-real-ip", "10.0.0.5"]]) } as unknown as Request;
    const ip = rateLimit.getClientIp(req);
    expect(ip).toBe("10.0.0.5");
  });

  it("returns 'unknown' when no IP headers present", () => {
    const req = { headers: new Map() } as unknown as Request;
    const ip = rateLimit.getClientIp(req);
    expect(ip).toBe("unknown");
  });

  it("builds a standard 429 response with rate limit headers", () => {
    const response = rateLimit.rateLimitResponse(120, 0);
    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("120");
    expect(response.headers.get("X-RateLimit-Remaining")).toBe("0");
  });
});

// ---------------------------------------------------------------------------
// Session Token
// ---------------------------------------------------------------------------
describe("API Integration — Session Token", () => {
  let sessionToken: typeof import("../session-token");

  beforeAll(async () => {
    sessionToken = await import("../session-token");
  });

  describe("issueSessionToken", () => {
    it("creates a dot-separated token with two parts", () => {
      const token = sessionToken.issueSessionToken("user-123");
      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token).toContain(".");
      expect(token.split(".")).toHaveLength(2);
    });

    it("creates unique tokens for different users", () => {
      const t1 = sessionToken.issueSessionToken("user-a");
      const t2 = sessionToken.issueSessionToken("user-b");
      expect(t1).not.toBe(t2);
    });

    it("creates unique tokens for the same user (different jti)", () => {
      const t1 = sessionToken.issueSessionToken("user-1");
      const t2 = sessionToken.issueSessionToken("user-1");
      expect(t1).not.toBe(t2);
    });
  });

  describe("verifySessionToken", () => {
    it("verifies a valid token and returns payload with uid", () => {
      const token = sessionToken.issueSessionToken("user-123");
      const payload = sessionToken.verifySessionToken(token);
      expect(payload).not.toBeNull();
      expect(payload!.uid).toBe("user-123");
    });

    it("includes jti, iat, and exp in the payload", () => {
      const token = sessionToken.issueSessionToken("user-1");
      const payload = sessionToken.verifySessionToken(token);
      expect(payload).not.toBeNull();
      expect(payload!.jti).toBeDefined();
      expect(payload!.jti.length).toBeGreaterThan(0);
      expect(payload!.iat).toBeGreaterThan(0);
      expect(payload!.exp).toBeGreaterThan(payload!.iat);
    });

    it("sets expiration 8 hours from issuance", () => {
      const token = sessionToken.issueSessionToken("user-1");
      const payload = sessionToken.verifySessionToken(token);
      expect(payload).not.toBeNull();
      const diff = payload!.exp - payload!.iat;
      expect(diff).toBe(8 * 60 * 60); // 8 hours in seconds
    });

    it("rejects null token", () => {
      expect(sessionToken.verifySessionToken(null)).toBeNull();
    });

    it("rejects undefined token", () => {
      expect(sessionToken.verifySessionToken(undefined)).toBeNull();
    });

    it("rejects empty string token", () => {
      expect(sessionToken.verifySessionToken("")).toBeNull();
    });

    it("rejects token without two parts", () => {
      expect(sessionToken.verifySessionToken("singlepart")).toBeNull();
    });

    it("rejects token with three parts", () => {
      expect(sessionToken.verifySessionToken("a.b.c")).toBeNull();
    });

    it("rejects tampered signature", () => {
      const token = sessionToken.issueSessionToken("user-123");
      const [payloadB64] = token.split(".");
      const tampered = `${payloadB64}.invalidsignature`;
      expect(sessionToken.verifySessionToken(tampered)).toBeNull();
    });

    it("rejects token with modified payload", () => {
      const token = sessionToken.issueSessionToken("user-123");
      // Modify payload by base64 decoding, changing uid, re-encoding (but keeping old sig)
      const [payloadB64] = token.split(".");
      const decoded = JSON.parse(
        Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
      );
      decoded.uid = "attacker";
      const newPayloadB64 = Buffer.from(JSON.stringify(decoded))
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      const tampered = `${newPayloadB64}.${token.split(".")[1]}`;
      expect(sessionToken.verifySessionToken(tampered)).toBeNull();
    });

    it("rejects token with decoy- prefix in uid", () => {
      // Directly test the decoy check by creating a payload
      const token = sessionToken.issueSessionToken("decoy-fake-user");
      expect(sessionToken.verifySessionToken(token)).toBeNull();
    });
  });

  describe("revokeSessionToken", () => {
    it("revokes a valid token", async () => {
      const token = sessionToken.issueSessionToken("user-123");
      const revoked = await sessionToken.revokeSessionToken(token);
      expect(revoked).toBe(true);
    });

    it("returns false for null token", async () => {
      const revoked = await sessionToken.revokeSessionToken(null);
      expect(revoked).toBe(false);
    });

    it("returns false for invalid token", async () => {
      const revoked = await sessionToken.revokeSessionToken("invalid.token.structure");
      expect(revoked).toBe(false);
    });

    it("makes token unverifiable after revocation", async () => {
      const token = sessionToken.issueSessionToken("user-456");
      await sessionToken.revokeSessionToken(token);
      const result = await sessionToken.verifySessionTokenWithBlacklist(token);
      expect(result).toBeNull();
    });
  });

  describe("verifySessionTokenWithBlacklist", () => {
    it("passes a non-revoked token", async () => {
      const token = sessionToken.issueSessionToken("user-789");
      const result = await sessionToken.verifySessionTokenWithBlacklist(token);
      expect(result).not.toBeNull();
      expect(result!.uid).toBe("user-789");
    });

    it("blocks a revoked token", async () => {
      const token = sessionToken.issueSessionToken("user-revokeme");
      await sessionToken.revokeSessionToken(token);
      const result = await sessionToken.verifySessionTokenWithBlacklist(token);
      expect(result).toBeNull();
    });

    it("returns null for invalid token", async () => {
      const result = await sessionToken.verifySessionTokenWithBlacklist("bad-token");
      expect(result).toBeNull();
    });
  });

  describe("extractUserIdFromAuth", () => {
    it("extracts user ID from a valid Bearer token", async () => {
      const token = sessionToken.issueSessionToken("user-bearer");
      const userId = await sessionToken.extractUserIdFromAuth(`Bearer ${token}`);
      expect(userId).toBe("user-bearer");
    });

    it("returns null for null header", async () => {
      const userId = await sessionToken.extractUserIdFromAuth(null);
      expect(userId).toBeNull();
    });

    it("returns null for malformed auth header (no Bearer)", async () => {
      const userId = await sessionToken.extractUserIdFromAuth("Basic dGVzdDpwYXNz");
      expect(userId).toBeNull();
    });

    it("returns null for empty auth header", async () => {
      const userId = await sessionToken.extractUserIdFromAuth("");
      expect(userId).toBeNull();
    });

    it("returns null for Bearer without token", async () => {
      const userId = await sessionToken.extractUserIdFromAuth("Bearer ");
      expect(userId).toBeNull();
    });

    it("returns null for revoked token", async () => {
      const token = sessionToken.issueSessionToken("user-revoked");
      await sessionToken.revokeSessionToken(token);
      const userId = await sessionToken.extractUserIdFromAuth(`Bearer ${token}`);
      expect(userId).toBeNull();
    });
  });

  it("exports SESSION_TTL constant", () => {
    expect(sessionToken.SESSION_TTL).toBe(8 * 60 * 60);
  });
});

// ---------------------------------------------------------------------------
// Auth Helper
// ---------------------------------------------------------------------------
describe("API Integration — Auth Helper", () => {
  let authHelper: typeof import("../auth-helper");

  beforeAll(async () => {
    authHelper = await import("../auth-helper");
  });

  it("returns userId from x-authenticated-user-id header", async () => {
    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost", {
      headers: { "x-authenticated-user-id": "middleware-user" },
    });
    const result = await authHelper.requireAuth(req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.userId).toBe("middleware-user");
    }
  });

  it("falls back to Bearer token when middleware header is missing", async () => {
    const { NextRequest } = await import("next/server");
    const token = (await import("../session-token")).issueSessionToken("token-user");
    const req = new NextRequest("http://localhost", {
      headers: { authorization: `Bearer ${token}` },
    });
    const result = await authHelper.requireAuth(req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.userId).toBe("token-user");
    }
  });

  it("returns 401 when no auth is provided", async () => {
    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost", {});
    const result = await authHelper.requireAuth(req);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(401);
    }
  });

  it("prefers middleware header over Bearer token when both present", async () => {
    const { NextRequest } = await import("next/server");
    const token = (await import("../session-token")).issueSessionToken("token-user");
    const req = new NextRequest("http://localhost", {
      headers: {
        "x-authenticated-user-id": "middleware-user",
        authorization: `Bearer ${token}`,
      },
    });
    const result = await authHelper.requireAuth(req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.userId).toBe("middleware-user");
    }
  });

  it("returns 401 for invalid Bearer token", async () => {
    const { NextRequest } = await import("next/server");
    const req = new NextRequest("http://localhost", {
      headers: { authorization: "Bearer invalid-token-structure" },
    });
    const result = await authHelper.requireAuth(req);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(401);
    }
  });
});
