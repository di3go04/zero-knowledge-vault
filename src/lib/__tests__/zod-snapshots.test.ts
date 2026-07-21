import { describe, it, expect } from "vitest";
import { registerSchema, loginSchema, createShareSchema } from "@/lib/validation-schemas";
// Generate valid base64 blobs that pass the validators
const validBase64Blob = (bytes: number) => Buffer.alloc(bytes, 0x41).toString("base64");
const validIv = Buffer.alloc(12, 0x42).toString("base64");
const validWrappedKey = Buffer.alloc(256, 0x43).toString("base64");
const validSalt = Buffer.alloc(16, 0x44).toString("base64");

describe("Zod schema snapshots", () => {
  it("registerSchema accepts valid input", () => {
    const r = registerSchema.safeParse({
      email: "test@example.com",
      kdfAlgorithm: "argon2id",
      kdfSalt: validSalt,
      kdfIterations: 600000,
      publicKeyJwk: { kty: "RSA", n: "abc", e: "AQAB" },
      publicKeyFingerprint: "a".repeat(64),
      popSignature: validBase64Blob(256),
      encryptedPrivateKeyJwk: validBase64Blob(100),
      privateKeyIv: validIv,
    });
    expect(r.success).toBe(true);
  });
  it("loginSchema accepts valid email", () => {
    const r = loginSchema.safeParse({ email: "test@example.com" });
    expect(r.success).toBe(true);
  });
  it("loginSchema rejects invalid email", () => {
    const r = loginSchema.safeParse({ email: "not-an-email" });
    expect(r.success).toBe(false);
  });
  it("loginSchema rejects empty email", () => {
    const r = loginSchema.safeParse({ email: "" });
    expect(r.success).toBe(false);
  });
  it("registerSchema rejects missing kdfSalt", () => {
    const r = registerSchema.safeParse({ email: "test@example.com", kdfAlgorithm: "argon2id", kdfIterations: 600000 });
    expect(r.success).toBe(false);
  });
  it("createShareSchema accepts valid share", () => {
    const r = createShareSchema.safeParse({
      secretId: "abc123",
      recipientId: "xyz789",
      wrappedSymmetricKey: validWrappedKey,
    });
    expect(r.success).toBe(true);
  });
  it("createShareSchema rejects empty secretId", () => {
    const r = createShareSchema.safeParse({ secretId: "", recipientId: "xyz", wrappedSymmetricKey: validWrappedKey });
    expect(r.success).toBe(false);
  });
});
