import { describe, it, expect, beforeAll } from "vitest";
import { createApiKey, validateApiKey, revokeApiKey, listApiKeys, checkScope } from "../api-key-auth";
import { db } from "../db";

describe("ApiKey", () => {
  let userId: string;

  beforeAll(async () => {
    const user = await db.user.create({
      data: {
        email: `api-key-test-${Date.now()}@test.com`,
        name: "API Key Test",
      },
    });
    userId = user.id;
  });

  it("crea una key y devuelve rawKey + record", async () => {
    const result = await createApiKey({
      userId,
      name: "test-key",
      scopes: ["read:secrets", "write:secrets"],
    });

    expect(result.rawKey).toMatch(/^zk_/);
    expect(result.record.keyPrefix).toBe(result.rawKey.slice(0, 8));
    expect(result.record.name).toBe("test-key");
    expect(result.record.scopes).toEqual(["read:secrets", "write:secrets"]);
    expect(result.record.revokedAt).toBeNull();
  });

  it("valida una key correcta contra la BD", async () => {
    const { rawKey, record } = await createApiKey({
      userId,
      name: "valid-test",
      scopes: ["read:secrets"],
    });

    const result = await validateApiKey(rawKey);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.record.id).toBe(record.id);
      expect(result.record.userId).toBe(userId);
    }
  });

  it("rechaza formato inválido", async () => {
    const result = await validateApiKey("not-a-valid-key");
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("invalid_format");
  });

  it("rechaza key inexistente", async () => {
    const result = await validateApiKey("zk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("not_found");
  });

  it("rechaza key revocada", async () => {
    const { rawKey, record } = await createApiKey({
      userId,
      name: "revoke-me",
      scopes: ["read:secrets"],
    });

    await revokeApiKey(record.id, userId);

    const result = await validateApiKey(rawKey);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("revoked");
  });

  it("listApiKeys devuelve solo las keys del usuario", async () => {
    const keys = await listApiKeys(userId);
    expect(keys.length).toBeGreaterThanOrEqual(3);
    for (const k of keys) {
      expect(k.userId).toBe(userId);
    }
  });

  it("checkScope verifica permisos correctamente", async () => {
    const { record } = await createApiKey({
      userId,
      name: "scope-test",
      scopes: ["read:secrets"],
    });

    expect(checkScope(record, "read:secrets")).toBe(true);
    expect(checkScope(record, "write:secrets")).toBe(false);
  });

  it("persiste correctamente (prueba de que no es Map en memoria)", async () => {
    const { rawKey, record } = await createApiKey({
      userId,
      name: "persist-test",
      scopes: ["read:secrets"],
    });

    const fromDb = await db.apiKey.findUnique({ where: { id: record.id } });
    expect(fromDb).not.toBeNull();
    expect(fromDb!.keyHash).not.toBe(rawKey);

    const validated = await validateApiKey(rawKey);
    expect(validated.valid).toBe(true);
  });
});
