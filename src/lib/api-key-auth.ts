import crypto from "node:crypto";
import { db } from "./db";

export const VALID_SCOPES = [
  "read:secrets",
  "write:secrets",
  "delete:secrets",
  "read:shares",
  "write:shares",
  "admin:keys",
] as const;

export type ApiKeyScope = (typeof VALID_SCOPES)[number];

export interface ApiKeyRecord {
  id: string;
  userId: string;
  keyPrefix: string;
  name: string;
  scopes: ApiKeyScope[];
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
}

export interface CreatedApiKey {
  rawKey: string;
  record: ApiKeyRecord;
}

function generateRawKey(): string {
  return `zk_${crypto.randomBytes(32).toString("base64url")}`;
}

function hashKey(rawKey: string): string {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

function parseScopes(raw: string): ApiKeyScope[] {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter((s): s is ApiKeyScope => VALID_SCOPES.includes(s));
    return [];
  } catch {
    return [];
  }
}

export async function createApiKey(params: {
  userId: string;
  name: string;
  scopes: ApiKeyScope[];
  expiresAt?: Date;
}): Promise<CreatedApiKey> {
  const rawKey = generateRawKey();
  const keyHash = hashKey(rawKey);
  const keyPrefix = rawKey.slice(0, 8);

  const record = await db.apiKey.create({
    data: {
      userId: params.userId,
      keyPrefix,
      keyHash,
      name: params.name,
      scopes: JSON.stringify(params.scopes),
      expiresAt: params.expiresAt ?? null,
    },
  });

  return {
    rawKey,
    record: {
      id: record.id,
      userId: record.userId,
      keyPrefix: record.keyPrefix,
      name: record.name,
      scopes: parseScopes(record.scopes),
      expiresAt: record.expiresAt,
      lastUsedAt: record.lastUsedAt,
      createdAt: record.createdAt,
      revokedAt: record.revokedAt,
    },
  };
}

export async function validateApiKey(rawKey: string): Promise<{ valid: false; reason: string } | { valid: true; record: ApiKeyRecord }> {
  const match = rawKey.match(/^zk_(.+)$/);
  if (!match) return { valid: false, reason: "invalid_format" };

  const keyHash = hashKey(rawKey);

  const record = await db.apiKey.findUnique({
    where: { keyHash },
  });

  if (!record) return { valid: false, reason: "not_found" };
  if (record.revokedAt) return { valid: false, reason: "revoked" };
  if (record.expiresAt && record.expiresAt < new Date()) return { valid: false, reason: "expired" };

  await db.apiKey.update({
    where: { id: record.id },
    data: { lastUsedAt: new Date() },
  });

  return {
    valid: true,
    record: {
      id: record.id,
      userId: record.userId,
      keyPrefix: record.keyPrefix,
      name: record.name,
      scopes: parseScopes(record.scopes),
      expiresAt: record.expiresAt,
      lastUsedAt: record.lastUsedAt,
      createdAt: record.createdAt,
      revokedAt: record.revokedAt,
    },
  };
}

export async function revokeApiKey(apiKeyId: string, userId: string): Promise<boolean> {
  const result = await db.apiKey.updateMany({
    where: { id: apiKeyId, userId },
    data: { revokedAt: new Date() },
  });
  return result.count > 0;
}

export async function listApiKeys(userId: string): Promise<ApiKeyRecord[]> {
  const records = await db.apiKey.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });

  return records.map((r) => ({
    id: r.id,
    userId: r.userId,
    keyPrefix: r.keyPrefix,
    name: r.name,
    scopes: parseScopes(r.scopes),
    expiresAt: r.expiresAt,
    lastUsedAt: r.lastUsedAt,
    createdAt: r.createdAt,
    revokedAt: r.revokedAt,
  }));
}

export function checkScope(record: ApiKeyRecord, requiredScope: ApiKeyScope): boolean {
  return record.scopes.includes(requiredScope);
}
