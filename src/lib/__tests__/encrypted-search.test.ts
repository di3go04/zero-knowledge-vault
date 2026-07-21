/**
 * Tests for encrypted client-side search.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { decryptAndSearch, SearchIndex, type EncryptedSecretMeta } from "@/lib/encrypted-search";
import { deriveMasterKey, aesEncrypt, pbkdf2LegacyParams, randomBytes } from "@/lib/crypto";

let masterKey: CryptoKey;
let secrets: EncryptedSecretMeta[];

beforeAll(async () => {
  const params = pbkdf2LegacyParams(randomBytes(16), 1000);
  masterKey = await deriveMasterKey("test-search-password", params);

  const titles = ["GitHub Personal Access Token", "AWS Production Keys", "PostgreSQL Connection", "GitLab CI Token", "Slack Webhook URL"];
  secrets = [];
  for (const title of titles) {
    const enc = await aesEncrypt(masterKey, title);
    secrets.push({
      id: crypto.randomUUID(),
      encryptedTitle: enc.ciphertext,
      titleIv: enc.iv,
      ownerId: "user-1",
      createdAt: new Date().toISOString(),
    });
  }
});

describe("decryptAndSearch", () => {
  it("returns all secrets when query is empty", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "");
    expect(results).toHaveLength(5);
  });

  it("finds exact match with score 0", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "AWS Production Keys");
    expect(results).toHaveLength(1);
    expect(results[0].score).toBe(0);
    expect(results[0].title).toBe("AWS Production Keys");
  });

  it("finds startsWith match with score 1", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "Git");
    expect(results).toHaveLength(2); // GitHub + GitLab
    expect(results[0].score).toBeLessThanOrEqual(1);
  });

  it("finds includes match with score 2", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "Token");
    expect(results.length).toBeGreaterThanOrEqual(2); // GitHub Token + GitLab Token
    for (const r of results) expect(r.score).toBeLessThanOrEqual(2);
  });

  it("is case-insensitive", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "aws production keys");
    expect(results).toHaveLength(1);
    expect(results[0].title).toBe("AWS Production Keys");
  });

  it("returns empty for non-matching query", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "nonexistent-xyz-123");
    expect(results).toHaveLength(0);
  });

  it("sorts results by relevance (exact < startsWith < includes)", async () => {
    const results = await decryptAndSearch(secrets, masterKey, "Git");
    expect(results.length).toBeGreaterThanOrEqual(2);
    // GitHub starts with "Git", GitLab also starts with "Git"
    for (let i = 1; i < results.length; i++) {
      expect(results[i].score).toBeGreaterThanOrEqual(results[i - 1].score);
    }
  });
});

describe("SearchIndex", () => {
  it("builds index and searches instantly", async () => {
    const index = new SearchIndex();
    await index.build(secrets, masterKey);
    expect(index.size).toBe(5);

    const results = index.search("AWS");
    expect(results).toHaveLength(1);
    expect(results[0].title).toBe("AWS Production Keys");
  });

  it("supports fuzzy matching", async () => {
    const index = new SearchIndex();
    await index.build(secrets, masterKey);
    // "ghb" matches "GitHub" via fuzzy
    const results = index.search("ghb");
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it("clear() empties the index", async () => {
    const index = new SearchIndex();
    await index.build(secrets, masterKey);
    expect(index.size).toBe(5);
    index.clear();
    expect(index.size).toBe(0);
    expect(index.search("AWS")).toHaveLength(0);
  });
});
