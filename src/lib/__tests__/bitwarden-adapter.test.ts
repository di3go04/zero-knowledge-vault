/**
 * Tests for Bitwarden JSON export/import adapter.
 */
import { describe, it, expect } from "vitest";
import {
  exportToBitwardenJson,
  importFromBitwardenJson,
  parseBitwardenJson,
  zkVaultToBitwardenItem,
  bitwardenItemToZkVault,
  type BitwardenExport,
  type BitwardenItem,
  type ZkVaultSecretInput,
} from "@/lib/bitwarden-adapter";

describe("zkVaultToBitwardenItem", () => {
  it("converts a ZK Vault secret with JSON content to a Login item", () => {
    const secret: ZkVaultSecretInput = {
      title: "GitHub",
      content: JSON.stringify({ username: "octocat", password: "ghp_abc123", url: "https://github.com" }),
    };
    const item = zkVaultToBitwardenItem(secret);

    expect(item.name).toBe("GitHub");
    expect(item.type).toBe(1);
    expect(item.login?.username).toBe("octocat");
    expect(item.login?.password).toBe("ghp_abc123");
    expect(item.login?.uris?.[0]?.uri).toBe("https://github.com");
  });

  it("converts a plain-text secret (non-JSON) to a Login with password only", () => {
    const secret: ZkVaultSecretInput = {
      title: "My Password",
      content: "plain-password-123",
    };
    const item = zkVaultToBitwardenItem(secret);

    expect(item.name).toBe("My Password");
    expect(item.type).toBe(1);
    expect(item.login?.password).toBe("plain-password-123");
    expect(item.login?.username).toBeNull();
  });

  it("preserves notes from JSON content", () => {
    const secret: ZkVaultSecretInput = {
      title: "With Notes",
      content: JSON.stringify({ password: "secret", notes: "Important note here" }),
    };
    const item = zkVaultToBitwardenItem(secret);
    expect(item.notes).toBe("Important note here");
  });
});

describe("bitwardenItemToZkVault", () => {
  it("converts a Login item back to ZK Vault format", () => {
    const item: BitwardenItem = {
      id: "abc",
      name: "GitHub",
      notes: null,
      favorite: false,
      type: 1,
      login: { username: "octocat", password: "ghp_abc123", totp: null, uris: [{ uri: "https://github.com", match: null }] },
      secureNote: null,
      card: null,
      identity: null,
      fields: null,
      collectionIds: null,
      revisionDate: "2024-01-01T00:00:00.000Z",
    };
    const secret = bitwardenItemToZkVault(item);

    expect(secret.title).toBe("GitHub");
    const parsed = JSON.parse(secret.content);
    expect(parsed.username).toBe("octocat");
    expect(parsed.password).toBe("ghp_abc123");
    expect(parsed.url).toBe("https://github.com");
  });

  it("converts a SecureNote item to plain text content", () => {
    const item: BitwardenItem = {
      id: "xyz",
      name: "My Note",
      notes: "This is a secure note",
      favorite: false,
      type: 2,
      login: null,
      secureNote: { type: 0 },
      card: null,
      identity: null,
      fields: null,
      collectionIds: null,
      revisionDate: "2024-01-01T00:00:00.000Z",
    };
    const secret = bitwardenItemToZkVault(item);
    expect(secret.title).toBe("My Note");
    expect(secret.content).toBe("This is a secure note");
  });
});

describe("exportToBitwardenJson", () => {
  it("produces valid Bitwarden export structure", () => {
    const secrets: ZkVaultSecretInput[] = [
      { title: "Site A", content: JSON.stringify({ username: "a", password: "p1", url: "https://a.com" }) },
      { title: "Site B", content: "plain-password" },
    ];
    const exportData = exportToBitwardenJson(secrets);

    expect(exportData.encrypted).toBe(false);
    expect(exportData.folders).toEqual([]);
    expect(exportData.items).toHaveLength(2);
    expect(exportData.items[0].name).toBe("Site A");
    expect(exportData.items[1].name).toBe("Site B");
  });
});

describe("importFromBitwardenJson", () => {
  it("round-trips: export → import produces equivalent secrets", () => {
    const original: ZkVaultSecretInput[] = [
      { title: "GitHub", content: JSON.stringify({ username: "octocat", password: "ghp_abc", url: "https://github.com" }) },
      { title: "Plain", content: "plain-password" },
    ];

    const exported = exportToBitwardenJson(original);
    const imported = importFromBitwardenJson(exported);

    expect(imported).toHaveLength(2);
    expect(imported[0].title).toBe("GitHub");
    expect(imported[1].title).toBe("Plain");

    // Verify round-trip fidelity for JSON-structured secrets
    const parsed0 = JSON.parse(imported[0].content);
    expect(parsed0.username).toBe("octocat");
    expect(parsed0.password).toBe("ghp_abc");

    // Plain-text secrets: password is preserved
    const parsed1 = JSON.parse(imported[1].content);
    expect(parsed1.password).toBe("plain-password");
  });
});

describe("parseBitwardenJson", () => {
  it("parses a valid Bitwarden JSON string", () => {
    const json = JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{ id: "1", name: "Test", type: 1, login: { username: "u", password: "p", totp: null, uris: null } }],
    });
    const parsed = parseBitwardenJson(json);
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0].name).toBe("Test");
  });

  it("rejects invalid JSON", () => {
    expect(() => parseBitwardenJson("not json")).toThrow("Invalid JSON");
  });

  it("rejects JSON without items array", () => {
    expect(() => parseBitwardenJson(JSON.stringify({ encrypted: false }))).toThrow("items");
  });

  it("rejects items missing name field", () => {
    const json = JSON.stringify({ items: [{ type: 1 }] });
    expect(() => parseBitwardenJson(json)).toThrow("name");
  });

  it("adds empty folders array if missing", () => {
    const json = JSON.stringify({ items: [{ id: "1", name: "Test", type: 1 }] });
    const parsed = parseBitwardenJson(json);
    expect(parsed.folders).toEqual([]);
  });
});
