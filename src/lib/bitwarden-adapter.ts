/**
 * Bitwarden JSON export/import adapter.
 *
 * Bitwarden's "JSON export" format is documented at:
 * https://bitwarden.com/help/export-your-data/
 *
 * Structure:
 * {
 *   "encrypted": false,
 *   "folders": [],
 *   "items": [
 *     {
 *       "id": "...",
 *       "name": "My Login",
 *       "notes": "...",
 *       "favorite": false,
 *       "type": 1,            // 1=Login, 2=SecureNote, 3=Card, 4=Identity
 *       "secureNote": null,
 *       "login": {
 *         "username": "user@example.com",
 *         "password": "secret123",
 *         "totp": null,
 *         "uris": [{ "uri": "https://example.com", "match": null }]
 *       },
 *       "card": null,
 *       "identity": null,
 *       "fields": [],
 *       "attachments": null,
 *       "collectionIds": null,
 *       "revisionDate": "2024-01-01T00:00:00.000Z"
 *     }
 *   ]
 * }
 *
 * This module converts between Bitwarden JSON and ZK Vault's internal
 * Secret format, encrypting/decrypting with the user's masterKey.
 */
import { aesEncrypt, aesDecrypt, type KdfParams } from "@/lib/crypto";

export interface BitwardenExport {
  encrypted: boolean;
  folders: BitwardenFolder[];
  items: BitwardenItem[];
}

export interface BitwardenFolder {
  id: string;
  name: string;
}

export interface BitwardenItem {
  id: string;
  name: string;
  notes: string | null;
  favorite: boolean;
  type: 1 | 2 | 3 | 4; // Login, SecureNote, Card, Identity
  login: {
    username: string | null;
    password: string | null;
    totp: string | null;
    uris: Array<{ uri: string; match: number | null }> | null;
  } | null;
  secureNote: { type: number } | null;
  card: Record<string, string | null> | null;
  identity: Record<string, string | null> | null;
  fields: Array<{ name: string; value: string; type: number }> | null;
  collectionIds: string[] | null;
  revisionDate: string;
}

export interface ZkVaultSecretInput {
  title: string;
  content: string;
}

/**
 * Convert a ZK Vault secret to Bitwarden JSON item format.
 * ZK Vault stores all secrets as { title, content } where content
 * is a free-form string. We map this to Bitwarden's Login type (1)
 * with username/password parsed from the content if possible.
 */
export function zkVaultToBitwardenItem(secret: ZkVaultSecretInput): BitwardenItem {
  // Try to parse content as JSON with { username, password, url, notes }
  let parsed: { username?: string; password?: string; url?: string; notes?: string } = {};
  try {
    parsed = JSON.parse(secret.content);
  } catch {
    // If not JSON, treat content as the password and title as the name
    parsed = { password: secret.content };
  }

  return {
    id: crypto.randomUUID(),
    name: secret.title,
    notes: parsed.notes ?? null,
    favorite: false,
    type: 1, // Login
    login: {
      username: parsed.username ?? null,
      password: parsed.password ?? null,
      totp: null,
      uris: parsed.url ? [{ uri: parsed.url, match: null }] : null,
    },
    secureNote: null,
    card: null,
    identity: null,
    fields: null,
    collectionIds: null,
    revisionDate: new Date().toISOString(),
  };
}

/**
 * Convert a Bitwarden JSON item to ZK Vault secret format.
 */
export function bitwardenItemToZkVault(item: BitwardenItem): ZkVaultSecretInput {
  let content: string;

  if (item.type === 1 && item.login) {
    // Login: serialize as JSON with username, password, url
    content = JSON.stringify({
      username: item.login.username ?? "",
      password: item.login.password ?? "",
      url: item.login.uris?.[0]?.uri ?? "",
      notes: item.notes ?? "",
      totp: item.login.totp ?? "",
    });
  } else if (item.type === 2) {
    // SecureNote: content is the notes field
    content = item.notes ?? "";
  } else if (item.type === 3 && item.card) {
    // Card: serialize card fields
    content = JSON.stringify({
      type: "card",
      cardholderName: item.card.cardholderName ?? "",
      number: item.card.number ?? "",
      code: item.card.code ?? "",
      expMonth: item.card.expMonth ?? "",
      expYear: item.card.expYear ?? "",
      notes: item.notes ?? "",
    });
  } else if (item.type === 4 && item.identity) {
    // Identity: serialize identity fields
    content = JSON.stringify({
      type: "identity",
      ...item.identity,
      notes: item.notes ?? "",
    });
  } else {
    // Fallback: serialize the entire item
    content = JSON.stringify(item);
  }

  return {
    title: item.name,
    content,
  };
}

/**
 * Export ZK Vault secrets to Bitwarden-compatible JSON format.
 * The output can be imported directly into Bitwarden/Vaultwarden.
 *
 * @param secrets - Array of decrypted ZK Vault secrets
 * @returns BitwardenExport JSON object
 */
export function exportToBitwardenJson(secrets: ZkVaultSecretInput[]): BitwardenExport {
  return {
    encrypted: false,
    folders: [],
    items: secrets.map(zkVaultToBitwardenItem),
  };
}

/**
 * Import Bitwarden JSON export into ZK Vault format.
 *
 * @param bitwardenJson - Parsed Bitwarden export
 * @returns Array of ZK Vault secrets ready to encrypt and store
 */
export function importFromBitwardenJson(bitwardenJson: BitwardenExport): ZkVaultSecretInput[] {
  return bitwardenJson.items.map(bitwardenItemToZkVault);
}

/**
 * Parse a Bitwarden JSON file string and validate its structure.
 * Throws if the format is invalid.
 */
export function parseBitwardenJson(jsonString: string): BitwardenExport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    throw new Error("Invalid JSON: cannot parse file");
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Invalid Bitwarden export: root must be an object");
  }

  const obj = parsed as Record<string, unknown>;
  if (!Array.isArray(obj.items)) {
    throw new Error("Invalid Bitwarden export: 'items' must be an array");
  }

  // Validate each item has the required fields
  for (let i = 0; i < obj.items.length; i++) {
    const item = obj.items[i] as Record<string, unknown>;
    if (typeof item.name !== "string") {
      throw new Error(`Invalid Bitwarden export: item ${i} missing 'name' field`);
    }
    if (typeof item.type !== "number") {
      throw new Error(`Invalid Bitwarden export: item ${i} missing 'type' field`);
    }
  }

  // Ensure folders array exists
  if (!Array.isArray(obj.folders)) {
    obj.folders = [];
  }

  return obj as unknown as BitwardenExport;
}
