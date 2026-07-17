/**
 * =====================================================================
 * hkdf.ts — HKDF-SHA256 subkey derivation
 * =====================================================================
 *
 * Derives cryptographically isolated subkeys from the master key using
 * HKDF-SHA256 (RFC 5869) via Web Crypto API.
 *
 * Subkey purposes:
 *   masterKey → auditKey      (for encrypted audit logs)
 *   masterKey → deviceKey     (for multi-device enrollment)
 *   masterKey → shareKey      (for wrapping share keys)
 *   masterKey → metadataKey   (for encrypting secret metadata)
 *
 * Cryptographic isolation: if any single subkey is compromised, the
 * others remain secure because HKDF is a one-way function.
 *
 * Implementation note: Web Crypto's HKDF requires the input key to be
 * extractable=false but with `deriveBits` usage. The masterKey is
 * imported with `extractable: false` and `deriveKey`/`deriveBits`
 * usages, so HKDF works directly — no AES-GCM nonce trick needed.
 * =====================================================================
 */

const SUBKEY_INFO_STRINGS = {
  audit: "zk-vault-audit-key-v1",
  device: "zk-vault-device-key-v1",
  share: "zk-vault-share-key-v1",
  metadata: "zk-vault-metadata-key-v1",
} as const;

export type SubKeyType = keyof typeof SUBKEY_INFO_STRINGS;

/**
 * Salt for HKDF. RFC 5869 says the salt is optional but recommended.
 * We use a fixed, domain-separated salt to ensure subkeys derived in
 * zk-vault are distinct from subkeys any other HKDF-using app might
 * derive from the same master key.
 */
const HKDF_SALT = new TextEncoder().encode("zk-vault-hkdf-salt-v1");

/**
 * Derive a 256-bit AES-GCM subkey from the master key using HKDF-SHA256.
 *
 * @param masterKey - The master CryptoKey (must have `deriveKey` usage).
 * @param type      - Which subkey to derive (audit, device, share, metadata).
 * @returns A non-extractable AES-GCM CryptoKey.
 */
export async function deriveSubKey(
  masterKey: CryptoKey,
  type: SubKeyType,
): Promise<CryptoKey> {
  const info = new TextEncoder().encode(SUBKEY_INFO_STRINGS[type]);

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: HKDF_SALT as BufferSource,
      info: info as BufferSource,
    },
    masterKey,
    { name: "AES-GCM", length: 256 },
    false, // extractable: false — subkeys never leave the client
    ["encrypt", "decrypt"],
  );
}

/**
 * Derive raw bytes (not a CryptoKey) from the master key using HKDF-SHA256.
 *
 * Useful when you need bytes for a non-AES purpose (e.g. a derived salt
 * or a derived HMAC key).
 *
 * @param masterKey - The master CryptoKey (must have `deriveBits` usage).
 * @param info      - Domain-separation string.
 * @param length    - Number of bytes to derive (e.g. 32 for 256 bits).
 */
export async function deriveRawBytes(
  masterKey: CryptoKey,
  info: string,
  length: number,
): Promise<ArrayBuffer> {
  const infoBytes = new TextEncoder().encode(info);

  return crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: HKDF_SALT as BufferSource,
      info: infoBytes as BufferSource,
    },
    masterKey,
    length * 8, // bits
  );
}

/**
 * Derive all four subkeys at once. Convenient at login time when you
 * know you'll need all of them.
 *
 * @returns A record with audit, device, share, and metadata subkeys.
 */
export async function deriveAllSubKeys(
  masterKey: CryptoKey,
): Promise<Record<SubKeyType, CryptoKey>> {
  const [audit, device, share, metadata] = await Promise.all([
    deriveSubKey(masterKey, "audit"),
    deriveSubKey(masterKey, "device"),
    deriveSubKey(masterKey, "share"),
    deriveSubKey(masterKey, "metadata"),
  ]);

  return { audit, device, share, metadata };
}
