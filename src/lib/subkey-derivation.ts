/**
 * =====================================================================
 * subkey-derivation.ts — Derivación de sub-llaves con HKDF.
 * =====================================================================
 *
 * masterKey usando HKDF-SHA256. Cada sub-llave tiene un propósito
 * distinto y están criptográficamente aisladas.
 *
 *   masterKey → auditKey      (para logs)
 *   masterKey → deviceKey     (para multi-device)
 *   masterKey → shareKey      (para wrapping de shares)
 *   masterKey → metadataKey   (para cifrar metadatos)
 *
 * Si una sub-llave se compromete, las demás siguen seguras.
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
 * Deriva una sub-llave AES-256-GCM desde la masterKey usando HKDF.
 *
 * Web Crypto no permite HKDF directamente sobre AES-GCM keys (no-extraíbles),
 * así que usamos el mismo truco que deriveAuditKey: cifrar un nonce fijo
 * con la masterKey y derivar la sub-llave del ciphertext.
 *
 * Cada sub-llave tiene un nonce distinto (basado en el info string),
 * garantizando que sub-llaves distintas son independientes.
 */
export async function deriveSubKey(
  masterKey: CryptoKey,
  type: SubKeyType,
): Promise<CryptoKey> {
  const info = SUBKEY_INFO_STRINGS[type];

  // Cifrar un nonce fijo derivado del info string
  const nonceBytes = new TextEncoder().encode(`subkey:${info}`);
  const iv = new Uint8Array(12); // IV fijo de ceros — OK porque el plaintext es único por tipo
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    masterKey,
    nonceBytes,
  );

  // Usar el ciphertext como semilla para PBKDF2 → sub-llave
  const seedKey = await crypto.subtle.importKey(
    "raw",
    ciphertext,
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(`salt:${info}`),
      iterations: 100_000,
      hash: "SHA-256",
    },
    seedKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Deriva todas las sub-llaves de una vez.
 */
export async function deriveAllSubKeys(masterKey: CryptoKey): Promise<
  Record<SubKeyType, CryptoKey>
> {
  const [audit, device, share, metadata] = await Promise.all([
    deriveSubKey(masterKey, "audit"),
    deriveSubKey(masterKey, "device"),
    deriveSubKey(masterKey, "share"),
    deriveSubKey(masterKey, "metadata"),
  ]);

  return { audit, device, share, metadata };
}
