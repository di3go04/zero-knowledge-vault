/**
 * =====================================================================
 * crypto-client.ts — Primitivas criptográficas del lado del CLIENTE.
 * =====================================================================
 * Todo el cifrado ocurre en el navegador mediante Web Crypto API.
 * El servidor NUNCA recibe:
 *   - La contraseña maestra
 *   - La llave maestra derivada (PBKDF2)
 *   - La llave privada RSA en claro
 *   - La llave simétrica AES en claro
 *
 * Esquema criptográfico:
 *   - KDF:        PBKDF2-SHA256, 600.000 iteraciones, salt aleatorio
 *   - Simétrico:  AES-256-GCM (12-byte IV)
 *   - Asimétrico: RSA-OAEP 2048-bit, SHA-256 (hash), SHA-1 (label/MGF1)
 *                 — algoritmo soportado universalmente por Web Crypto
 *   - Wrapping:   RSA-OAEP wrap de la llave AES cruda
 * =====================================================================
 */

// ---------------------------------------------------------------------------
// Constantes criptográficas
// ---------------------------------------------------------------------------
export const KDF_ITERATIONS = 600_000; // OWASP 2023 recomendado para PBKDF2-SHA256
export const SALT_LENGTH = 16; // 128 bits
export const IV_LENGTH = 12; // 96 bits (recomendado GCM)
export const RSA_MODULUS = 2048;
export const AES_KEY_LENGTH = 256;

// ---------------------------------------------------------------------------
// Helpers de serialización (base64 <-> ArrayBuffer)
// ---------------------------------------------------------------------------
export function bufToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuf(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

// ---------------------------------------------------------------------------
// 1. KDF — Derivar llave maestra desde contraseña + salt
// ---------------------------------------------------------------------------
/**
 * Deriva una CryptoKey AES-256-GCM a partir de la contraseña del usuario
 * y un salt aleatorio. Esta llave se usa EXCLUSIVAMENTE para cifrar
 * la llave privada RSA del usuario antes de enviarla al servidor.
 *
 * Esta llave NUNCA sale del navegador.
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  iterations: number = KDF_ITERATIONS,
): Promise<CryptoKey> {
  // 1. Importar password como llave raw
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  // 2. Derivar llave AES-256-GCM no extraíble
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false, // no extraíble: jamás podrá ser exportada
    ["encrypt", "decrypt"],
  );
}

// ---------------------------------------------------------------------------
// 2. AES-256-GCM helpers (para cifrar blobs genéricos)
// ---------------------------------------------------------------------------
export async function aesEncrypt(
  key: CryptoKey,
  plaintext: string,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = randomBytes(IV_LENGTH);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { ciphertext: bufToBase64(ct), iv: bufToBase64(iv) };
}

export async function aesDecrypt(
  key: CryptoKey,
  ciphertextB64: string,
  ivB64: string,
): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuf(ivB64) as BufferSource },
    key,
    base64ToBuf(ciphertextB64) as BufferSource,
  );
  return new TextDecoder().decode(pt);
}

// ---------------------------------------------------------------------------
// 3. RSA-OAEP — Generación de par asimétrico para compartir secretos
// ---------------------------------------------------------------------------
export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true, // extraíble: necesitamos exportar la llave privada para cifrarla
    // Importante: declarar TODOS los usos que usaremos después al importar
    // para que el campo `key_ops` de la JWK exportada sea compatible.
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  );
}

export async function exportPublicKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}

export async function exportPrivateKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}

/**
 * Limpia campos opcionales de la JWK que pueden causar inconsistencias
 * con el parámetro `usages` de importKey. Específicamente `key_ops`,
 * que si está presente debe ser superconjunto de los usos solicitados.
 */
function sanitizeJwk(jwk: JsonWebKey): JsonWebKey {
  const { key_ops: _ignoredKeyOps, ext: _ignoredExt, ...rest } = jwk;
  return rest;
}

export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt", "wrapKey"],
  );
}

export async function importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false, // no extraíble: la llave privada en memoria no debe poder exportarse de nuevo
    ["decrypt", "unwrapKey"],
  );
}

// ---------------------------------------------------------------------------
// 4. Cifrar / descifrar la llave privada RSA con la llave maestra
// ---------------------------------------------------------------------------
export interface EncryptedPrivateKey {
  encryptedJwk: string; // base64
  iv: string; // base64
}

export async function encryptPrivateKey(
  masterKey: CryptoKey,
  privateKey: CryptoKey,
): Promise<EncryptedPrivateKey> {
  const jwk = await exportPrivateKeyJwk(privateKey);
  const jwkStr = JSON.stringify(jwk);
  const { ciphertext, iv } = await aesEncrypt(masterKey, jwkStr);
  return { encryptedJwk: ciphertext, iv };
}

export async function decryptPrivateKey(
  masterKey: CryptoKey,
  encryptedJwkB64: string,
  ivB64: string,
): Promise<CryptoKey> {
  const jwkStr = await aesDecrypt(masterKey, encryptedJwkB64, ivB64);
  const jwk = JSON.parse(jwkStr) as JsonWebKey;
  return importPrivateKeyJwk(jwk);
}

// ---------------------------------------------------------------------------
// 5. AES-256-GCM para cifrar el contenido de los secretos
// ---------------------------------------------------------------------------
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    true, // extraíble: necesitamos exportar el raw para wrap con RSA
    ["encrypt", "decrypt"],
  );
}

export async function exportAesKeyRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey("raw", key);
}

export async function importAesKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
  );
}

// ---------------------------------------------------------------------------
// 6. Key Wrapping — envolver la llave AES con la llave pública RSA
// ---------------------------------------------------------------------------
/**
 * Envuelve (cifra) la llave simétrica AES con la llave PÚBLICA del
 * destinatario. Solo quien posea la llave PRIVADA correspondiente
 * podrá desenvolverla.
 */
export async function wrapAesKeyWithRsaPublicKey(
  aesKey: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<string> {
  const rawAes = await exportAesKeyRaw(aesKey);
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAes,
  );
  return bufToBase64(wrapped);
}

/**
 * Desenvuelve (descifra) la llave simétrica AES usando la llave
 * PRIVADA del destinatario.
 */
export async function unwrapAesKeyWithRsaPrivateKey(
  wrappedKeyB64: string,
  recipientPrivateKey: CryptoKey,
): Promise<CryptoKey> {
  const rawAes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    recipientPrivateKey,
    base64ToBuf(wrappedKeyB64) as BufferSource,
  );
  return importAesKeyRaw(rawAes);
}

// ---------------------------------------------------------------------------
// 7. Orquestación de alto nivel — Registro
// ---------------------------------------------------------------------------
export interface RegistrationArtifacts {
  kdfSalt: string;
  kdfIterations: number;
  publicKeyJwk: JsonWebKey;
  encryptedPrivateKey: EncryptedPrivateKey;
  // En memoria (NO se envían al servidor):
  masterKey: CryptoKey;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export async function performRegistration(
  email: string,
  password: string,
): Promise<RegistrationArtifacts> {
  // 1. Salt aleatorio
  const salt = randomBytes(SALT_LENGTH);

  // 2. Derivar llave maestra (PBKDF2)
  const masterKey = await deriveMasterKey(password, salt);

  // 3. Generar par RSA-OAEP
  const rsaPair = await generateRsaKeyPair();

  // 4. Cifrar llave privada con llave maestra (AES-256-GCM)
  const encryptedPrivateKey = await encryptPrivateKey(masterKey, rsaPair.privateKey);

  // 5. Exportar llave pública (en claro, es pública)
  const publicKeyJwk = await exportPublicKeyJwk(rsaPair.publicKey);

  return {
    kdfSalt: bufToBase64(salt),
    kdfIterations: KDF_ITERATIONS,
    publicKeyJwk,
    encryptedPrivateKey,
    masterKey,
    privateKey: rsaPair.privateKey,
    publicKey: rsaPair.publicKey,
  };
}

// ---------------------------------------------------------------------------
// 8. Orquestación de alto nivel — Login
// ---------------------------------------------------------------------------
export interface LoginArtifacts {
  masterKey: CryptoKey;
  privateKey: CryptoKey;
}

export async function performLogin(
  password: string,
  kdfSaltB64: string,
  kdfIterations: number,
  encryptedPrivateKeyJwkB64: string,
  privateKeyIvB64: string,
): Promise<LoginArtifacts> {
  const salt = base64ToBuf(kdfSaltB64);
  const masterKey = await deriveMasterKey(password, salt, kdfIterations);
  const privateKey = await decryptPrivateKey(
    masterKey,
    encryptedPrivateKeyJwkB64,
    privateKeyIvB64,
  );
  return { masterKey, privateKey };
}

// ---------------------------------------------------------------------------
// 9. Orquestación de alto nivel — Crear secreto
// ---------------------------------------------------------------------------
export interface SecretArtifacts {
  encryptedTitle: string;
  titleIv: string;
  encryptedData: string;
  dataIv: string;
  aesKey: CryptoKey; // en memoria
  wrappedKeyForOwner: string; // AES key wrapped con la llave pública del owner
}

export async function encryptNewSecret(
  title: string,
  content: string,
  ownerPublicKey: CryptoKey,
): Promise<SecretArtifacts> {
  const aesKey = await generateAesKey();

  const { ciphertext: encryptedTitle, iv: titleIv } = await aesEncrypt(aesKey, title);
  const { ciphertext: encryptedData, iv: dataIv } = await aesEncrypt(aesKey, content);

  const wrappedKeyForOwner = await wrapAesKeyWithRsaPublicKey(aesKey, ownerPublicKey);

  return { encryptedTitle, titleIv, encryptedData, dataIv, aesKey, wrappedKeyForOwner };
}

// ---------------------------------------------------------------------------
// 10. Orquestación de alto nivel — Leer secreto
// ---------------------------------------------------------------------------
export async function decryptSecret(
  wrappedKeyB64: string,
  encryptedTitle: string,
  titleIv: string,
  encryptedData: string,
  dataIv: string,
  recipientPrivateKey: CryptoKey,
): Promise<{ title: string; content: string; aesKey: CryptoKey }> {
  const aesKey = await unwrapAesKeyWithRsaPrivateKey(wrappedKeyB64, recipientPrivateKey);
  const title = await aesDecrypt(aesKey, encryptedTitle, titleIv);
  const content = await aesDecrypt(aesKey, encryptedData, dataIv);
  return { title, content, aesKey };
}

// ---------------------------------------------------------------------------
// 11. Orquestación de alto nivel — Compartir secreto
// ---------------------------------------------------------------------------
/**
 * Toma la llave AES del secreto (envuelta con la publicKey del owner)
 * y la re-envuelve con la publicKey del destinatario.
 *
 * Implementación: operamos directamente con los BYTES RAW de la AES key
 * (sin pasar por importKey/exportKey) para evitar restricciones de
 * extraibilidad. Esto es seguro porque los raw bytes nunca salen del
 * navegador: se descifran con la privateKey del owner y se re-cifran
 * inmediatamente con la publicKey del destinatario, todo en memoria.
 */
export async function shareSecretWithRecipient(
  ownerWrappedKeyB64: string,
  ownerPrivateKey: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<string> {
  // 1. Owner desenvuelve SU wrappedKey -> obtiene AES key cruda (bytes)
  const rawAesBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    ownerPrivateKey,
    base64ToBuf(ownerWrappedKeyB64) as BufferSource,
  );

  // 2. Re-envuelve con la llave PÚBLICA del destinatario
  const rewrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesBytes,
  );

  return bufToBase64(rewrapped);
}
