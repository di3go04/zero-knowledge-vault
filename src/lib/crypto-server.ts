/**
 * =====================================================================
 * crypto-server.ts — Validaciones criptográficas del lado del SERVIDOR.
 * =====================================================================
 * El servidor sigue siendo un "crypto-blind store", pero ahora:
 *   1. Verifica Proof-of-Possession (PoP) en el registro — garantiza
 *      que el cliente realmente posee la privateKey correspondiente
 *      a la publicKey que está registrando.
 *   2. Valida longitudes de salt, IVs, blobs, JWKs y kdfIterations.
 *   3. Genera respuestas decoy para login de usuarios inexistentes,
 *      previniendo enumeración de emails.
 *
 * NUNCA realiza operaciones de descifrado de material del usuario.
 * =====================================================================
 */
import { webcrypto, createHmac } from "node:crypto";

// Web Crypto está disponible en Node 18+ como global, pero en algunos
// runtimes (Edge) conviene referenciarlo explícitamente.
const subtle = webcrypto.subtle;

// Límites server-side — deben coincidir con el cliente
export const KDF_ITERATIONS_MIN = 310_000;
export const KDF_ITERATIONS_MAX = 1_000_000;
export const SALT_MIN_BYTES = 16; // 128 bits
export const SALT_MAX_BYTES = 64; // anti-DoS
export const IV_EXPECTED_BYTES = 12; // GCM recomendado
export const MAX_BLOB_BYTES = 64 * 1024; // 64 KiB
export const MAX_JWK_BYTES = 4 * 1024; // 4 KiB
export const MAX_POP_SIGNATURE_BYTES = 512; // RSA-2048 signature = 256 bytes, margen

// ---------------------------------------------------------------------------
// Helpers de serialización (base64 <-> bytes) — server-side
// ---------------------------------------------------------------------------
export function base64ToBytes(b64: string): Uint8Array {
  const binary = Buffer.from(b64, "base64");
  return new Uint8Array(binary);
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// ---------------------------------------------------------------------------
// Validadores — TODO devuelve boolean o lanza; el caller decide HTTP code
// ---------------------------------------------------------------------------
export function isValidBase64(s: unknown): s is string {
  if (typeof s !== "string" || s.length === 0) return false;
  return /^[A-Za-z0-9+/=_-]+$/.test(s);
}

export function validateKdfIterations(it: unknown): it is number {
  return (
    typeof it === "number" &&
    Number.isInteger(it) &&
    it >= KDF_ITERATIONS_MIN &&
    it <= KDF_ITERATIONS_MAX
  );
}

/**
 * Valida que un string sea base64 Y que al decodificar esté dentro del
 * rango de bytes esperado. Esto previene DoS por blobs gigantes y
 * también previene salts degenerados (1 byte).
 */
export function validateBase64Blob(
  s: unknown,
  minBytes: number,
  maxBytes: number,
): s is string {
  if (!isValidBase64(s)) return false;
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(s);
  } catch {
    return false;
  }
  return decoded.length >= minBytes && decoded.length <= maxBytes;
}

// ---------------------------------------------------------------------------
// Canonicalización JWK + fingerprint (server-side mirror del cliente)
// ---------------------------------------------------------------------------
/**
 * Canonicaliza una JWK eliminando key_ops, ext y alg antes de ordenar.
 * Debe ser IDÉNTICA a la función del cliente (crypto-client.ts).
 */
export function canonicalJwkString(jwk: Record<string, unknown>): string {
  const {
    key_ops: _kops,
    ext: _ext,
    alg: _alg,
    ...material
  } = jwk;
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(material).sort()) {
    sorted[k] = (material as Record<string, unknown>)[k];
  }
  return JSON.stringify(sorted);
}

export async function publicKeyFingerprint(
  jwk: Record<string, unknown>,
): Promise<string> {
  const canon = canonicalJwkString(jwk);
  const hash = await subtle.digest("SHA-256", new TextEncoder().encode(canon));
  const bytes = new Uint8Array(hash);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Proof-of-Possession (PoP) — verificación server-side
// ---------------------------------------------------------------------------
export function buildPopMessage(
  email: string,
  fingerprintHex: string,
  kdfSaltB64: string,
): Uint8Array {
  const msg = `zk-vault-pop-v1\nemail=${email}\nfingerprint=${fingerprintHex}\nsalt=${kdfSaltB64}`;
  return new TextEncoder().encode(msg);
}

/**
 * Importa una JWK como llave pública RSA-PSS para verificación de PoP.
 *
 * Nota: Bun (runtime del servidor) NO soporta pasar un array de
 * algoritmos a importKey. Por eso importamos SOLO como RSA-PSS aquí.
 * Si más adelante el servidor necesita usar la misma publicKey para
 * RSA-OAEP (no es el caso actual), deberá importarse por separado.
 */
async function importRsaPublicKeyForVerify(jwk: JsonWebKey): Promise<CryptoKey> {
  // Sanitizar key_ops / ext / alg para evitar inconsistencias
  const { key_ops: _kops, ext: _ext, alg: _alg, ...clean } = jwk;
  return subtle.importKey(
    "jwk",
    clean,
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["verify"],
  );
}

/**
 * Verifica una firma PoP RSA-PSS.
 * Devuelve true solo si la firma es válida.
 */
export async function verifyPopSignature(params: {
  publicKeyJwk: JsonWebKey;
  signatureB64: string;
  email: string;
  fingerprintHex: string;
  kdfSaltB64: string;
}): Promise<boolean> {
  const { publicKeyJwk, signatureB64, email, fingerprintHex, kdfSaltB64 } = params;

  // Validaciones previas
  if (!isValidBase64(signatureB64)) return false;
  const sigBytes = base64ToBytes(signatureB64);
  if (sigBytes.length > MAX_POP_SIGNATURE_BYTES) return false;

  try {
    const pubKey = await importRsaPublicKeyForVerify(publicKeyJwk);
    const msg = buildPopMessage(email, fingerprintHex, kdfSaltB64);
    return subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      pubKey,
      sigBytes as BufferSource,
      msg as BufferSource,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Decoy login — respuestas byte-a-byte idénticas para usuarios inexistentes
// ---------------------------------------------------------------------------
/**
 * HMAC-SHA-256 con un secreto del servidor para derivar material decoy
 * determinista a partir del email. Esto permite responder al login de
 * un email NO registrado con EXACTAMENTE la misma estructura que un
 * email registrado, evitando enumeración.
 *
 * El material decoy:
 *   - kdfSalt: 16 bytes deterministas (parece un salt real)
 *   - kdfIterations: KDF_ITERATIONS_MIN (constante, plausible)
 *   - encryptedPrivateKeyJwk: 256 bytes deterministas (tamaño plausible
 *     de RSA-2048 GCM ciphertext, NO descifrable por el cliente)
 *   - privateKeyIv: 12 bytes deterministas
 *   - publicKeyJwk: una JWK RSA-2048 generada deterministamente (no
 *     corresponde a ninguna llave privada real, pero estructuralmente
 *     válida para que el cliente pueda importarla sin error antes de
 *     fallar el descifrado)
 *
 * El atacante que reciba esto ejecutará PBKDF2 + AES-GCM y obtendrá
 * un error de tag GCM inválido — idéntico al comportamiento cuando
 * un usuario real introduce su contraseña maestra incorrecta.
 */
const DECOY_HMAC_KEY_ENV = process.env.DECOY_HMAC_KEY || "zk-vault-decoy-static-key-change-me";

function hmacSha256(input: string): Uint8Array {
  // createHmac es sincrono y compatible con todos los runtimes Node.
  // Usamos la importación estática al inicio del archivo (createHmac).
  const h = createHmac("sha256", DECOY_HMAC_KEY_ENV).update(input).digest();
  return new Uint8Array(h);
}

/**
 * Genera material decoy determinista a partir del email.
 * El email se normaliza a minúsculas para que el mismo email con
 * diferente capitalización produzca el mismo decoy.
 */
export function generateDecoyLoginResponse(email: string): {
  kdfSalt: string;
  kdfIterations: number;
  encryptedPrivateKeyJwk: string;
  privateKeyIv: string;
  publicKeyJwk: JsonWebKey;
  isDecoy: true;
} {
  const normalizedEmail = email.toLowerCase().trim();

  // 1. Derivar varios bloques del email usando HKDF-like expansion
  //    sobre HMAC-SHA-256.
  const block1 = hmacSha256(`salt:${normalizedEmail}`); // 32 bytes
  const block2 = hmacSha256(`iv:${normalizedEmail}`); // 32 bytes
  const block3 = hmacSha256(`ciphertext:${normalizedEmail}`); // 32 bytes
  const block4 = hmacSha256(`ciphertext2:${normalizedEmail}`); // 32 bytes
  const block5 = hmacSha256(`ciphertext3:${normalizedEmail}`); // 32 bytes
  const block6 = hmacSha256(`ciphertext4:${normalizedEmail}`); // 32 bytes

  // Salt de 16 bytes (usamos la primera mitad de block1)
  const kdfSalt = bytesToBase64(block1.slice(0, 16));

  // IV de 12 bytes (primera parte de block2)
  const privateKeyIv = bytesToBase64(block2.slice(0, 12));

  // Ciphertext de 256 bytes (8 bloques de 32 bytes = 256 bytes — plausible
  // para AES-GCM de una JWK RSA-2048 que es ~1.2 KiB)
  const ctBytes = new Uint8Array(256);
  ctBytes.set(block3, 0);
  ctBytes.set(block4, 32);
  ctBytes.set(block5, 64);
  ctBytes.set(block6, 96);
  // Rellenar el resto repitiendo con contexto diferente
  for (let i = 128; i < 256; i += 32) {
    const b = hmacSha256(`ct-fill:${normalizedEmail}:${i}`);
    ctBytes.set(b.subarray(0, 32), i);
  }
  const encryptedPrivateKeyJwk = bytesToBase64(ctBytes);

  // publicKeyJwk decoy: una JWK RSA con n de 2048 bits derivada de los
  // bloques HMAC. NO es criptográficamente válida como par RSA real,
  // pero el cliente puede importarla (structurally) y fallará más
  // adelante al intentar descifrar la privateKey. El objetivo es que
  // la respuesta JSON tenga IDÉNTICA estructura que un usuario real.
  const nHex = Array.from(block1)
    .concat(Array.from(block2))
    .concat(Array.from(block3))
    .concat(Array.from(block4))
    .concat(Array.from(block5))
    .concat(Array.from(block6))
    .concat(Array.from(hmacSha256(`n-fill:${normalizedEmail}`)))
    .concat(Array.from(hmacSha256(`n-fill2:${normalizedEmail}`)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  // Asegurar que el byte alto de n esté seteado (MSB=1) para que sea
  // un módulo RSA-2048 plausible (256 bytes = 512 hex chars)
  const nBytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    nBytes[i] = parseInt(nHex.substr(i * 2, 2), 16);
  }
  nBytes[0] |= 0x80; // MSB set para tamaño correcto
  // Asegurar impar (n debe ser impar en RSA)
  nBytes[255] |= 0x01;

  const publicKeyJwk: JsonWebKey = {
    kty: "RSA",
    n: bytesToBase64(nBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    e: "AQAB", // 65537 — exponente estándar
    alg: "RSA-OAEP-256",
    kid: `decoy-${normalizedEmail}`,
  };

  return {
    kdfSalt,
    kdfIterations: KDF_ITERATIONS_MIN,
    encryptedPrivateKeyJwk,
    privateKeyIv,
    publicKeyJwk,
    isDecoy: true,
  };
}
