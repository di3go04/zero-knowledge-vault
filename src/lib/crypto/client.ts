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
// KDF — Argon2id (preferido) + PBKDF2 (legacy fallback)
//   Argon2id parámetros OWASP 2024:
//     m (memory) = 64 MiB = 65536 KiB
//     t (iterations) = 3
//     p (parallelism) = 4
//   PBKDF2 parámetros legacy (cuentas creadas antes de la migración):
//     iterations = 600.000, SHA-256
export type KdfAlgorithm = "argon2id" | "pbkdf2";

export const ARGON2_MEMORY_KIB = 65_536; // 64 MiB — desktop. Mobile may need 32_768 (32 MiB) for performance/memory trade-off
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 4;
export const ARGON2_SALT_LENGTH = 16; // 128 bits

export const KDF_ITERATIONS = 600_000; // PBKDF2 legacy
export const KDF_ITERATIONS_MIN = 310_000;
export const KDF_ITERATIONS_MAX = 1_000_000;

export const SALT_LENGTH = 16; // 128 bits
export const IV_LENGTH = 12; // 96 bits (recomendado GCM)
export const RSA_MODULUS = 2048;
export const AES_KEY_LENGTH = 256;
export const MAX_BLOB_BYTES = 64 * 1024;
export const MAX_JWK_BYTES = 4 * 1024;

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

/**
 * Normaliza una contraseña a Unicode NFC antes de cualquier derivación.
 * Evita que el mismo password en forma NFC vs NFD produzca llaves maestras
 * distintas, lo que bloquearía al usuario fuera de su bóveda sin razón
 * aparente. NFC es la forma preferida por W3C.
 */
export function normalizePassword(password: string): string {
  // NFKC normalizes full-width characters to ASCII equivalents and
  // trims whitespace, so "  Secret  " → "Secret" and "ＡＢＣ" → "ABC".
  return password.normalize("NFKC").trim();
}

/**
 * Canonicaliza una JWK para que su hash sea determinista independientemente
 * del orden de claves o de espacios en blanco. Devuelve un JSON con claves
 * ordenadas alfabéticamente y sin espacios.
 *
 * Se eliminan los campos `key_ops`, `ext` y `alg` antes de canonicalizar
 * porque son metadatos de uso, no parte de la key material. Dos JWKs
 * representando el mismo par RSA pero con distintos `alg` (RSA-OAEP-256
 * vs RSA-OAEP) deben producir la misma fingerprint.
 */
export function canonicalJwkString(jwk: JsonWebKey): string {
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

/**
 * Huella criptográfica de una llave pública (SHA-256 del JWK canonizado).
 * Se usa para:
 *  - TOFU: el cliente muestra esta huella al compartir, el owner la verifica
 *    fuera de banda con el destinatario.
 *  - Detección de sustitución: si la huella cambia entre dos lookups,
 *    el cliente alerta al usuario.
 *
 *
 * timing attacks en la verificación TOFU.
 */
export async function publicKeyFingerprint(jwk: JsonWebKey): Promise<string> {
  const canon = canonicalJwkString(jwk);
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon));
  const bytes = new Uint8Array(hash);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 *
 * Previene timing attacks en la verificación TOFU.
 *
 * Compara byte a byte XOR, acumulando diferencias. Devuelve true
 * solo si todos los bytes coinciden. El tiempo de ejecución no
 * depende del número de bytes que coinciden.
 */
export function constantTimeFingerprintCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// ---------------------------------------------------------------------------
// 1. KDF — Derivar llave maestra desde contraseña + salt
// ---------------------------------------------------------------------------
/**
 * Deriva una CryptoKey AES-256-GCM a partir de la contraseña del usuario.
 *
 * MEJORA Fase 2: soporta Argon2id (preferido, memory-hard) Y PBKDF2
 * (legacy, para cuentas creadas antes de la migración). El algoritmo
 * se selecciona con `algorithm` y los parámetros vienen en `params`.
 *
 * Argon2id se ejecuta en un Web Worker para no bloquear la UI mientras
 * consume 64 MiB de RAM durante ~1-2s.
 *
 * Esta llave NUNCA sale del navegador.
 */
export interface KdfParams {
  algorithm: KdfAlgorithm;
  salt: Uint8Array;
  // PBKDF2:
  iterations?: number;
  // Argon2id:
  memoryKiB?: number;
  argon2Iterations?: number;
  parallelism?: number;
}

let _argonWorker: Worker | null = null;
let _argonWorkerRequestId = 0;

function getArgonWorker(): Worker {
  if (_argonWorker) return _argonWorker;
  // Crear el Web Worker para Argon2id.
  // Next.js/Turbopack empaqueta el worker automáticamente con esta sintaxis.
  // Si el worker falla al cargar, la función argon2HashInWorker captura
  // el error y derivará a PBKDF2 como fallback.
  try {
    _argonWorker = new Worker(new URL("./argon2-worker.ts", import.meta.url));
    // Manejar errores no capturados del worker
    _argonWorker.onerror = (e) => {
      _argonWorker = null;
      _argonWorker = null; // Reset para permitir reintento
    };
    return _argonWorker;
  } catch (err) {
    throw new Error("Argon2id worker unavailable");
    throw new Error("Argon2id worker no disponible");
  }
}

function argon2HashInWorker(params: {
  password: string;
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const worker = getArgonWorker();
    const id = ++_argonWorkerRequestId;
    const handler = (e: MessageEvent) => {
      const resp = e.data;
      if (resp.id !== id) return; // no es nuestra respuesta
      worker.removeEventListener("message", handler);
      if (resp.ok && resp.rawKey) {
        resolve(resp.rawKey);
      } else {
        reject(new Error(resp.error ?? "Argon2id failed"));
      }
    };
    worker.addEventListener("message", handler);
    // Copiar el salt porque será transferido al worker
    const saltCopy = new Uint8Array(params.salt);
    worker.postMessage(
      {
        id,
        password: params.password,
        salt: saltCopy,
        memoryKiB: params.memoryKiB,
        iterations: params.iterations,
        parallelism: params.parallelism,
      },
      [saltCopy.buffer],
    );
  });
}

export async function deriveMasterKey(
  password: string,
  params: KdfParams,
): Promise<CryptoKey> {
  const rawBytes = await deriveMasterKeyRaw(password, params);
  return crypto.subtle.importKey(
    "raw",
    rawBytes,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Derive the raw master key bytes (32 bytes = 256 bits) from the user's
 * password + KDF params. Exposed so callers can also import the bytes
 * as an HKDF key for subkey derivation.
 */
export async function deriveMasterKeyRaw(
  password: string,
  params: KdfParams,
): Promise<ArrayBuffer> {
  const normalized = normalizePassword(password);

  if (params.algorithm === "argon2id") {
    // Argon2id via Web Worker. No silent fallback — see deriveMasterKey.
    return argon2HashInWorker({
      password: normalized,
      salt: params.salt,
      memoryKiB: params.memoryKiB ?? ARGON2_MEMORY_KIB,
      iterations: params.argon2Iterations ?? ARGON2_ITERATIONS,
      parallelism: params.parallelism ?? ARGON2_PARALLELISM,
    });
  }

  // PBKDF2 (legacy or explicit)
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalized),
    { name: "PBKDF2" },
    false,
    ["deriveKey", "deriveBits"],
  );
  return crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: params.salt as BufferSource,
      iterations: params.iterations ?? KDF_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    AES_KEY_LENGTH,
  );
}

// Convenience: construir KdfParams para Argon2id con valores por defecto
export function argon2DefaultParams(salt: Uint8Array): KdfParams {
  return {
    algorithm: "argon2id",
    salt,
    memoryKiB: ARGON2_MEMORY_KIB,
    argon2Iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
  };
}

// Convenience: construir KdfParams PBKDF2 legacy
export function pbkdf2LegacyParams(
  salt: Uint8Array,
  iterations: number,
): KdfParams {
  return {
    algorithm: "pbkdf2",
    salt,
    iterations,
  };
}

// ---------------------------------------------------------------------------
// 2. AES-256-GCM helpers (para cifrar blobs genéricos)
// ---------------------------------------------------------------------------
export async function aesEncrypt(
  key: CryptoKey,
  plaintext: string,
  additionalData?: string | Uint8Array,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = randomBytes(IV_LENGTH);
  const aad =
    additionalData instanceof Uint8Array
      ? additionalData
      : additionalData
        ? new TextEncoder().encode(additionalData)
        : undefined;
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      ...(aad ? { additionalData: aad as BufferSource } : {}),
    },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { ciphertext: bufToBase64(ct), iv: bufToBase64(iv) };
}

export async function aesDecrypt(
  key: CryptoKey,
  ciphertextB64: string,
  ivB64: string,
  additionalData?: string | Uint8Array,
): Promise<string> {
  const aad =
    additionalData instanceof Uint8Array
      ? additionalData
      : additionalData
        ? new TextEncoder().encode(additionalData)
        : undefined;
  const pt = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBuf(ivB64) as BufferSource,
      ...(aad ? { additionalData: aad as BufferSource } : {}),
    },
    key,
    base64ToBuf(ciphertextB64) as BufferSource,
  );
  return new TextDecoder().decode(pt);
}

// ---------------------------------------------------------------------------
// 3. RSA-OAEP + RSA-PSS — Par asimétrico dual-purpose
//    - RSA-OAEP: cifrado / wrapping de llaves AES
//    - RSA-PSS:  firma de prueba-de-posesión (PoP) en el registro
// ---------------------------------------------------------------------------
/**
 * Genera el par RSA-OAEP. Web Crypto NO permite combinar `sign`/`verify`
 * con `encrypt`/`decrypt` en una sola generateKey() para RSA-OAEP, así
 * que generamos solo los usos de cifrado aquí. La firma PoP se realiza
 * re-importando la JWK privada como RSA-PSS (ver signPop más abajo),
 * usando la misma key material.
 *
 * Esto es válido porque matemáticamente un par RSA es el mismo par de
 * enteros (n, e, d) independientemente del padding usado en una
 * operación concreta. La restricción de Web Crypto es solo de API.
 */
export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true, // extraíble: necesitamos exportar la llave privada para cifrarla
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
 * con el parámetro `usages` o el algoritmo de importKey.
 * Específicamente:
 *   - key_ops: debe ser superconjunto de los usos solicitados.
 *   - ext: debe coincidir con el flag extractable solicitado.
 *   - alg: si está presente, debe coincidir con el algoritmo de importKey.
 *     Como usamos la misma JWK para RSA-OAEP y RSA-PSS, eliminamos alg
 *     para evitar el mismatch.
 */
function sanitizeJwk(jwk: JsonWebKey): JsonWebKey {
  const {
    key_ops: _ignoredKeyOps,
    ext: _ignoredExt,
    alg: _ignoredAlg,
    ...rest
  } = jwk;
  return rest;
}

export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    // Solo RSA-OAEP para wrapping de llaves AES.
    // La verificación PoP se hace en el servidor (no aquí).
    // Si en el futuro el cliente necesita verificar PoP, se importará
    // por separado como RSA-PSS.
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt", "wrapKey"],
  );
}

export async function importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    // Solo RSA-OAEP para unwrap de llaves AES.
    // La firma PoP se hace re-importando la JWK como RSA-PSS en signPop.
    { name: "RSA-OAEP", hash: "SHA-256" },
    // Extractable: needed for password rotation (re-export to re-encrypt
    // with a new master key) and for signPop (re-import as RSA-PSS).
    // The JWK is never sent to the server — it stays in client memory.
    true,
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
// 4.b Proof-of-Possession (PoP) — firma RSA-PSS que demuestra que el
//     cliente realmente posee la privateKey correspondiente a la publicKey
//     que está registrando. El servidor verifica esta firma antes de
//     aceptar el registro, previniendo sustitución de publicKey.
// ---------------------------------------------------------------------------
/**
 * Construye el mensaje canónico que se firma para PoP.
 * Incluye email + fingerprint + kdfSalt para vincular la identidad del
 * usuario con su par de llaves y su salt de derivación.
 */
export function buildPopMessage(
  email: string,
  fingerprintHex: string,
  kdfSaltB64: string,
): Uint8Array {
  // Formato determinista: campo=valor separados por \n
  const msg = `zk-vault-pop-v1\nemail=${email}\nfingerprint=${fingerprintHex}\nsalt=${kdfSaltB64}`;
  return new TextEncoder().encode(msg);
}

/**
 * Firma el mensaje PoP con RSA-PSS (salt length = 32 bytes).
 * Devuelve la firma en base64.
 *
 *
 * mensaje (no appended). El verificador recibe mensaje + firma
 * por separado, permitiendo mayor flexibilidad de protocolo.
 *
 * IMPORTANTE: Web Crypto no permite usar la misma CryptoKey para
 * RSA-OAEP (decrypt) y RSA-PSS (sign) simultáneamente. Por eso
 * exportamos la privateKey a JWK y la re-importamos como RSA-PSS
 * con uso `sign`. Es la misma key material (mismos enteros n, d),
 * solo cambia el algoritmo de padding aplicado en esta operación.
 */
export async function signPop(
  privateKey: CryptoKey,
  email: string,
  fingerprintHex: string,
  kdfSaltB64: string,
): Promise<string> {
  // 1. Exportar la privateKey a JWK (es extraíble por diseño en generateKey)
  const jwk = await exportPrivateKeyJwk(privateKey);

  // 2. Re-importar como RSA-PSS con uso `sign`
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"],
  );

  // 3. Firmar
  const msg = buildPopMessage(email, fingerprintHex, kdfSaltB64);
  const sig = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    signingKey,
    msg as BufferSource,
  );
  return bufToBase64(sig);
}

/**
 * Verifica una firma PoP con la publicKey declarada.
 * Usado por el servidor en /api/auth/register.
 */
export async function verifyPop(
  publicKey: CryptoKey,
  signatureB64: string,
  email: string,
  fingerprintHex: string,
  kdfSaltB64: string,
): Promise<boolean> {
  try {
    // The public key may be imported as RSA-OAEP; re-import as RSA-PSS
    // for verification, mirroring what signPop does on the signing side.
    const jwk = await exportPublicKeyJwk(publicKey);
    const verifyKey = await crypto.subtle.importKey(
      "jwk",
      sanitizeJwk(jwk),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const msg = buildPopMessage(email, fingerprintHex, kdfSaltB64);
    return crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      verifyKey,
      base64ToBuf(signatureB64) as BufferSource,
      msg as BufferSource,
    );
  } catch {
    return false;
  }
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
  kdfAlgorithm: KdfAlgorithm;
  kdfSalt: string;
  kdfIterations: number;
  kdfMemoryKiB?: number;
  kdfParallelism?: number;
  publicKeyJwk: JsonWebKey;
  publicKeyFingerprint: string;
  encryptedPrivateKey: EncryptedPrivateKey;
  popSignature: string;
  masterKey: CryptoKey;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  mlKemPublicKey: string; // base64
  encryptedMlKemPrivateKey: { ciphertext: string; iv: string };
}

export async function performRegistration(
  email: string,
  password: string,
): Promise<RegistrationArtifacts> {
  // 1. Salt aleatorio
  const salt = randomBytes(SALT_LENGTH);

  // 2. Derivar llave maestra con Argon2id (memory-hard, GPU-resistant).
  //    Se ejecuta en Web Worker para no bloquear la UI.
  //
  //    ESTRATEGIA DE FALLBACK CONSISTENTE:
  //    - Intentar Argon2id primero.
  //    - Si el worker falla (WASM no soportado, error de carga), hacer
  //      fallback a PBKDF2 con iteraciones altas PERO marcar
  //      kdfAlgorithm="pbkdf2" honestamente (no mentir al servidor).
  //    - Así el login futuro será consistente: el servidor dirá "pbkdf2"
  //      y el cliente usará PBKDF2.
  const PREFER_ARGON2 = true;
  let masterKey: CryptoKey;
  let kdfAlgorithm: KdfAlgorithm;
  let kdfIterationsUsed: number;
  let kdfMemoryKiBUsed: number | undefined;
  let kdfParallelismUsed: number | undefined;

  if (PREFER_ARGON2) {
    try {
      masterKey = await deriveMasterKey(password, argon2DefaultParams(salt));
      kdfAlgorithm = "argon2id";
      kdfIterationsUsed = ARGON2_ITERATIONS;
      kdfMemoryKiBUsed = ARGON2_MEMORY_KIB;
      kdfParallelismUsed = ARGON2_PARALLELISM;
    } catch (err) {
      masterKey = await deriveMasterKey(
        password,
        pbkdf2LegacyParams(salt, KDF_ITERATIONS),
      );
      kdfAlgorithm = "pbkdf2";
      kdfIterationsUsed = KDF_ITERATIONS;
      kdfMemoryKiBUsed = undefined;
      kdfParallelismUsed = undefined;
    }
  } else {
    masterKey = await deriveMasterKey(
      password,
      pbkdf2LegacyParams(salt, KDF_ITERATIONS),
    );
    kdfAlgorithm = "pbkdf2";
    kdfIterationsUsed = KDF_ITERATIONS;
    kdfMemoryKiBUsed = undefined;
    kdfParallelismUsed = undefined;
  }

  // 3. Generar par RSA-OAEP + RSA-PSS
  const rsaPair = await generateRsaKeyPair();

  // 3b. Generar par ML-KEM-768 (post-quantum)
  const { getActiveKEM } = await import("./pq-kem");
  const kem = getActiveKEM();
  const mlKemPair = kem.generateKeyPair();
  const mlKemPublicKeyB64 = btoa(String.fromCharCode(...mlKemPair.publicKey));
  const mlKemPrivStr = btoa(String.fromCharCode(...mlKemPair.privateKey));
  const { ciphertext: encMlKemPriv, iv: mlKemIv } = await aesEncrypt(masterKey, mlKemPrivStr);
  const mlKemArtifacts = { publicKeyB64: mlKemPublicKeyB64, encrypted: { ciphertext: encMlKemPriv, iv: mlKemIv } };

  // 4. Cifrar llave privada con llave maestra (AES-256-GCM)
  const encryptedPrivateKey = await encryptPrivateKey(masterKey, rsaPair.privateKey);

  // 5. Exportar llave pública (en claro, es pública)
  const publicKeyJwk = await exportPublicKeyJwk(rsaPair.publicKey);

  // 6. Calcular fingerprint de la publicKey para TOFU
  const kdfSaltB64 = bufToBase64(salt);
  const fingerprint = await publicKeyFingerprint(publicKeyJwk);

  // 7. Firma PoP
  const normalizedEmail = email.toLowerCase().trim();
  const popSignature = await signPop(
    rsaPair.privateKey,
    normalizedEmail,
    fingerprint,
    kdfSaltB64,
  );

  return {
    kdfAlgorithm,
    kdfSalt: kdfSaltB64,
    kdfIterations: kdfIterationsUsed,
    kdfMemoryKiB: kdfMemoryKiBUsed,
    kdfParallelism: kdfParallelismUsed,
    publicKeyJwk,
    publicKeyFingerprint: fingerprint,
    encryptedPrivateKey,
    popSignature,
    masterKey,
    privateKey: rsaPair.privateKey,
    publicKey: rsaPair.publicKey,
    mlKemPublicKey: mlKemArtifacts.publicKeyB64,
    encryptedMlKemPrivateKey: mlKemArtifacts.encrypted,
  };
}

// ---------------------------------------------------------------------------
// 8. Orquestación de alto nivel — Login
// ---------------------------------------------------------------------------
export interface LoginArtifacts {
  masterKey: CryptoKey;
  privateKey: CryptoKey;
  mlKemPrivateKey: Uint8Array | null;
}

/**
 * Login que soporta tanto Argon2id (nuevo) como PBKDF2 (legacy).
 * El servidor devuelve el algoritmo usado en el registro; el cliente
 * aplica el mismo para derivar la masterKey.
 */
export async function performLogin(params: {
  password: string;
  kdfAlgorithm: KdfAlgorithm;
  kdfSaltB64: string;
  kdfIterations: number;
  kdfMemoryKiB?: number;
  kdfParallelism?: number;
  encryptedPrivateKeyJwkB64: string;
  privateKeyIvB64: string;
  encryptedMlKemPrivateKeyB64?: string;
  mlKemPrivateKeyIvB64?: string;
}): Promise<LoginArtifacts> {
  const {
    password,
    kdfAlgorithm,
    kdfSaltB64,
    kdfIterations,
    kdfMemoryKiB,
    kdfParallelism,
    encryptedPrivateKeyJwkB64,
    privateKeyIvB64,
    encryptedMlKemPrivateKeyB64,
    mlKemPrivateKeyIvB64,
  } = params;

  const salt = base64ToBuf(kdfSaltB64);
  const kdfParams: KdfParams =
    kdfAlgorithm === "argon2id"
      ? { algorithm: "argon2id", salt, memoryKiB: kdfMemoryKiB ?? ARGON2_MEMORY_KIB, argon2Iterations: kdfIterations, parallelism: kdfParallelism ?? ARGON2_PARALLELISM }
      : { algorithm: "pbkdf2", salt, iterations: kdfIterations };

  const masterKey = await deriveMasterKey(password, kdfParams);
  const privateKey = await decryptPrivateKey(masterKey, encryptedPrivateKeyJwkB64, privateKeyIvB64);

  let mlKemPrivateKey: Uint8Array | null = null;
  if (encryptedMlKemPrivateKeyB64 && mlKemPrivateKeyIvB64) {
    try {
      const mlKemPrivStr = await aesDecrypt(masterKey, encryptedMlKemPrivateKeyB64, mlKemPrivateKeyIvB64);
      mlKemPrivateKey = Uint8Array.from(atob(mlKemPrivStr), (c) => c.charCodeAt(0));
    } catch { mlKemPrivateKey = null; }
  }

  return { masterKey, privateKey, mlKemPrivateKey };
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
  recipientMlKemPrivateKey?: Uint8Array | null,
): Promise<{ title: string; content: string; aesKey: CryptoKey }> {
  let aesKey: CryptoKey;
  const { isKemWrappedKey } = await import("./pq-kem");

  if (recipientMlKemPrivateKey && isKemWrappedKey(wrappedKeyB64)) {
    // ML-KEM hybrid unwrap
    const { getActiveKEM } = await import("./pq-kem");
    const kem = getActiveKEM();
    const rawAes = await kem.unwrapAesKey(wrappedKeyB64, recipientMlKemPrivateKey);
    aesKey = await importAesKeyRaw(rawAes.buffer as ArrayBuffer);
  } else {
    // RSA-OAEP unwrap (legacy)
    aesKey = await unwrapAesKeyWithRsaPrivateKey(wrappedKeyB64, recipientPrivateKey);
  }

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
  recipientMlKemPublicKeyB64?: string | null,
): Promise<string> {
  // 1. Owner desenvuelve SU wrappedKey -> obtiene AES key cruda (bytes)
  const { isKemWrappedKey } = await import("./pq-kem");
  let rawAesBytes: ArrayBuffer;

  if (isKemWrappedKey(ownerWrappedKeyB64)) {
    // Owner's key was KEM-wrapped — needs ML-KEM private key (not available here in RSA flow)
    // Fall through to RSA decrypt attempt (will fail gracefully if owner used KEM)
    throw new Error("Owner's wrapped key is KEM-encrypted — RSA unwrap not possible");
  }

  rawAesBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    ownerPrivateKey,
    base64ToBuf(ownerWrappedKeyB64) as BufferSource,
  );

  // 2. Re-envuelve con la llave del destinatario
  if (recipientMlKemPublicKeyB64) {
    // ML-KEM hybrid wrap
    const { getActiveKEM } = await import("./pq-kem");
    const kem = getActiveKEM();
    const recipientMlKemPub = Uint8Array.from(atob(recipientMlKemPublicKeyB64), (c) => c.charCodeAt(0));
    return kem.wrapAesKey(new Uint8Array(rawAesBytes), recipientMlKemPub);
  }

  // RSA-OAEP wrap (legacy fallback)
  const rewrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesBytes,
  );
  return bufToBase64(rewrapped);
}

// ---------------------------------------------------------------------------
// 12. Orquestación de alto nivel — Rotación de contraseña maestra
// ---------------------------------------------------------------------------
/**
 * Rotación de contraseña maestra.
 *
 * Cliente debe proporcionar:
 *   - oldPassword: para descifrar la privateKey actual y verificar que
 *     el usuario legítimo es quien rota (no un atacante con sesión abierta).
 *   - newPassword: la nueva contraseña maestra.
 *   - Los artifacts del login actual (salt, iterations, encryptedPrivateKey,
 *     iv) para descifrar la privateKey.
 *
 * Salida: artifacts listos para enviar al servidor:
 *   - newKdfSalt, newKdfIterations
 *   - newEncryptedPrivateKey (la MISMA privateKey, re-cifrada con la nueva
 *     masterKey)
 *   - newPopSignature (firma sobre el nuevo salt, con la misma privateKey)
 *
 * CRÍTICO: la privateKey RSA NO cambia. Por tanto:
 *   - Las wrappedKeys existentes siguen siendo válidas.
 *   - Los shares existentes siguen funcionando.
 *   - Solo cambia el "candado" (masterKey) que protege la privateKey en BD.
 *
 * Si el atacante tiene la masterKey VIEJA pero el usuario rota antes de que
 * el atacante obtenga la BD, la masterKey vieja ya no sirve para nada.
 */
export interface RotationArtifacts {
  newKdfAlgorithm: KdfAlgorithm;
  newKdfSalt: string;
  newKdfIterations: number;
  newKdfMemoryKiB?: number;
  newKdfParallelism?: number;
  newEncryptedPrivateKey: EncryptedPrivateKey;
  newPopSignature: string;
  // En memoria (actualizar el store):
  newMasterKey: CryptoKey;
}

export async function performPasswordRotation(params: {
  oldPassword: string;
  newPassword: string;
  email: string;
  currentKdfAlgorithm: KdfAlgorithm;
  currentKdfSaltB64: string;
  currentKdfIterations: number;
  currentKdfMemoryKiB?: number;
  currentKdfParallelism?: number;
  currentEncryptedPrivateKeyJwkB64: string;
  currentPrivateKeyIvB64: string;
}): Promise<RotationArtifacts> {
  const {
    oldPassword,
    newPassword,
    email,
    currentKdfAlgorithm,
    currentKdfSaltB64,
    currentKdfIterations,
    currentKdfMemoryKiB,
    currentKdfParallelism,
    currentEncryptedPrivateKeyJwkB64,
    currentPrivateKeyIvB64,
  } = params;

  // 1. Descifrar la privateKey JWK con la contraseña VIEJA.
  //    Usamos el algoritmo declarado en el registro (Argon2id o PBKDF2 legacy).
  const oldKdfParams: KdfParams =
    currentKdfAlgorithm === "argon2id"
      ? {
          algorithm: "argon2id",
          salt: base64ToBuf(currentKdfSaltB64),
          memoryKiB: currentKdfMemoryKiB ?? ARGON2_MEMORY_KIB,
          argon2Iterations: currentKdfIterations,
          parallelism: currentKdfParallelism ?? ARGON2_PARALLELISM,
        }
      : {
          algorithm: "pbkdf2",
          salt: base64ToBuf(currentKdfSaltB64),
          iterations: currentKdfIterations,
        };

  const oldMasterKey = await deriveMasterKey(oldPassword, oldKdfParams);
  const privateKeyJwkStr = await aesDecrypt(
    oldMasterKey,
    currentEncryptedPrivateKeyJwkB64,
    currentPrivateKeyIvB64,
  );
  const privateKeyJwk = JSON.parse(privateKeyJwkStr) as JsonWebKey;

  // 2. Generar nuevo salt y derivar nueva masterKey.
  //    Misma estrategia de fallback consistente que el registro.
  const PREFER_ARGON2 = true;
  const newSalt = randomBytes(SALT_LENGTH);
  let newMasterKey: CryptoKey;
  let newKdfAlgorithm: KdfAlgorithm;
  let newKdfIterations: number;
  let newKdfMemoryKiB: number | undefined;
  let newKdfParallelism: number | undefined;

  if (PREFER_ARGON2) {
    try {
      newMasterKey = await deriveMasterKey(newPassword, argon2DefaultParams(newSalt));
      newKdfAlgorithm = "argon2id";
      newKdfIterations = ARGON2_ITERATIONS;
      newKdfMemoryKiB = ARGON2_MEMORY_KIB;
      newKdfParallelism = ARGON2_PARALLELISM;
    } catch (err) {
      throw new Error("Argon2id unavailable");
      newMasterKey = await deriveMasterKey(
        newPassword,
        pbkdf2LegacyParams(newSalt, KDF_ITERATIONS),
      );
    throw new Error("Argon2id unavailable in rotation");
      newKdfIterations = KDF_ITERATIONS;
      newKdfMemoryKiB = undefined;
      newKdfParallelism = undefined;
    }
  } else {
    newMasterKey = await deriveMasterKey(
      newPassword,
      pbkdf2LegacyParams(newSalt, KDF_ITERATIONS),
    );
    newKdfAlgorithm = "pbkdf2";
    newKdfIterations = KDF_ITERATIONS;
    newKdfMemoryKiB = undefined;
    newKdfParallelism = undefined;
  }

  // 3. Re-cifrar la MISMA privateKey JWK con la nueva masterKey
  const { ciphertext: newEncryptedJwk, iv: newIv } = await aesEncrypt(
    newMasterKey,
    privateKeyJwkStr,
  );
  const newEncryptedPrivateKey: EncryptedPrivateKey = {
    encryptedJwk: newEncryptedJwk,
    iv: newIv,
  };

  // 4. Construir publicKey JWK desde la privateKey JWK (mismo n, e)
  const publicKeyJwk: JsonWebKey = {
    kty: privateKeyJwk.kty,
    n: privateKeyJwk.n,
    e: privateKeyJwk.e,
  };

  // 5. Fingerprint de la publicKey (para PoP message)
  const newKdfSaltB64 = bufToBase64(newSalt);
  const fingerprint = await publicKeyFingerprint(publicKeyJwk);

  // 6. Importar temporalmente la privateKey como RSA-PSS para firmar PoP
  const normalizedEmail = email.toLowerCase().trim();
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(privateKeyJwk),
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const msg = buildPopMessage(normalizedEmail, fingerprint, newKdfSaltB64);
  const sig = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    signingKey,
    msg as BufferSource,
  );
  const newPopSignature = bufToBase64(sig);

  return {
    newKdfAlgorithm,
    newKdfSalt: newKdfSaltB64,
    newKdfIterations: newKdfIterations,
    newKdfMemoryKiB: newKdfMemoryKiB,
    newKdfParallelism: newKdfParallelism,
    newEncryptedPrivateKey,
    newPopSignature,
    newMasterKey,
  };
}

/**
 * Construye una publicKey JWK a partir de una privateKey JWK.
 * En RSA, la publicKey contiene los mismos `n` y `e` que la privateKey,
 * pero sin `d`, `p`, `q`, `dp`, `dq`, `qi`.
 *
 * Web Crypto no permite "derivar" la publicKey desde una CryptoKey privada
 * directamente, pero podemos exportar la privateKey a JWK y construir la
 * publicKey JWK manualmente conservando solo los campos públicos.
 */

// =========================================================================
// 13. MULTI-DEVICE SYNC — ECDH (P-256) para autorizar nuevos dispositivos
// =========================================================================
//
// Cada dispositivo tiene su propio par ECDH (P-256). Cuando el usuario
// quiere autorizar un dispositivo nuevo:
//
//   1. Dispositivo B (nuevo) genera par ECDH, muestra código + publicKeyECDH.
//   2. Dispositivo A (logueado) escanea, deriva shared secret ECDH
//      (A.privateKeyECDH × B.publicKeyECDH), y usa ese shared secret
//      como llave AES-256 para envolver la privateKey RSA del usuario.
//   3. Servidor almacena el blob en Device.wrappedPrivateKeyForDevice.
//   4. Dispositivo B hace polling, recibe el blob, deriva el mismo
//      shared secret (B.privateKeyECDH × A.publicKeyECDH) y desenvuelve.
//
// El servidor NUNCA ve la privateKey RSA ni el shared secret ECDH.
// =========================================================================

const ECDH_CURVE = "P-256"; // NIST P-256, ~128-bit security, soportado por Web Crypto

/** Genera un par ECDH P-256 para un dispositivo. */
export async function generateEcdhKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: ECDH_CURVE },
    true,
    ["deriveKey", "deriveBits"],
  );
}

export async function exportEcdhPublicKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}

export async function importEcdhPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "ECDH", namedCurve: ECDH_CURVE },
    true,
    [],
  );
}

export async function importEcdhPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "ECDH", namedCurve: ECDH_CURVE },
    false,
    ["deriveKey", "deriveBits"],
  );
}

/**
 * Deriva una llave simétrica AES-256-GCM a partir de ECDH entre
 * la privateKey propia y la publicKey del peer.
 *
 * Esta llave solo existe en los dos dispositivos (A y B) — nunca
 * sale ni se envía al servidor.
 */
export async function deriveEcdhSharedAesKey(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    ownPrivateKey,
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"],
  );
}

/**
 * Envuelve (cifra) la privateKey RSA del usuario con una llave AES
 * derivada de ECDH. Usado por el dispositivo A para autorizar al
 * dispositivo B.
 *
 * Recibe la privateKey RSA como JWK string (porque la CryptoKey en
 * sesión es no-extraíble), la cifra con AES-256-GCM usando la llave
 * ECDH compartida.
 */
export async function wrapPrivateKeyForDevice(
  privateKeyJwkStr: string,
  ecdhSharedKey: CryptoKey,
): Promise<{ wrappedKey: string; iv: string }> {
  const { ciphertext, iv } = await aesEncrypt(ecdhSharedKey, privateKeyJwkStr);
  return { wrappedKey: ciphertext, iv };
}

/**
 * Desenvuelve (descifra) la privateKey RSA del usuario usando la llave
 * AES derivada de ECDH. Usado por el dispositivo B tras recibir el
 * blob del servidor.
 */
export async function unwrapPrivateKeyForDevice(
  wrappedKeyB64: string,
  ivB64: string,
  ecdhSharedKey: CryptoKey,
): Promise<CryptoKey> {
  const privateKeyJwkStr = await aesDecrypt(ecdhSharedKey, wrappedKeyB64, ivB64);
  const jwk = JSON.parse(privateKeyJwkStr) as JsonWebKey;
  return importPrivateKeyJwk(jwk);
}

// =========================================================================
// 13b. CHALLENGE-RESPONSE ECDSA (P-256) para Enroll Device
// =========================================================================
//
// Cierra la brecha crítica del flujo Enroll Device:
//   1. El servidor genera un challenge (nonce 32 bytes) y lo asocia al
//      deviceId con TTL corto (60s).
//   2. El Dispositivo B firma el challenge con su privateKey ECDH usando
//      ECDSA P-256 (SHA-256).
//   3. El servidor verifica la firma con la publicKeyECDH registrada.
//      Solo si es válida, devuelve la wrappedPrivateKeyForDevice.
//
// Esto prueba posesión de la privateKey ECDH, no solo conocimiento del
// deviceId. Un atacante que intercepte el deviceId no puede responder
// al challenge sin la privateKey.
//
// Nota: ECDSA P-256 reutiliza el mismo par de llaves que ECDH P-256
// matemáticamente (mismo grupo curva), pero Web Crypto requiere importar
// la llave con uso `sign`/`verify` por separado.
// =========================================================================

const ECDSA_CURVE = "P-256";

/**
 * Importa una JWK de privateKey ECDH como ECDSA para firmar challenges.
 * Mismo par de llaves, distinto uso.
 */
export async function importEcdhPrivateKeyForSigning(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "ECDSA", namedCurve: ECDSA_CURVE },
    false,
    ["sign"],
  );
}

/**
 * Importa una JWK de publicKey ECDH como ECDSA para verificar challenges.
 */
export async function importEcdhPublicKeyForVerifying(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    sanitizeJwk(jwk),
    { name: "ECDSA", namedCurve: ECDSA_CURVE },
    true,
    ["verify"],
  );
}

/**
 * Firma un challenge (nonce) con ECDSA P-256 + SHA-256.
 * Devuelve la firma en base64.
 *
 * Usado por el Dispositivo B para probar posesión de su privateKey ECDH.
 */
export async function signChallenge(
  privateKey: CryptoKey,
  challengeB64: string,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    base64ToBuf(challengeB64) as BufferSource,
  );
  return bufToBase64(signature);
}

/**
 * Verifica una firma ECDSA P-256 sobre un challenge.
 * Usado por el servidor en /api/devices/enroll/poll/verify.
 */
export async function verifyChallenge(params: {
  publicKeyJwk: JsonWebKey;
  challengeB64: string;
  signatureB64: string;
}): Promise<boolean> {
  const { publicKeyJwk, challengeB64, signatureB64 } = params;
  try {
    const publicKey = await importEcdhPublicKeyForVerifying(publicKeyJwk);
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      base64ToBuf(signatureB64) as BufferSource,
      base64ToBuf(challengeB64) as BufferSource,
    );
  } catch {
    return false;
  }
}

/**
 * Genera un código de enrollment de 6 dígitos (criptográficamente
 * seguro). El dispositivo B lo muestra al usuario, quien lo introduce
 * en el dispositivo A para vincularlos.
 */
export function generateEnrollCode(): string {
  const bytes = randomBytes(4);
  // Convertir a número de 6 dígitos (mod 1_000_000)
  const num =
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return (num % 1_000_000).toString().padStart(6, "0");
}

// =========================================================================
// 14. RECOVERY KEY (BIP-39) — Backup cifrado de la privateKey
// =========================================================================
//
// Genera una frase semilla de 24 palabras (256 bits de entropía, BIP-39).
// El usuario la guarda offline. Se deriva a una llave AES-256 para cifrar
// la privateKey RSA del usuario como backup de recuperación.
//
// Si el usuario olvida su contraseña maestra, introduce las 24 palabras
// → se deriva la recovery key → se descifra la privateKey RSA → se puede
// re-establecer una nueva contraseña maestra.
//
// El servidor NUNCA ve las 24 palabras — solo el blob cifrado.
// =========================================================================

const RECOVERY_KDF_ITERATIONS = 600_000; // PBKDF2 alto — no bloquea UI porque solo se usa en recuperación

/**
 * Genera una frase semilla BIP-39 de 24 palabras (256 bits de entropía).
 * Devuelve { mnemonic, entropyHex }.
 *
 * El usuario debe guardar las 24 palabras offline. La entropía NO se
 * envía al servidor.
 */
export async function generateRecoveryMnemonic(): Promise<{
  mnemonic: string;
  entropyHex: string;
}> {
  // Usamos la librería bip39 (dependencia instalada)
  const { generateMnemonic, entropyToMnemonic, mnemonicToEntropy } = await import("bip39");
  // 24 palabras = 256 bits de entropía
  const mnemonic = generateMnemonic(256);
  const entropyHex = mnemonicToEntropy(mnemonic);
  return { mnemonic, entropyHex };
}

/**
 * Valida que una frase BIP-39 sea correcta (checksum + palabras válidas).
 */
export async function validateRecoveryMnemonic(mnemonic: string): Promise<boolean> {
  const { validateMnemonic } = await import("bip39");
  return validateMnemonic(mnemonic.trim().toLowerCase());
}

/**
 * Deriva una llave AES-256-GCM a partir de la frase BIP-39.
 *
 * Usamos PBKDF2 con muchas iteraciones (no Argon2id) porque:
 *   1. La frase tiene 256 bits de entropía — no necesita memory-hardness
 *      (no es una contraseña baja-entropía).
 *   2. PBKDF2 es universalmente soportado y la recuperación es rara.
 *
 * El salt debe ser aleatorio por usuario y almacenarse en el servidor.
 */
export async function deriveRecoveryKey(
  mnemonic: string,
  salt: Uint8Array,
  iterations: number = RECOVERY_KDF_ITERATIONS,
): Promise<CryptoKey> {
  const normalized = mnemonic.trim().toLowerCase().normalize("NFC");
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalized),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Cifra la privateKey RSA con la recovery key. Devuelve el blob que
 * se envía al servidor como `encryptedPrivateKeyForRecovery`.
 */
export async function encryptPrivateKeyForRecovery(
  privateKeyJwkStr: string,
  recoveryKey: CryptoKey,
): Promise<{ ciphertext: string; iv: string }> {
  return aesEncrypt(recoveryKey, privateKeyJwkStr);
}

/**
 * Descifra la privateKey RSA usando la recovery key. Usado en el flujo
 * de recuperación de cuenta.
 */
export async function decryptPrivateKeyForRecovery(
  encryptedB64: string,
  ivB64: string,
  recoveryKey: CryptoKey,
): Promise<CryptoKey> {
  const jwkStr = await aesDecrypt(recoveryKey, encryptedB64, ivB64);
  const jwk = JSON.parse(jwkStr) as JsonWebKey;
  return importPrivateKeyJwk(jwk);
}

export const RECOVERY_ITERATIONS = RECOVERY_KDF_ITERATIONS;

// =========================================================================
// 15. AUDIT LOG CIFRADO (Zero-Knowledge Logging)
// =========================================================================
//
// Los logs se generan y CIFRAN en el cliente con una llave de auditoría
// derivada de la masterKey vía HKDF. El servidor solo almacena blobs.
//
// La llave de auditoría es DISTINTA de la masterKey para que un atacante
// con la masterKey (ej. via sesión abierta) no pueda leer logs históricos
// si la llave de auditoría se rotó. Se deriva como:
//   HKDF-SHA256(masterKey, salt="", info="zk-vault-audit-log-v1", length=32)
//
// El servidor NUNCA ve:
//   - El contenido del log (cifrado AES-256-GCM)
//   - La llave de auditoría
//   - La masterKey
//
// Solo ve: userId, categoría (para indexación), timestamp.
// =========================================================================

/**
 * Deriva la llave de auditoría desde la masterKey usando HKDF.
 *
 * HKDF expande la masterKey en una llave independiente para que los
 * logs no se puedan descifrar con la masterKey directamente.
 */
export async function deriveAuditKey(masterKey: CryptoKey): Promise<CryptoKey> {
  // Re-derive raw bytes from the password is not possible (masterKey is
  // non-extractable). Instead, we derive the audit subkey by encrypting
  // a fixed nonce with masterKey to get 32 bytes of IKM, then HKDF-expand.
  // This is acceptable because the "nonce" is unique per purpose and the
  // IV is fixed (deterministic) — same input → same output, but distinct
  // for each subkey purpose.
  const fixedNonce = new TextEncoder().encode("zk-vault-audit-nonce-v1");
  const iv = new Uint8Array(12);
  const ikm = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      masterKey,
      fixedNonce,
    ),
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  const { deriveSubKey } = await import("./hkdf");
  return deriveSubKey(hkdfKey, "audit");
}

/**
 * Crea y cifra un evento de auditoría.
 *
 * El evento es un JSON con: { type, timestamp, details, ... }
 * Se serializa y se cifra con AES-256-GCM usando la audit key.
 */
export async function encryptAuditEvent(
  auditKey: CryptoKey,
  event: Record<string, unknown>,
): Promise<{ encryptedEvent: string; eventIv: string }> {
  const eventStr = JSON.stringify({
    ...event,
    timestamp: new Date().toISOString(),
  });
  const { ciphertext, iv } = await aesEncrypt(auditKey, eventStr);
  return { encryptedEvent: ciphertext, eventIv: iv };
}

/**
 * Descifra un evento de auditoría.
 */
export async function decryptAuditEvent(
  auditKey: CryptoKey,
  encryptedEventB64: string,
  eventIvB64: string,
): Promise<Record<string, unknown>> {
  const eventStr = await aesDecrypt(auditKey, encryptedEventB64, eventIvB64);
  return JSON.parse(eventStr);
}

export type AuditCategory = "auth" | "secret" | "share" | "device" | "recovery";

// Fingerprint cache (LRU with TTL)
const _fpCache = new Map<string, { fp: string; exp: number }>();
const FP_CACHE_TTL = 5 * 60 * 1000;

export async function cachedPublicKeyFingerprint(jwk: JsonWebKey): Promise<string> {
  const key = JSON.stringify(jwk);
  const cached = _fpCache.get(key);
  if (cached && Date.now() < cached.exp) return cached.fp;
  const fp = await publicKeyFingerprint(jwk);
  _fpCache.set(key, { fp, exp: Date.now() + FP_CACHE_TTL });
  if (_fpCache.size > 50) {
    const firstKey = _fpCache.keys().next().value;
    if (firstKey) _fpCache.delete(firstKey);
  }
  return fp;
}
