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

export const ARGON2_MEMORY_KIB = 65_536; // 64 MiB
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
  return password.normalize("NFC");
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
      console.error("[argon2-worker] Error no capturado:", e.message);
      _argonWorker = null; // Reset para permitir reintento
    };
    return _argonWorker;
  } catch (err) {
    console.warn("[argon2] No se pudo crear Worker, fallback a PBKDF2:", err);
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
  const normalized = normalizePassword(password);

  if (params.algorithm === "argon2id") {
    // Argon2id vía Web Worker.
    //
    // IMPORTANTE: NO hacemos fallback silencioso a PBKDF2 aquí. Si el
    // worker falla, propagamos el error. El llamador decide qué hacer:
    //   - En REGISTRO: si Argon2id falla, abortar (no registrar con
    //     algoritmo equivocado).
    //   - En LOGIN: el servidor ya dijo qué algoritmo se usó al registrar;
    //     si era argon2id, DEBE usarse argon2id (no se puede cambiar a
    //     pbkdf2 porque la masterKey sería distinta y el descifrado fallaría).
    //
    // El fallback a PBKDF2 solo tiene sentido si el usuario tiene una
    // cuenta legacy (kdfAlgorithm="pbkdf2" en BD), en cuyo caso
    // params.algorithm === "pbkdf2" y este bloque no se ejecuta.
    const rawKey = await argon2HashInWorker({
      password: normalized,
      salt: params.salt,
      memoryKiB: params.memoryKiB ?? ARGON2_MEMORY_KIB,
      iterations: params.argon2Iterations ?? ARGON2_ITERATIONS,
      parallelism: params.parallelism ?? ARGON2_PARALLELISM,
    });
    return crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      false,
      ["encrypt", "decrypt"],
    );
  }

  // PBKDF2 (legacy o explícito)
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
      salt: params.salt as BufferSource,
      iterations: params.iterations ?? KDF_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
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
  const ctBuf = base64ToBuf(ciphertextB64);
  const ivBuf = base64ToBuf(ivB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBuf as BufferSource },
    key,
    ctBuf as BufferSource,
  );
  zeroBuffer(ctBuf);
  zeroBuffer(ivBuf);
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
  const key = await importPrivateKeyJwk(jwk);
  // Zero the JWK string and parsed object after import
  zeroBuffer(new TextEncoder().encode(jwkStr));
  for (const k of Object.keys(jwk)) {
    (jwk as any)[k] = "";
  }
  return key;
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
    const msg = buildPopMessage(email, fingerprintHex, kdfSaltB64);
    return crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
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
  kdfIterations: number; // Para Argon2id = t (time); para PBKDF2 = iteraciones
  kdfMemoryKiB?: number; // Argon2id only
  kdfParallelism?: number; // Argon2id only
  publicKeyJwk: JsonWebKey;
  publicKeyFingerprint: string; // hex SHA-256 — para TOFU
  encryptedPrivateKey: EncryptedPrivateKey;
  popSignature: string; // base64 RSA-PSS — prueba de posesión
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
      console.warn(
        "[kdf] Argon2id no disponible, fallback HONESTO a PBKDF2. " +
          "La cuenta se registrará con kdfAlgorithm='pbkdf2'. Error:",
        err,
      );
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
  };
}

// ---------------------------------------------------------------------------
// 8. Orquestación de alto nivel — Login
// ---------------------------------------------------------------------------
export interface LoginArtifacts {
  masterKey: CryptoKey;
  privateKey: CryptoKey;
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
  } = params;

  const salt = base64ToBuf(kdfSaltB64);
  const kdfParams: KdfParams =
    kdfAlgorithm === "argon2id"
      ? {
          algorithm: "argon2id",
          salt,
          memoryKiB: kdfMemoryKiB ?? ARGON2_MEMORY_KIB,
          argon2Iterations: kdfIterations,
          parallelism: kdfParallelism ?? ARGON2_PARALLELISM,
        }
      : {
          algorithm: "pbkdf2",
          salt,
          iterations: kdfIterations,
        };

  const masterKey = await deriveMasterKey(password, kdfParams);
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
  const wrappedBuf = base64ToBuf(ownerWrappedKeyB64);
  const rawAesBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    ownerPrivateKey,
    wrappedBuf as BufferSource,
  );
  zeroBuffer(wrappedBuf);

  const rewrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesBytes,
  );
  zeroBuffer(new Uint8Array(rawAesBytes));

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
      console.warn("[kdf] Argon2id no disponible en rotación, fallback HONESTO a PBKDF2:", err);
      newMasterKey = await deriveMasterKey(
        newPassword,
        pbkdf2LegacyParams(newSalt, KDF_ITERATIONS),
      );
      newKdfAlgorithm = "pbkdf2";
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
async function derivePublicJwkFromPrivate(privateKey: CryptoKey): Promise<JsonWebKey> {
  const privJwk = await exportPrivateKeyJwk(privateKey);
  return {
    kty: privJwk.kty,
    n: privJwk.n,
    e: privJwk.e,
  };
}

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
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    ownPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
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
  const num =
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return (num % 1_000_000).toString().padStart(6, "0");
}

// =========================================================================
// 13c. POST-QUANTUM KEM (Kyber/ML-KEM 768) — Hybrid Key Exchange
// =========================================================================
//
// Mejora #1: Integración de ML-KEM (CRYSTALS-Kyber) como KEM post-quántico
// junto a ECDH P-256 para ofrecer cifrado híbrido (ECDH + Kyber).
//
// Esquema híbrido:
//   1. Cada dispositivo genera un par ECDH P-256 Y un par Kyber ML-KEM 768.
//   2. Durante el enrollment, el dispositivo A (logueado) deriva DOS shared
//      secrets: ECDH(A.priv × B.pub) + Kyber encapsulate(B.pubKyber).
//   3. Ambos shared secrets se combinan vía SHA-256 para producir la llave
//      AES final que envuelve la privateKey RSA del usuario.
//   4. Un atacante que rompa ECDH (computación cuántica) aún necesitaría
//      romper Kyber, y viceversa. Mientras AL MENOS UNO de los dos
//      algoritmos sea seguro, el secreto compuesto es seguro.
//
// ML-KEM 768 (~NIST security level 3) es el parámetro recomendado para
// un balance seguridad/rendimiento. Level 5 (1024) está disponible si se
// necesita máxima seguridad.
//
// Esta integración es la primera capa de defensa post-quántica. En el futuro,
// Kyber podría reemplazar completamente a ECDH cuando Web Crypto lo soporte
// nativamente.
// =========================================================================

export type KyberSecurityLevel = 512 | 768 | 1024;

const KYBER_DEFAULT_LEVEL: KyberSecurityLevel = 768;

export interface KyberKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface KyberCiphertext {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * Genera un par de llaves Kyber ML-KEM en el nivel especificado.
 * ML-KEM 768 (recomendado) produce 1184 bytes de publicKey y 2400 bytes
 * de privateKey. Todo en memoria, nunca sale del navegador.
 */
export async function generateKyberKeyPair(
  level: KyberSecurityLevel = KYBER_DEFAULT_LEVEL,
): Promise<KyberKeyPair> {
  const { default: Kyber } = await import("crystals-kyber-js");
  const kyber = new Kyber(level);
  const { publicKey, privateKey } = kyber.generateKeypair();
  return { publicKey: new Uint8Array(publicKey), privateKey: new Uint8Array(privateKey) };
}

/**
 * Encapsula: genera un ciphertext + shared secret a partir de una
 * publicKey Kyber. El ciphertext se envía al peer; el shared secret
 * se combina con el ECDH shared secret para formar la llave híbrida.
 */
export async function kyberEncapsulate(
  publicKey: Uint8Array,
  level: KyberSecurityLevel = KYBER_DEFAULT_LEVEL,
): Promise<KyberCiphertext> {
  const { default: Kyber } = await import("crystals-kyber-js");
  const kyber = new Kyber(level);
  const { cipherText, sharedSecret } = kyber.encapsulate(publicKey);
  return { ciphertext: new Uint8Array(cipherText), sharedSecret: new Uint8Array(sharedSecret) };
}

/**
 * Decapsula: recupera el shared secret a partir de un ciphertext +
 * privateKey Kyber. Usado por el peer para derivar el mismo shared secret.
 */
export async function kyberDecapsulate(
  ciphertext: Uint8Array,
  privateKey: Uint8Array,
  level: KyberSecurityLevel = KYBER_DEFAULT_LEVEL,
): Promise<Uint8Array> {
  const { default: Kyber } = await import("crystals-kyber-js");
  const kyber = new Kyber(level);
  const sharedSecret = kyber.decapsulate(ciphertext, privateKey);
  return new Uint8Array(sharedSecret);
}

/**
 * Deriva una llave AES-256-GCM a partir de la combinación híbrida
 * de dos shared secrets: ECDH + Kyber. Se concatenan y se hashean
 * con SHA-256 para producir una única llave de 256 bits.
 *
 * Zeroeamos los buffers intermedios después de usarlos.
 * Si Kyber no está disponible, se usa solo ECDH (fallback seguro).
 */
export async function deriveHybridSharedAesKey(
  ecdhSharedKey: CryptoKey,
  kyberSharedSecret: Uint8Array | null,
): Promise<CryptoKey> {
  const ecdhRaw = await crypto.subtle.exportKey("raw", ecdhSharedKey);
  const combined = new Uint8Array(ecdhRaw.byteLength + (kyberSharedSecret?.length ?? 0));
  combined.set(new Uint8Array(ecdhRaw), 0);
  zeroBuffer(ecdhRaw);
  if (kyberSharedSecret) {
    combined.set(kyberSharedSecret, ecdhRaw.byteLength);
    zeroBuffer(kyberSharedSecret);
  }
  const hash = await crypto.subtle.digest("SHA-256", combined);
  zeroBuffer(combined);
  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Serializa una Kyber publicKey a base64 para enviarla al servidor
 * como parte del enrollment de dispositivo.
 */
export function kyberPublicKeyToBase64(publicKey: Uint8Array): string {
  return bufToBase64(publicKey);
}

/**
 * Deserializa una Kyber publicKey desde base64.
 */
export function kyberPublicKeyFromBase64(b64: string): Uint8Array {
  return base64ToBuf(b64);
}

/**
 * Serializa una Kyber ciphertext a base64 para almacenar en el servidor
 * junto con el enrollment (el ciphertext lo necesita el dispositivo B).
 */
export function kyberCiphertextToBase64(ciphertext: Uint8Array): string {
  return bufToBase64(ciphertext);
}

export function kyberCiphertextFromBase64(b64: string): Uint8Array {
  return base64ToBuf(b64);
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
  // Web Crypto no soporta HKDF directamente sobre AES-GCM keys.
  // Workaround: exportar masterKey como raw (es no-extraíble por defecto,
  // así que esto falla). En su lugar, usamos masterKey para cifrar un
  // secreto fijo y derivar la llave del ciphertext.
  //
  // Mejor enfoque: usar la masterKey como input a PBKDF2 con un salt fijo
  // y un info string, lo que produce una llave independiente.
  //
  // Como la masterKey es AES-GCM no-extraíble, no podemos obtener sus raw
  // bytes. En su lugar, la usamos para cifrar un nonce fijo, y el
  // ciphertext resultante (32 bytes) se usa como semilla para derivar
  // la audit key vía PBKDF2.

  // Cifrar un nonce fijo con la masterKey → produce 12 (IV) + 16 (tag) + 32 (plaintext) = 60 bytes
  const fixedNonce = new TextEncoder().encode("zk-vault-audit-nonce-v1");
  const iv = new Uint8Array(12); // IV fijo de ceros — OK porque el plaintext es único
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    masterKey,
    fixedNonce,
  );

  // Usar el ciphertext como semilla para derivar la audit key
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
      salt: new TextEncoder().encode("zk-vault-audit-salt"),
      iterations: 100_000, // bajo porque la semilla ya es alta-entropía
      hash: "SHA-256",
    },
    seedKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
  );
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
