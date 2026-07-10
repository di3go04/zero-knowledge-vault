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
export const KDF_ITERATIONS_MIN = 310_000; // mínimo server-side (post-2024)
export const KDF_ITERATIONS_MAX = 1_000_000; // máximo server-side (anti-DoS)
export const SALT_LENGTH = 16; // 128 bits — mínimo absoluto
export const IV_LENGTH = 12; // 96 bits (recomendado GCM)
export const RSA_MODULUS = 2048;
export const AES_KEY_LENGTH = 256;
export const MAX_BLOB_BYTES = 64 * 1024; // 64 KiB — anti-DoS para blobs cifrados
export const MAX_JWK_BYTES = 4 * 1024; // 4 KiB — una JWK RSA-2048 ocupa ~1.2 KiB

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
  // 1. Normalizar Unicode NFC — evita bloqueos por diferencias NFC/NFD
  const normalized = normalizePassword(password);

  // 2. Importar password como llave raw
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalized),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  // 3. Derivar llave AES-256-GCM no extraíble
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
  kdfSalt: string;
  kdfIterations: number;
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

  // 2. Derivar llave maestra (PBKDF2) con password normalizado NFC
  const masterKey = await deriveMasterKey(password, salt);

  // 3. Generar par RSA-OAEP + RSA-PSS
  const rsaPair = await generateRsaKeyPair();

  // 4. Cifrar llave privada con llave maestra (AES-256-GCM)
  const encryptedPrivateKey = await encryptPrivateKey(masterKey, rsaPair.privateKey);

  // 5. Exportar llave pública (en claro, es pública)
  const publicKeyJwk = await exportPublicKeyJwk(rsaPair.publicKey);

  // 6. Calcular fingerprint de la publicKey para TOFU
  const kdfSaltB64 = bufToBase64(salt);
  const fingerprint = await publicKeyFingerprint(publicKeyJwk);

  // 7. Firma PoP: demuestra que poseemos la privateKey correspondiente
  //    a la publicKey que estamos registrando. El servidor verificará
  //    esta firma ANTES de almacenar nada.
  //    IMPORTANTE: normalizamos el email a lowercase + trim para que la
  //    firma coincida con la verificación server-side.
  const normalizedEmail = email.toLowerCase().trim();
  const popSignature = await signPop(
    rsaPair.privateKey,
    normalizedEmail,
    fingerprint,
    kdfSaltB64,
  );

  return {
    kdfSalt: kdfSaltB64,
    kdfIterations: KDF_ITERATIONS,
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
  newKdfSalt: string;
  newKdfIterations: number;
  newEncryptedPrivateKey: EncryptedPrivateKey;
  newPopSignature: string;
  // En memoria (actualizar el store):
  newMasterKey: CryptoKey;
}

export async function performPasswordRotation(params: {
  oldPassword: string;
  newPassword: string;
  email: string;
  currentKdfSaltB64: string;
  currentKdfIterations: number;
  currentEncryptedPrivateKeyJwkB64: string;
  currentPrivateKeyIvB64: string;
}): Promise<RotationArtifacts> {
  const {
    oldPassword,
    newPassword,
    email,
    currentKdfSaltB64,
    currentKdfIterations,
    currentEncryptedPrivateKeyJwkB64,
    currentPrivateKeyIvB64,
  } = params;

  // 1. Descifrar la privateKey JWK con la contraseña VIEJA.
  //    Obtenemos la JWK en claro (no una CryptoKey) porque necesitamos:
  //    (a) re-cifrarla con la nueva masterKey
  //    (b) construir la publicKey JWK desde ella (para fingerprint)
  //    (c) importarla temporalmente como RSA-PSS para firmar PoP
  const oldMasterKey = await deriveMasterKey(
    oldPassword,
    base64ToBuf(currentKdfSaltB64),
    currentKdfIterations,
  );
  const privateKeyJwkStr = await aesDecrypt(
    oldMasterKey,
    currentEncryptedPrivateKeyJwkB64,
    currentPrivateKeyIvB64,
  );
  const privateKeyJwk = JSON.parse(privateKeyJwkStr) as JsonWebKey;

  // 2. Generar nuevo salt y derivar nueva masterKey
  const newSalt = randomBytes(SALT_LENGTH);
  const newMasterKey = await deriveMasterKey(newPassword, newSalt);

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
    newKdfSalt: newKdfSaltB64,
    newKdfIterations: KDF_ITERATIONS,
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
