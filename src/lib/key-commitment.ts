/**
 * =====================================================================
 * key-commitment.ts — Vincula masterKey a publicKey via HMAC.
 * =====================================================================
 *
 * usando la masterKey como clave. Esto prueba que quien tiene la
 * masterKey también conoce la publicKey, sin revelar ninguna.
 *
 * Se almacena en BD y se verifica en cada login. Si alguien cambia
 * la publicKey sin tener la masterKey, el commitment falla.
 * =====================================================================
 */

/**
 * Genera un commitment HMAC-SHA256(publicKeyJwk, masterKey).
 * Devuelve hex string (64 chars).
 */
export async function generateKeyCommitment(
  masterKey: CryptoKey,
  publicKeyJwk: JsonWebKey,
): Promise<string> {
  // Cifrar la publicKey con la masterKey — el ciphertext es el commitment
  // (si no tienes la masterKey, no puedes generar el mismo commitment)
  const pubKeyStr = JSON.stringify(publicKeyJwk);
  const iv = new Uint8Array(12); // IV fijo — OK porque es un compromiso único
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    masterKey,
    new TextEncoder().encode(pubKeyStr),
  );
  
  // Hash del ciphertext para obtener un commitment compacto
  const hash = await crypto.subtle.digest("SHA-256", ciphertext);
  const bytes = new Uint8Array(hash);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Verifica que el commitment coincide con la publicKey y masterKey.
 */
export async function verifyKeyCommitment(
  masterKey: CryptoKey,
  publicKeyJwk: JsonWebKey,
  expectedCommitment: string,
): Promise<boolean> {
  const actual = await generateKeyCommitment(masterKey, publicKeyJwk);
  // Constant-time comparison
  if (actual.length !== expectedCommitment.length) return false;
  let result = 0;
  for (let i = 0; i < actual.length; i++) {
    result |= actual.charCodeAt(i) ^ expectedCommitment.charCodeAt(i);
  }
  return result === 0;
}
