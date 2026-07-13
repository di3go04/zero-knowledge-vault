/**
 * =====================================================================
 * forward-secrecy-shares.ts — Ephemeral ECDH para shares.
 * =====================================================================
 *
 * estático para envolver la llave AES, cada share genera un par
 * ECDH efímero. Si la privateKey RSA se compromete en el futuro,
 * los shares anteriores siguen siendo seguros porque la llave
 * efímera ya se destruyó.
 *
 * Esto es una preparación arquitectónica — la implementación
 * completa requiere cambios en el schema (campo ephemeralPublicKey
 * en SecretKeyShare) y en el flujo de share.
 * =====================================================================
 */

export interface EphemeralShareArtifacts {
  ephemeralPublicKey: JsonWebKey; // ECDH P-256 efímera — se envía al servidor
  wrappedAesKey: string; // AES key envuelta con ECDH shared secret
  wrappedIv: string;
}

/**
 * Envuelve una llave AES usando ECDH efímero en lugar de RSA-OAEP.
 *
 * Flujo:
 *   1. Generar par ECDH efímero
 *   2. Derivar shared secret: ephemeralPriv × recipientPub
 *   3. Cifrar AES key con el shared secret
 *   4. Enviar ephemeralPublicKey + ciphertext al servidor
 *   5. Destruir ephemeralPriv inmediatamente
 *
 * El destinatario desenvuelve derivando: recipientPriv × ephemeralPub
 */
export async function wrapWithEphemeralECDH(
  aesKeyRaw: ArrayBuffer,
  recipientPublicKeyECDH: CryptoKey,
): Promise<EphemeralShareArtifacts> {
  // 1. Generar par ECDH efímero
  const ephemeralPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );

  // 2. Derivar shared secret
  const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKeyECDH },
    ephemeralPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // 3. Cifrar la AES key con el shared secret
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    sharedKey,
    aesKeyRaw,
  );

  // 4. Exportar ephemeral publicKey
  const ephemeralPublicKey = await crypto.subtle.exportKey("jwk", ephemeralPair.publicKey);

  // 5. Destruir ephemeralPriv — Web Crypto no permite zeroing,
  //    pero desreferenciar permite al GC recolectar
  // (ephemeralPair.privateKey sale de scope aquí)

  return {
    ephemeralPublicKey,
    wrappedAesKey: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    wrappedIv: btoa(String.fromCharCode(...iv)),
  };
}
