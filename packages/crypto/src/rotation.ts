/**
 * =====================================================================
 * key-rotation.ts — Rotación de wrappedKeys cuando se cambia el par RSA.
 * =====================================================================
 *
 * todas las wrappedKeys que apuntan a su publicKey vieja deben
 * re-envolverse con la nueva.
 *
 * IMPLEMENTACIÓN REAL: lee todas las SecretKeyShare donde el usuario
 * es recipient, desenvuelve cada una con la privateKey vieja,
 * y re-envuelve con la publicKey nueva. El servidor nunca ve la
 * llave AES en claro — todo ocurre en el cliente.
 *
 * NOTA: La rotación de par RSA NO está implementada en el flujo de
 * registro/login actual (solo se rota la contraseña maestra, que NO
 * cambia el par RSA). Esta función se usará cuando se implemente
 * la rotación de par RSA en el futuro. Es código funcional y listo.
 * =====================================================================
 */

export interface KeyRotationParams {
  oldPrivateKey: CryptoKey;
  newPublicKey: CryptoKey;
}

export interface KeyRotationResult {
  rotated: number;
  failed: number;
  rewrappedKeys: Array<{ shareId: string; newWrappedKey: string }>;
}

/**
 * Re-envuelve una wrappedKey individual.
 * Solo funciona en el cliente (usa Web Crypto).
 */
export async function rewrapSingleKey(
  oldWrappedKeyB64: string,
  oldPrivateKey: CryptoKey,
  newPublicKey: CryptoKey,
): Promise<string> {
  // 1. Desenvolver con privateKey vieja (RSA-OAEP decrypt)
  const rawAesBytes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    oldPrivateKey,
    Uint8Array.from(atob(oldWrappedKeyB64), (c) => c.charCodeAt(0)) as BufferSource,
  );

  // 2. Re-envolver con publicKey nueva (RSA-OAEP encrypt)
  const rewrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    newPublicKey,
    rawAesBytes,
  );

  return btoa(String.fromCharCode(...new Uint8Array(rewrapped)));
}

/**
 * Re-envuelve múltiples wrappedKeys en paralelo.
 * El cliente llama a esta función con todas las shares del usuario,
 * luego envía los resultados al servidor en batch.
 */
export async function rewrapAllKeys(
  shares: Array<{ shareId: string; wrappedKey: string }>,
  params: KeyRotationParams,
): Promise<KeyRotationResult> {
  const results = await Promise.allSettled(
    shares.map(async (share) => {
      const newWrappedKey = await rewrapSingleKey(
        share.wrappedKey,
        params.oldPrivateKey,
        params.newPublicKey,
      );
      return { shareId: share.shareId, newWrappedKey };
    }),
  );

  const rewrappedKeys: Array<{ shareId: string; newWrappedKey: string }> = [];
  let failed = 0;

  for (const result of results) {
    if (result.status === "fulfilled") {
      rewrappedKeys.push(result.value);
    } else {
      failed++;
    }
  }

  return {
    rotated: rewrappedKeys.length,
    failed,
    rewrappedKeys,
  };
}
