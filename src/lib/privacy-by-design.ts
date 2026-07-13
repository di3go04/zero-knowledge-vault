/**
 * privacy-by-design.ts — Minimización de datos en respuestas API.
 *
 *
 * Filtra las respuestas API para no incluir más datos de los necesarios.
 * Por ejemplo, GET /api/users/list no devuelve publicKeyJwk completo
 * (solo fingerprint), y GET /api/secrets no incluye wrappedKey de otros
 * destinatarios.
 */

/**
 * Filtra una lista de usuarios para devolver solo lo necesario.
 */
export function sanitizeUserList(users: any[]): any[] {
  return users.map((u) => ({
    id: u.id,
    email: u.email,
    name: u.name,
    publicKeyFingerprint: u.publicKeyFingerprint ?? null,
    // NO incluir: publicKeyJwk, keyMaterial completo, etc.
  }));
}

/**
 * Filtra un usuario individual para lookup.
 */
export function sanitizeUserLookup(user: any): any {
  return {
    userId: user.id,
    email: user.email,
    name: user.name,
    publicKeyJwk: user.publicKeyJwk, // necesario para wrap
    publicKeyFingerprint: user.publicKeyFingerprint,
    // NO incluir: encryptedPrivateKeyJwk, kdfSalt, etc.
  };
}

/**
 * Filtra una lista de secretos.
 */
export function sanitizeSecretList(secrets: any[]): any[] {
  return secrets.map((s) => ({
    id: s.id,
    ownerId: s.ownerId,
    ownerEmail: s.ownerEmail,
    ownerName: s.ownerName,
    ownedByMe: s.ownedByMe,
    encryptedTitle: s.encryptedTitle,
    titleIv: s.titleIv,
    encryptedData: s.encryptedData,
    dataIv: s.dataIv,
    wrappedKey: s.wrappedKey,
    createdAt: s.createdAt,
    sharedAt: s.sharedAt,
    // NO incluir: wrappedKeys de otros, detalles internos, etc.
  }));
}
