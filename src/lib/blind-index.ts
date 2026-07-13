/**
 * blind-index.ts — Búsqueda difusa cifrada con HMAC (blind index).
 *
 * sin que el servidor conozca el título.
 *
 * El cliente calcula HMAC-SHA256(título normalizado, blindKey) → hex.
 * Este hex se envía al servidor como `blindTitleIndex`.
 * El servidor puede comparar sin descifrar.
 */

/**
 * Genera un blind index para un título.
 * El blindKey se deriva de la masterKey del usuario.
 */
export async function generateBlindIndex(
  title: string,
  blindKey: CryptoKey,
): Promise<string> {
  // Normalizar: lowercase + trim + remove diacritics
  const normalized = title
    .toLowerCase()
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");

  // HMAC-SHA256 del título normalizado
  const data = new TextEncoder().encode(normalized);
  const signature = await crypto.subtle.sign(
    "HMAC",
    blindKey,
    data as BufferSource,
  );

  // Convertir a hex
  const bytes = new Uint8Array(signature);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}
