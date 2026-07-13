/**
 * request-signing.ts — HMAC en cada petición autenticada.
 *
 *
 * Cada petición autenticada incluye:
 *   X-ZK-Timestamp: timestamp actual (epoch ms)
 *   X-ZK-Signature: HMAC-SHA256(sessionToken, method + path + timestamp)
 *
 * El servidor verifica que:
 *   1. El timestamp está dentro de ±5 minutos
 *   2. La firma coincide
 */

const MAX_SKEW_MS = 5 * 60 * 1000; // 5 minutos

/**
 * Cliente: firma una petición.
 */
export async function signRequest(
  method: string,
  path: string,
  sessionToken: string,
): Promise<{ timestamp: string; signature: string }> {
  const timestamp = Date.now().toString();
  const data = `${method.toUpperCase()}${path}${timestamp}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(sessionToken),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const signature = btoa(String.fromCharCode(...new Uint8Array(sig)));

  return { timestamp, signature };
}

/**
 * Servidor: verifica la firma de una petición.
 */
export async function verifyRequestSignature(
  method: string,
  path: string,
  timestamp: string,
  signature: string,
  sessionToken: string,
): Promise<boolean> {
  // Verificar timestamp
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts)) return false;
  if (Math.abs(Date.now() - ts) > MAX_SKEW_MS) return false;

  // Calcular firma esperada
  const data = `${method.toUpperCase()}${path}${timestamp}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(sessionToken),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const expectedSig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const expected = btoa(String.fromCharCode(...new Uint8Array(expectedSig)));

  // Constant-time comparison
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return result === 0;
}
