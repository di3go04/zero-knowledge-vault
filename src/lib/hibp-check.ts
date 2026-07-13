/**
 * hibp-check.ts — Check contra HaveIBeenPwned API (k-anonymity).
 *
 *
 * Usa el API de HaveIBeenPwned con k-anonymity:
 *   1. SHA-1 de la contraseña
 *   2. Enviar solo los primeros 5 hex chars al API
 *   3. Comparar localmente el resto del hash
 *
 * El servidor de HIBP nunca recibe la contraseña completa.
 */
import { createHash } from "node:crypto";

const HIBP_API = "https://api.pwnedpasswords.com/range";

export async function checkPasswordBreach(password: string): Promise<{
  breached: boolean;
  count: number;
}> {
  // SHA-1 de la contraseña
  const hash = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  // Pedir al API solo el prefijo (k-anonymity)
  try {
    const res = await fetch(`${HIBP_API}/${prefix}`, {
      headers: { "Add-Padding": "true" },
    });

    if (!res.ok) {
      return { breached: false, count: 0 }; // fail-open si API no responde
    }

    const text = await res.text();
    const lines = text.split("\n");

    for (const line of lines) {
      const [hashSuffix, countStr] = line.trim().split(":");
      if (hashSuffix === suffix) {
        return { breached: true, count: parseInt(countStr, 10) };
      }
    }

    return { breached: false, count: 0 };
  } catch {
    return { breached: false, count: 0 }; // fail-open
  }
}
