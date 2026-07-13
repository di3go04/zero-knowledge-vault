/**
 * =====================================================================
 * shamir-recovery.ts — Shamir's Secret Sharing para recovery avanzado.
 * =====================================================================
 *
 * reconstruir. Permite recovery distribuido entre custodios de confianza.
 * =====================================================================
 */
import secrets from "secrets.js-grempe";

const DEFAULT_SHARES = 5;
const DEFAULT_THRESHOLD = 3;
const SHARE_BITS = 512; // 256 bits entropy en hex = 512 bits

export interface ShamirShare {
  share: string;
  index: number;
}

/**
 * Divide un secreto (hex string) en N partes usando Shamir's Secret
 * Sharing. Se necesitan K partes para reconstruir el secreto.
 *
 * Uso: dividir la recovery key (derivada de BIP-39) en 5 partes,
 * entregar 1 a cada custodio. Se necesitan 3 para recuperar.
 */
export function splitSecret(
  secretHex: string,
  shares: number = DEFAULT_SHARES,
  threshold: number = DEFAULT_THRESHOLD,
): ShamirShare[] {
  const sharesHex = secrets.share(secretHex, shares, threshold, SHARE_BITS);
  return sharesHex.map((share, i) => ({ share, index: i + 1 }));
}

/**
 * Reconstruye un secreto a partir de K o más partes.
 * Devuelve el secreto original en hex.
 */
export function reconstructSecret(shares: string[]): string {
  return secrets.combine(shares);
}

/**
 * Valida que una parte sea bien formada.
 */
export function isValidShare(share: string): boolean {
  try {
    const parsed = secrets.extractShareComponents(share);
    return parsed.data.length > 0;
  } catch {
    return false;
  }
}

/**
 * Genera N partes a partir de la entropy de la recovery key.
 * El secreto se pasa como hex string (256 bits = 64 hex chars).
 */
export function generateShamirShares(
  recoveryKeyHex: string,
  shares?: number,
  threshold?: number,
): { shares: ShamirShare[]; threshold: number; total: number } {
  const s = shares ?? DEFAULT_SHARES;
  const t = threshold ?? DEFAULT_THRESHOLD;
  const parts = splitSecret(recoveryKeyHex, s, t);
  return { shares: parts, threshold: t, total: s };
}
