/**
 * Shamir's Secret Sharing (t-of-n) for enhanced recovery.
 * Uses secrets.js-grempe for the math.
 */
import secrets from "secrets.js-grempe";
export const DEFAULT_THRESHOLD = 3;
export const DEFAULT_SHARES = 5;
export function splitSecret(secret: string, shares = DEFAULT_SHARES, threshold = DEFAULT_THRESHOLD): string[] {
  return secrets.share(secrets.str2hex(secret), shares, threshold);
}
export function combineShares(shareParts: string[]): string {
  const hex = secrets.combine(shareParts);
  return secrets.hex2str(hex);
}
export function verifyShares(shareParts: string[]): boolean {
  try { const comb = secrets.combine(shareParts); return comb.length > 0; } catch { return false; }
}
