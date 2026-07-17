/**
 * Client-side cache for public keys.
 *
 * Reduces API calls to /api/users/lookup by caching
 * fetched public keys in memory.
 *
 * Since public keys change only when the master password
 * is rotated, a session-scoped cache is sufficient.
 */

interface CachedKey {
  publicKeyJwk: string;
  fingerprint: string;
  fetchedAt: number;
}

const cache = new Map<string, CachedKey>();

const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

export function getCachedPublicKey(email: string): CachedKey | null {
  const entry = cache.get(email);
  if (!entry) return null;

  if (Date.now() - entry.fetchedAt > CACHE_TTL_MS) {
    cache.delete(email);
    return null;
  }

  return entry;
}

export function setCachedPublicKey(email: string, publicKeyJwk: string, fingerprint: string): void {
  cache.set(email, {
    publicKeyJwk,
    fingerprint,
    fetchedAt: Date.now(),
  });
}

export function clearPublicKeyCache(): void {
  cache.clear();
}

export function removeCachedPublicKey(email: string): void {
  cache.delete(email);
}
