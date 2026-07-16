/**
 * Side-channel protection: constant-time operations and timing-safe comparisons.
 */

export function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export function addRandomDelay(minMs: number = 0, maxMs: number = 50): Promise<void> {
  // Use crypto.getRandomValues for cryptographically-suitable jitter.
  // (Math.random is not a CSPRNG; even for timing jitter, prefer crypto.)
  const rand = new Uint32Array(1);
  crypto.getRandomValues(rand);
  const normalized = rand[0] / 0x100000000; // [0, 1)
  const delay = minMs + normalized * (maxMs - minMs);
  return new Promise(resolve => setTimeout(resolve, delay));
}
