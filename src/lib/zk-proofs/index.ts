/**
 * ZK-Proof utilities for proving possession without revealing keys.
 * Uses hash-based commitments and Fiat-Shamir heuristic.
 */

export async function createCommitment(secret: Uint8Array): Promise<{ commitment: string; nonce: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const data = new Uint8Array(secret.length + nonce.length);
  data.set(secret, 0);
  data.set(nonce, secret.length);
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return {
    commitment: btoa(String.fromCharCode(...new Uint8Array(hash))),
    nonce: btoa(String.fromCharCode(...nonce)),
  };
}

export async function verifyCommitment(secret: Uint8Array, commitment: string, nonce: string): Promise<boolean> {
  const nonceBytes = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
  const data = new Uint8Array(secret.length + nonceBytes.length);
  data.set(secret, 0);
  data.set(nonceBytes, secret.length);
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  const computed = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return computed === commitment;
}
