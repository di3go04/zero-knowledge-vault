export async function deriveKeyPbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number = 600000
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password.normalize("NFC")),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function deriveKeyArgon2id(_password: string, _salt: Uint8Array): Promise<CryptoKey> {
  // In browser, this runs via Web Worker + hash-wasm
  // In Node.js, this would use a native binding
  throw new Error("Argon2id requires Web Worker environment");
}
