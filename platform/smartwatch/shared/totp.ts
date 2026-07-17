// TOTP (RFC 6238) — Time-based One-Time Password generator
//
// Shared implementation usable on both WatchOS and WearOS.
// The smartwatch only needs to generate TOTP codes from a shared secret;
// it never stores master keys or performs vault operations.

/**
 * Generates a TOTP code from a base32-encoded secret.
 * Default: 6 digits, 30-second window, SHA-1 (RFC 4226).
 *
 * @param secretB32 - Base32-encoded shared secret
 * @param timestamp - Unix timestamp in seconds (default: Date.now() / 1000)
 * @param digits    - Number of digits (6 or 8)
 * @returns TOTP code as a zero-padded string
 */
export function generateTOTP(
  secretB32: string,
  timestamp: number = Math.floor(Date.now() / 1000),
  digits: 6 | 8 = 6,
): string {
  const key = base32Decode(secretB32);
  const counter = BigInt(Math.floor(timestamp / 30));
  const counterBytes = bigIntToBytes(counter, 8);

  // HMAC-SHA1
  const hmac = hmacSha1(key, counterBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;

  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = code % Math.pow(10, digits);
  return otp.toString().padStart(digits, "0");
}

// -------------------------------------------------------------------------
// Minimal HMAC-SHA1 implementation (no external deps for watch platform)
// -------------------------------------------------------------------------

function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  if (key.length > blockSize) {
    key = sha1(key);
  }
  if (key.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(key);
    key = padded;
  }

  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = key[i] ^ 0x5c;
    iKeyPad[i] = key[i] ^ 0x36;
  }

  const inner = sha1(concat(iKeyPad, message));
  const outer = sha1(concat(oKeyPad, inner));
  return outer;
}

function sha1(data: Uint8Array): Uint8Array {
  // Placeholder — real implementation uses platform-native crypto.
  // On WatchOS: CommonCrypto (CCHmac)
  // On WearOS: javax.crypto.Mac
  // For the stub, we return a fixed-size array.
  return new Uint8Array(20);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a);
  result.set(b, a.length);
  return result;
}

// -------------------------------------------------------------------------
// Base32 decoding (RFC 4648)
// -------------------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(encoded: string): Uint8Array {
  const cleaned = encoded.replace(/[= \t\n\r]/g, "").toUpperCase();
  const bits: number[] = [];
  for (const ch of cleaned) {
    const val = BASE32_ALPHABET.indexOf(ch);
    if (val === -1) continue;
    for (let i = 4; i >= 0; i--) {
      bits.push((val >> i) & 1);
    }
  }
  const bytes: number[] = [];
  for (let i = 0; i + 7 < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | bits[i + j];
    }
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
}

function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

export function getTOTPState(secretB32: string) {
  const now = Math.floor(Date.now() / 1000);
  const code = generateTOTP(secretB32, now);
  const timeRemaining = 30 - (now % 30);
  return { code, timeRemaining };
}
