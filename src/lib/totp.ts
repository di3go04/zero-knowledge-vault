/**
 * totp.ts — TOTP 2FA (RFC 6238) con segundo factor de 6 dígitos.
 *
 *
 * El usuario escanea un QR con Google Authenticator/Authy.
 * En cada login, después de derivar masterKey, debe introducir
 * el código TOTP de 6 dígitos.
 */
import { createHmac } from "node:crypto";

const TOTP_PERIOD = 30; // segundos
const TOTP_DIGITS = 6;

/**
 * Genera un secreto TOTP aleatorio (base32, 20 bytes = 32 chars).
 */
export function generateTotpSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * Genera el código TOTP actual para un secreto.
 */
export function generateTotpCode(secret: string, timestamp: number = Date.now()): string {
  const counter = Math.floor(timestamp / 1000 / TOTP_PERIOD);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));

  const key = base32Decode(secret);
  const hmac = createHmac("sha1", key).update(buffer).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
}

/**
 * Verifica un código TOTP con ventana de ±1 período (30s).
 */
export function verifyTotpCode(secret: string, code: string): boolean {
  const now = Date.now();
  for (let offset = -1; offset <= 1; offset++) {
    const expected = generateTotpCode(secret, now + offset * TOTP_PERIOD * 1000);
    if (expected === code) return true;
  }
  return false;
}

/**
 * Genera la URL otpauth:// para QR code.
 */
export function getTotpUrl(secret: string, email: string, issuer: string = "ZK Vault"): string {
  return `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}

// Base32 helpers
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let result = "";
  let buffer = 0;
  let bitsLeft = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      result += BASE32_ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1f];
      bitsLeft -= 5;
    }
  }
  if (bitsLeft > 0) {
    result += BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f];
  }
  return result;
}

function base32Decode(str: string): Buffer {
  str = str.replace(/=+$/, "").toUpperCase();
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const char of str) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) continue;
    buffer = (buffer << 5) | value;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bytes.push((buffer >> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
    }
  }
  return Buffer.from(bytes);
}
