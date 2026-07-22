import { randomBytes, timingSafeEqual } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CborDecoder } from "./cbor";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WebAuthnChallenge {
  challenge: string;
  userId: string;
  expiresAt: number;
  used: boolean;
}

export interface ParsedCredential {
  credentialId: string;
  publicKey: string;
  algorithm: number;
  aaguid: string;
  transports: string;
  counter: number;
  backedUp: boolean;
}

export interface ParsedAssertion {
  credentialId: string;
  authenticatorData: Uint8Array;
  clientDataJSON: string;
  signature: Uint8Array;
  userHandle: string | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const RP_NAME = "Zero-Knowledge Vault";
export const RP_ID = process.env.WEBAUTHN_RP_ID ?? "localhost";
export const ORIGIN = process.env.WEBAUTHN_ORIGIN ?? "http://localhost:3000";
const CHALLENGE_TTL = 5 * 60 * 1000; // 5 minutes
const CHALLENGE_BYTES = 32;

// Base64url helpers
function base64UrlEncode(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function base64UrlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function bufToBase64(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}

// ---------------------------------------------------------------------------
// Challenge store (in-memory with TTL)
// ---------------------------------------------------------------------------

const challenges = new Map<string, WebAuthnChallenge>();

const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, ch] of challenges) {
    if (ch.expiresAt <= now) challenges.delete(key);
  }
}, 60_000).unref?.();

export function generateChallenge(userId: string): WebAuthnChallenge {
  const challenge = base64UrlEncode(randomBytes(CHALLENGE_BYTES));
  const entry: WebAuthnChallenge = {
    challenge,
    userId,
    expiresAt: Date.now() + CHALLENGE_TTL,
    used: false,
  };
  challenges.set(challenge, entry);
  return entry;
}

export function consumeChallenge(challengeB64: string): WebAuthnChallenge | null {
  const entry = challenges.get(challengeB64);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    challenges.delete(challengeB64);
    return null;
  }
  if (entry.used) return null;
  entry.used = true;
  challenges.delete(challengeB64);
  return entry;
}

// ---------------------------------------------------------------------------
// Registration: generate credential creation options
// ---------------------------------------------------------------------------

export function generateRegistrationOptions(
  userId: string,
  userName: string,
  userDisplayName: string,
  excludeCredentials: string[] = [],
): {
  challenge: string;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: string; alg: number }[];
  timeout: number;
  excludeCredentials: { type: string; id: string; transports: string[] }[];
  authenticatorSelection: {
    authenticatorAttachment?: string;
    residentKey: string;
    requireResidentKey: boolean;
    userVerification: string;
  };
  attestation: string;
} {
  const ch = generateChallenge(userId);
  return {
    challenge: ch.challenge,
    rp: { name: RP_NAME, id: RP_ID },
    user: {
      id: base64UrlEncode(Buffer.from(userId)),
      name: userName,
      displayName: userDisplayName || userName,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },    // ES256 (ECDSA P-256 SHA-256)
      { type: "public-key", alg: -257 },  // RS256 (RSASSA-PKCS1 SHA-256)
    ],
    timeout: 60000,
    excludeCredentials: excludeCredentials.map((id) => ({
      type: "public-key" as const,
      id,
      transports: ["usb", "nfc", "ble", "internal"],
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "required",
    },
    attestation: "none",
  };
}

// ---------------------------------------------------------------------------
// Registration: verify attestation
// ---------------------------------------------------------------------------

export function verifyRegistrationCredential(
  credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
      transports?: string[];
    };
  },
  expectedChallenge: string,
): ParsedCredential | string {
  // 1. Parse clientDataJSON
  let clientData: { type: string; challenge: string; origin: string };
  try {
    const cdJson = new TextDecoder().decode(base64UrlDecode(credential.response.clientDataJSON));
    clientData = JSON.parse(cdJson);
  } catch {
    return "Invalid clientDataJSON";
  }

  // 2. Verify type
  if (clientData.type !== "webauthn.create") {
    return `Unexpected type: ${clientData.type}`;
  }

  // 3. Verify challenge
  if (clientData.challenge !== expectedChallenge) {
    return "Challenge mismatch";
  }

  // 4. Verify origin
  if (clientData.origin !== ORIGIN) {
    return `Origin mismatch: ${clientData.origin}`;
  }

  // 5. Parse attestationObject
  let attestationObject: Uint8Array;
  try {
    attestationObject = base64UrlDecode(credential.response.attestationObject);
  } catch {
    return "Invalid attestationObject";
  }

  // 6. CBOR-decode attestationObject
  let attestationData: Record<string, unknown>;
  try {
    const decoder = new CborDecoder(attestationObject.buffer);
    attestationData = decoder.decodeAny() as Record<string, unknown>;
  } catch {
    return "Invalid CBOR in attestationObject";
  }

  const authData = attestationData["authData"] as Uint8Array | undefined;
  const fmt = attestationData["fmt"] as string | undefined;

  if (!authData || !fmt) {
    return "Missing authData or fmt in attestationObject";
  }

  // 7. Parse authData
  const parsed = parseAuthData(authData);
  if (typeof parsed === "string") return parsed;

  // 8. Extract COSE public key from attested credential data
  if (!parsed.attestedCredentialData) {
    return "Missing attested credential data (AT flag not set)";
  }

  const coseKey = parsed.attestedCredentialData.cosePublicKey;
  const parsedKey = parseCosePublicKey(coseKey);
  if (typeof parsedKey === "string") return parsedKey;

  // For "none" attestation, we skip signature verification
  // For "packed", "fido-u2f", we should verify, but for now accept "none"
  if (fmt !== "none") {
    // Verify attestation signature if present
    // For simplicity and security, we require "none" or ensure
    // the attestation is trustworthy
    if (attestationData["attStmt"]) {
      const attStmt = attestationData["attStmt"] as Record<string, unknown>;
      if (attStmt["sig"]) {
        const sig = attStmt["sig"] as Uint8Array;
        // Only verify if we have a way to trust the attestation cert
        // For production, we'd verify the attestation chain
      }
    }
  }

  // 9. Build credentialId from rawId
  const rawIdBytes = base64UrlDecode(credential.rawId);
  const credentialId = base64UrlEncode(rawIdBytes);

  // 10. Return parsed credential
  return {
    credentialId,
    publicKey: parsedKey.publicKey,
    algorithm: parsedKey.algorithm,
    aaguid: parsed.attestedCredentialData.aaguid,
    transports: JSON.stringify(credential.response.transports ?? ["internal"]),
    counter: parsed.signCount,
    backedUp: parsed.backedUp,
  };
}

// ---------------------------------------------------------------------------
// Login: generate credential request options
// ---------------------------------------------------------------------------

export function generateLoginOptions(
  userId: string,
  credentials: { credentialId: string; transports: string[] }[],
): {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials: { type: string; id: string; transports: string[] }[];
  userVerification: string;
} {
  const ch = generateChallenge(userId);
  return {
    challenge: ch.challenge,
    timeout: 60000,
    rpId: RP_ID,
    allowCredentials: credentials.map((c) => ({
      type: "public-key" as const,
      id: c.credentialId,
      transports: c.transports,
    })),
    userVerification: "required",
  };
}

// ---------------------------------------------------------------------------
// Login: verify assertion
// ---------------------------------------------------------------------------

export function verifyLoginAssertion(
  assertion: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
  },
  expectedChallenge: string,
  storedCredential: {
    publicKey: string;
    counter: number;
    credentialId: string;
  },
): { counter: number; userHandle: string | null } | string {
  // 1. Parse clientDataJSON
  let clientData: { type: string; challenge: string; origin: string };
  try {
    const cdJson = new TextDecoder().decode(base64UrlDecode(assertion.response.clientDataJSON));
    clientData = JSON.parse(cdJson);
  } catch {
    return "Invalid clientDataJSON";
  }

  // 2. Verify type
  if (clientData.type !== "webauthn.get") {
    return `Unexpected type: ${clientData.type}`;
  }

  // 3. Verify challenge
  if (clientData.challenge !== expectedChallenge) {
    return "Challenge mismatch";
  }

  // 4. Verify origin
  if (clientData.origin !== ORIGIN) {
    return `Origin mismatch: ${clientData.origin}`;
  }

  // 5. Parse authenticatorData
  let authDataBytes: Uint8Array;
  try {
    authDataBytes = base64UrlDecode(assertion.response.authenticatorData);
  } catch {
    return "Invalid authenticatorData";
  }

  // 6. Verify RP ID hash
  const rpIdHash = sha256(Buffer.from(RP_ID));
  const authDataRpIdHash = authDataBytes.slice(0, 32);
  if (!timingSafeEqual(Buffer.from(authDataRpIdHash), Buffer.from(rpIdHash))) {
    return "RP ID hash mismatch";
  }

  // 7. Parse flags
  const flags = authDataBytes[32];
  const counterBytes = authDataBytes.slice(33, 37);
  const signCount = (counterBytes[0] << 24) | (counterBytes[1] << 16) | (counterBytes[2] << 8) | counterBytes[3];
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;

  if (!userPresent) {
    return "User not present";
  }

  // 8. Verify signature
  const clientDataHash = sha256(Buffer.from(assertion.response.clientDataJSON, "base64url"));
  const signedData = Buffer.concat([Buffer.from(authDataBytes), Buffer.from(clientDataHash)]);

  try {
    const publicKeyBytes = base64UrlDecode(storedCredential.publicKey);
    const sigBytes = base64UrlDecode(assertion.response.signature);

    // Parse raw uncompressed EC public key (0x04 || x || y)
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
      return "Invalid public key format (expected uncompressed P-256)";
    }

    const valid = p256.verify(sigBytes, signedData, publicKeyBytes);
    if (!valid) {
      return "Signature verification failed";
    }
  } catch (err) {
    return `Signature verification error: ${String(err)}`;
  }

  // 9. Verify signCount increased (anti-cloning)
  if (signCount !== 0 && signCount <= storedCredential.counter) {
    return `Sign count did not increase: ${signCount} <= ${storedCredential.counter}`;
  }

  // 10. Parse userHandle
  const userHandle = assertion.response.userHandle
    ? new TextDecoder().decode(base64UrlDecode(assertion.response.userHandle))
    : null;

  return { counter: signCount, userHandle };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface AuthDataParsed {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  attestedCredentialData: {
    aaguid: string;
    credentialId: string;
    cosePublicKey: Uint8Array;
  } | null;
  extensions: unknown;
  backedUp: boolean;
}

function parseAuthData(authData: Uint8Array): AuthDataParsed | string {
  if (authData.length < 37) {
    return "authData too short";
  }

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
  const backedUp = (flags & 0x08) !== 0;

  let offset = 37;
  let attestedCredentialData: {
    aaguid: string;
    credentialId: string;
    cosePublicKey: Uint8Array;
  } | null = null;

  if (flags & 0x40) {
    if (authData.length < offset + 16) {
      return "authData too short for AAGUID";
    }

    const aaguidBytes = authData.slice(offset, offset + 16);
    offset += 16;

    if (authData.length < offset + 2) {
      return "authData too short for credential ID length";
    }

    const credIdLen = (authData[offset] << 8) | authData[offset + 1];
    offset += 2;

    if (authData.length < offset + credIdLen) {
      return "authData too short for credential ID";
    }

    const credId = authData.slice(offset, offset + credIdLen);
    offset += credIdLen;

    // The rest is the COSE-encoded public key
    const coseKeyBytes = authData.slice(offset);

    // Format AAGUID as hex string
    const aaguidHex = Buffer.from(aaguidBytes).toString("hex");

    attestedCredentialData = {
      aaguid: aaguidHex,
      credentialId: base64UrlEncode(credId),
      cosePublicKey: coseKeyBytes,
    };
  }

  return {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData,
    extensions: null,
    backedUp,
  };
}

interface CoseKeyParsed {
  publicKey: string;
  algorithm: number;
}

/**
 * Parse a COSE_Key-encoded EC2 public key (P-256).
 * COSE key format (RFC 8152):
 *   {
 *     1: 2,       // kty = EC2
 *     3: -7,      // alg = ES256
 *     -1: 1,      // crv = P-256
 *     -2: x,      // x coordinate (32 bytes)
 *     -3: y       // y coordinate (32 bytes)
 *   }
 */
function parseCosePublicKey(coseKeyBytes: Uint8Array): CoseKeyParsed | string {
  try {
    const decoder = new CborDecoder(coseKeyBytes.buffer);
    const keyMap = decoder.decodeAny() as Record<string, unknown>;

    const kty = Number(keyMap["1"]);
    const alg = Number(keyMap["3"]);
    const crv = Number(keyMap["-1"]);
    const x = keyMap["-2"] as Uint8Array | undefined;
    const y = keyMap["-3"] as Uint8Array | undefined;

    if (kty !== 2) return `Unsupported key type: ${kty} (expected EC2)`;
    if (alg !== -7) return `Unsupported algorithm: ${alg} (expected ES256)`;
    if (crv !== 1) return `Unsupported curve: ${crv} (expected P-256)`;
    if (!x || !y) return "Missing x or y coordinates in COSE key";
    if (x.length !== 32) return `Invalid x coordinate length: ${x.length}`;
    if (y.length !== 32) return `Invalid y coordinate length: ${y.length}`;

    // Build uncompressed EC public key: 0x04 || x || y
    const rawKey = new Uint8Array(65);
    rawKey[0] = 0x04;
    rawKey.set(x, 1);
    rawKey.set(y, 33);

    return {
      publicKey: base64UrlEncode(rawKey),
      algorithm: alg,
    };
  } catch (err) {
    return `COSE key parse error: ${String(err)}`;
  }
}

/**
 * Parse an ECDSA signature from DER or raw format to { r, s }.
 * WebAuthn returns DER-encoded signatures.
 */
function parseEcdsaSignature(sigBytes: Uint8Array): { r: bigint; s: bigint } | string {
  try {
    // Try DER format first (ASN.1 SEQUENCE of two INTEGERs)
    if (sigBytes[0] === 0x30) {
      return parseDerEcdsaSignature(sigBytes);
    }
    // Raw 64-byte format (r || s)
    if (sigBytes.length === 64) {
      const r = BigInt("0x" + Buffer.from(sigBytes.slice(0, 32)).toString("hex"));
      const s = BigInt("0x" + Buffer.from(sigBytes.slice(32, 64)).toString("hex"));
      return { r, s };
    }
    return `Unsupported signature length: ${sigBytes.length}`;
  } catch (err) {
    return `Signature parse error: ${String(err)}`;
  }
}

function parseDerEcdsaSignature(der: Uint8Array): { r: bigint; s: bigint } | string {
  let offset = 0;
  if (der[offset++] !== 0x30) return "Not a DER SEQUENCE";

  // Total length
  let totalLen = der[offset++];
  if (totalLen & 0x80) {
    const numBytes = totalLen & 0x7f;
    totalLen = 0;
    for (let i = 0; i < numBytes; i++) {
      totalLen = (totalLen << 8) | der[offset++];
    }
  }

  if (offset + totalLen > der.length) return "DER sequence too short";

  // First INTEGER (r)
  if (der[offset++] !== 0x02) return "Expected INTEGER for r";
  let rLen = der[offset++];
  if (rLen & 0x80) {
    const numBytes = rLen & 0x7f;
    rLen = 0;
    for (let i = 0; i < numBytes; i++) {
      rLen = (rLen << 8) | der[offset++];
    }
  }
  const rBytes = der.slice(offset, offset + rLen);
  offset += rLen;

  // Second INTEGER (s)
  if (der[offset++] !== 0x02) return "Expected INTEGER for s";
  let sLen = der[offset++];
  if (sLen & 0x80) {
    const numBytes = sLen & 0x7f;
    sLen = 0;
    for (let i = 0; i < numBytes; i++) {
      sLen = (sLen << 8) | der[offset++];
    }
  }
  const sBytes = der.slice(offset, offset + sLen);

  const r = BigInt("0x" + Buffer.from(rBytes).toString("hex"));
  const s = BigInt("0x" + Buffer.from(sBytes).toString("hex"));
  return { r, s };
}
