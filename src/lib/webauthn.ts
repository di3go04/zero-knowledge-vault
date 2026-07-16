import { randomBytes } from "node:crypto";

export function generateChallenge(): string {
  return randomBytes(32).toString("base64url");
}

export interface WebAuthnCredential {
  credentialId: string;
  publicKey: string;
  counter: number;
}

export function verifyWebAuthnCounter(storedCounter: number, newCounter: number): boolean {
  return newCounter > storedCounter;
}
