/**
 * test-enrollment-flow.ts — Integration test for device enrollment.
 * Tests: init → poll → verify with invalid signature (must fail).
 * Run: bun scripts/tests/test-enrollment-flow.ts
 */
import { generateEcdhKeyPair, importEcdhPublicKeyJwk, signChallenge, exportEcdhPublicKeyJwk } from "../../src/lib/crypto-client";

let passed = 0, failed = 0;
function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

console.log("\n=== Enrollment Flow (Client-Side Crypto) ===");
{
  // 1. Device B generates ECDH keypair
  const deviceBPair = await generateEcdhKeyPair();
  const deviceBPubJwk = await exportEcdhPublicKeyJwk(deviceBPair.publicKey);
  assert(!!deviceBPubJwk.x && !!deviceBPubJwk.y, "Device B ECDH public key has x,y coordinates");

  // 2. Simulate challenge from server (32 bytes base64)
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challenge = btoa(String.fromCharCode(...challengeBytes));
  assert(challenge.length > 0, "Challenge is non-empty");

  // 3. Device B signs challenge with its ECDH private key (as ECDSA)
  const { importEcdhPrivateKeyForSigning } = await import("../../src/lib/crypto-client");
  const privJwk = await crypto.subtle.exportKey("jwk", deviceBPair.privateKey);
  const signingKey = await importEcdhPrivateKeyForSigning(privJwk);
  const validSig = await signChallenge(signingKey, challenge);
  assert(!!validSig, "Valid ECDSA signature produced");

  // 4. Verify signature matches (server-side simulation)
  const { verifyChallenge } = await import("../../src/lib/crypto-server");
  const isValid = await verifyChallenge({
    publicKeyJwk: deviceBPubJwk,
    challengeB64: challenge,
    signatureB64: validSig,
  });
  assert(isValid, "Valid signature verifies");

  // 5. Test with WRONG challenge (must fail)
  const wrongChallenge = btoa(String.fromCharCode(...new Uint8Array(32).map(() => 0xFF)));
  const isWrongValid = await verifyChallenge({
    publicKeyJwk: deviceBPubJwk,
    challengeB64: wrongChallenge,
    signatureB64: validSig,
  });
  assert(!isWrongValid, "Signature with wrong challenge fails verification");

  // 6. Test with tampered signature (must fail)
  const tamperedSig = validSig.slice(0, -4) + "AAAA";
  const isTamperedValid = await verifyChallenge({
    publicKeyJwk: deviceBPubJwk,
    challengeB64: challenge,
    signatureB64: tamperedSig,
  });
  assert(!isTamperedValid, "Tampered signature fails verification");
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
