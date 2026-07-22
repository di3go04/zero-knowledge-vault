import { describe, it, expect } from "vitest";
import {
  generateChallenge,
  consumeChallenge,
  generateRegistrationOptions,
  generateLoginOptions,
  verifyRegistrationCredential,
  verifyLoginAssertion,
} from "@/lib/webauthn";
import { CborDecoder } from "@/lib/cbor";

function b64url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

function ecPubKeyB64url(): string {
  const buf = new Uint8Array(65);
  buf[0] = 0x04;
  return Buffer.from(buf).toString("base64url");
}

describe("WebAuthn Challenge Store", () => {
  it("generates and consumes a challenge", () => {
    const ch = generateChallenge("user-1");
    expect(ch.challenge).toBeDefined();
    expect(ch.challenge.length).toBeGreaterThan(20);
    expect(ch.userId).toBe("user-1");
    expect(ch.used).toBe(false);

    const consumed = consumeChallenge(ch.challenge);
    expect(consumed).not.toBeNull();
    expect(consumed!.challenge).toBe(ch.challenge);
  });

  it("prevents double consumption", () => {
    const ch = generateChallenge("user-1");
    consumeChallenge(ch.challenge);
    expect(consumeChallenge(ch.challenge)).toBeNull();
  });

  it("returns null for unknown challenge", () => {
    expect(consumeChallenge("unknown")).toBeNull();
  });
});

describe("Registration Options", () => {
  it("generates valid WebAuthn registration options", () => {
    const opts = generateRegistrationOptions("uid-1", "a@b.com", "User", []);
    expect(opts.rp.name).toBe("Zero-Knowledge Vault");
    expect(opts.challenge).toBeDefined();
    expect(opts.pubKeyCredParams[0].alg).toBe(-7);
    expect(consumeChallenge(opts.challenge)).not.toBeNull();
  });

  it("includes excludeCredentials", () => {
    const opts = generateRegistrationOptions("uid-1", "a@b.com", "User", ["cred-1"]);
    expect(opts.excludeCredentials).toHaveLength(1);
    expect(opts.excludeCredentials[0].id).toBe("cred-1");
  });
});

describe("Login Options", () => {
  it("generates valid login options", () => {
    const opts = generateLoginOptions("uid-1", [
      { credentialId: "cred-1", transports: ["internal"] },
    ]);
    expect(opts.rpId).toBe("localhost");
    expect(opts.allowCredentials).toHaveLength(1);
    expect(opts.userVerification).toBe("required");
    expect(consumeChallenge(opts.challenge)).not.toBeNull();
  });
});

describe("CBOR Decoder", () => {
  it("decodes integers", () => {
    expect(new CborDecoder(new Uint8Array([0x01]).buffer).decodeAny()).toBe(1);
    expect(new CborDecoder(new Uint8Array([0x20]).buffer).decodeAny()).toBe(-1);
    expect(new CborDecoder(new Uint8Array([0x18, 24]).buffer).decodeAny()).toBe(24);
  });

  it("decodes byte strings", () => {
    const buf = new Uint8Array([0x43, 0x01, 0x02, 0x03]);
    const r = new CborDecoder(buf.buffer).decodeAny() as Uint8Array;
    expect(r).toBeInstanceOf(Uint8Array);
    expect(r.length).toBe(3);
    expect(r[0]).toBe(1);
  });

  it("decodes text strings", () => {
    expect(new CborDecoder(new Uint8Array([0x63, 0x66, 0x6f, 0x6f]).buffer).decodeAny()).toBe("foo");
  });

  it("decodes arrays", () => {
    const buf = new Uint8Array([0x83, 0x01, 0x02, 0x03]);
    const r = new CborDecoder(buf.buffer).decodeAny() as number[];
    expect(r).toEqual([1, 2, 3]);
  });

  it("decodes maps", () => {
    const buf = new Uint8Array([0xa2, 0x01, 0x02, 0x03, 0x04]);
    const r = new CborDecoder(buf.buffer).decodeAny() as Record<string, unknown>;
    expect(r["1"]).toBe(2);
    expect(r["3"]).toBe(4);
  });

  it("decodes COSE key-like structure", () => {
    // { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: h'01...20', -3: h'21...40' }
    const xBytes = new Uint8Array(32).fill(0x01);
    const yBytes = new Uint8Array(32).fill(0x21);
    const buf = new Uint8Array([
      0xa5, 0x01, 0x02, 0x03, 0x26,
      0x20, 0x01,
      0x21, 0x58, 0x20, ...xBytes,
      0x22, 0x58, 0x20, ...yBytes,
    ]);
    const r = new CborDecoder(buf.buffer).decodeAny() as Record<string, unknown>;
    expect(r["1"]).toBe(2);
    expect(r["3"]).toBe(-7);
    expect(r["-1"]).toBe(1);
    expect((r["-2"] as Uint8Array).length).toBe(32);
  });
});

describe("Verification error paths", () => {
  it("verifyRegistration rejects invalid clientDataJSON base64", () => {
    const r = verifyRegistrationCredential(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: "!!!", attestationObject: b64url("t") } },
      "c",
    );
    expect(typeof r).toBe("string");
  });

  it("verifyRegistration rejects wrong type", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.get", challenge: "c", origin: "http://localhost:3000" }));
    const r = verifyRegistrationCredential(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, attestationObject: b64url("t") } },
      "c",
    );
    expect(r).toContain("Unexpected type");
  });

  it("verifyRegistration rejects challenge mismatch", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.create", challenge: "wrong", origin: "http://localhost:3000" }));
    const r = verifyRegistrationCredential(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, attestationObject: b64url("t") } },
      "expected",
    );
    expect(r).toContain("Challenge mismatch");
  });

  it("verifyRegistration rejects origin mismatch", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.create", challenge: "c", origin: "https://evil.com" }));
    const r = verifyRegistrationCredential(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, attestationObject: b64url("t") } },
      "c",
    );
    expect(r).toContain("Origin mismatch");
  });

  it("verifyLogin rejects invalid clientDataJSON base64", () => {
    const r = verifyLoginAssertion(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: "!!!", authenticatorData: b64url("t"), signature: b64url("t") } },
      "c",
      { publicKey: ecPubKeyB64url(), counter: 0, credentialId: "t" },
    );
    expect(typeof r).toBe("string");
  });

  it("verifyLogin rejects wrong type", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.create", challenge: "c", origin: "http://localhost:3000" }));
    const r = verifyLoginAssertion(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, authenticatorData: b64url("t"), signature: b64url("t") } },
      "c",
      { publicKey: ecPubKeyB64url(), counter: 0, credentialId: "t" },
    );
    expect(r).toContain("Unexpected type");
  });

  it("verifyLogin rejects challenge mismatch", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.get", challenge: "wrong", origin: "http://localhost:3000" }));
    const r = verifyLoginAssertion(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, authenticatorData: b64url("t"), signature: b64url("t") } },
      "expected",
      { publicKey: ecPubKeyB64url(), counter: 0, credentialId: "t" },
    );
    expect(r).toContain("Challenge mismatch");
  });

  it("verifyLogin rejects origin mismatch", () => {
    const cd = b64url(JSON.stringify({ type: "webauthn.get", challenge: "c", origin: "https://evil.com" }));
    const r = verifyLoginAssertion(
      { id: "t", rawId: b64url("t"), response: { clientDataJSON: cd, authenticatorData: b64url("t"), signature: b64url("t") } },
      "c",
      { publicKey: ecPubKeyB64url(), counter: 0, credentialId: "t" },
    );
    expect(r).toContain("Origin mismatch");
  });
});
