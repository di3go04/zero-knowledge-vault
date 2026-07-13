export interface SSHKeyPair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

export async function generateSSHKeyPair(keyType: "ed25519" | "rsa" = "ed25519"): Promise<SSHKeyPair> {
  if (keyType === "ed25519") {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const pubRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
    const privJwk = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pubRaw)));
    return {
      publicKey: `ssh-ed25519 ${pubB64} zk-vault`,
      privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(privJwk)))}\n-----END OPENSSH PRIVATE KEY-----`,
      fingerprint: await sshFingerprint(pubB64),
    };
  }
  throw new Error("RSA SSH keys not yet supported");
}

async function sshFingerprint(pubKeyB64: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pubKeyB64));
  return `SHA256:${btoa(String.fromCharCode(...new Uint8Array(hash)))}`;
}
