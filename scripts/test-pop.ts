/**
 * Test PoP — ejecuta el flujo cliente y servidor para debuguear
 * por qué la verificación PoP falla.
 */
import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;

// ----- Simular cliente -----
// 1. Generar par RSA-OAEP
const rsaPair = await subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
);

// 2. Exportar publicKey JWK
const pubJwk = await subtle.exportKey("jwk", rsaPair.publicKey);
console.log("publicKey JWK cruda:", JSON.stringify(pubJwk).slice(0, 200));

// 3. Canonicalizar (eliminar key_ops, ext, alg)
const {
  key_ops: _kp,
  ext: _ext,
  alg: _alg,
  ...material
} = pubJwk;
const sorted: Record<string, unknown> = {};
for (const k of Object.keys(material).sort()) {
  sorted[k] = (material as Record<string, unknown>)[k];
}
const canon = JSON.stringify(sorted);
console.log("canon (cliente):", canon.slice(0, 200));

// 4. Fingerprint
const hash = await subtle.digest("SHA-256", new TextEncoder().encode(canon));
const fp = Buffer.from(new Uint8Array(hash)).toString("hex");
console.log("fingerprint (cliente):", fp);

// 5. Firmar PoP — re-importar privateKey como RSA-PSS
const privJwk = await subtle.exportKey("jwk", rsaPair.privateKey);
const {
  key_ops: _kp2,
  ext: _ext2,
  alg: _alg2,
  ...privMaterial
} = privJwk;
const signingKey = await subtle.importKey(
  "jwk",
  privMaterial,
  { name: "RSA-PSS", hash: "SHA-256" },
  false,
  ["sign"],
);

const email = "alice@equipo.com";
const kdfSaltB64 = "AAECAwQFBgcICQ==";
const msg = `zk-vault-pop-v1\nemail=${email}\nfingerprint=${fp}\nsalt=${kdfSaltB64}`;
const sig = await subtle.sign(
  { name: "RSA-PSS", saltLength: 32 },
  signingKey,
  new TextEncoder().encode(msg),
);
const sigB64 = Buffer.from(new Uint8Array(sig)).toString("base64");
console.log("signature length:", sig.byteLength);

// ----- Simular servidor -----
// 1. El servidor recibe pubJwk (con key_ops, alg, ext) y lo sanitiza
const {
  key_ops: _skp,
  ext: _sext,
  alg: _salg,
  ...serverClean
} = pubJwk;

// 2. Re-canonicalizar en servidor
const serverSorted: Record<string, unknown> = {};
for (const k of Object.keys(serverClean).sort()) {
  serverSorted[k] = serverClean[k as keyof typeof serverClean];
}
const serverCanon = JSON.stringify(serverSorted);
console.log("canon (servidor):", serverCanon.slice(0, 200));

// 3. Fingerprint servidor
const serverHash = await subtle.digest("SHA-256", new TextEncoder().encode(serverCanon));
const serverFp = Buffer.from(new Uint8Array(serverHash)).toString("hex");
console.log("fingerprint (servidor):", serverFp);
console.log("fingerprints coinciden:", fp === serverFp);

// 4. Verificar PoP — importar publicKey como RSA-PSS (solo verify)
const verifyKey = await subtle.importKey(
  "jwk",
  serverClean,
  { name: "RSA-PSS", hash: "SHA-256" },
  true,
  ["verify"],
);

const serverMsg = `zk-vault-pop-v1\nemail=${email}\nfingerprint=${serverFp}\nsalt=${kdfSaltB64}`;
console.log("msg cliente:    ", msg);
console.log("msg servidor:   ", serverMsg);
console.log("msgs coinciden: ", msg === serverMsg);

const valid = await subtle.verify(
  { name: "RSA-PSS", saltLength: 32 },
  verifyKey,
  new Uint8Array(Buffer.from(sigB64, "base64")),
  new TextEncoder().encode(serverMsg),
);
console.log("PoP válida:", valid);
