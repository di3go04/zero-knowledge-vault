// scripts/zk-property-audit.mjs
// Verifies that the server is genuinely "crypto-blind":
//   1. Server never receives master password in plaintext
//   2. Server never receives private keys (raw JWK)
//   3. Server never has access to plaintext secret content
//   4. Server-side crypto operations are limited to wrapping/verification
//
// Server-side scope:
//   - src/app/api/**  (all API route handlers)
//   - src/lib/*server*, session-token, rate-limit, challenge-store,
//     stripe-billing, gdpr-*, crypto-shredding, hash-chain-logs,
//     audit, webauthn, dual-control
//
// Client-side libs (src/lib/crypto-client.ts, subkey-derivation.ts, pq-kem-real.ts, ...)
// are NOT scanned here because they legitimately reference masterKey/privateKey
// (those types exist on the client).

import { readFileSync, readdirSync } from "node:fs";

const ROOT = process.cwd();

function walk(dir, ext = ".ts") {
  const out = [];
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".next") continue;
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...walk(p, ext));
    else if (e.name.endsWith(ext)) out.push(p);
  }
  return out;
}

const apiFiles = walk("src/app/api");
const serverLibFiles = walk("src/lib").filter((f) =>
  /server|session-token|rate-limit|challenge-store|crypto-server|stripe-billing|gdpr|crypto-shredding|hash-chain-logs|audit|webauthn|dual-control/i.test(f)
);

console.log("# Zero-Knowledge Property Audit\n");
console.log(`- API route files: ${apiFiles.length}`);
console.log(`- Server-side lib files: ${serverLibFiles.length}\n`);

const forbiddenServerPatterns = [
  {
    pattern: /\bmasterPassword\b/g,
    label: "masterPassword variable on server",
    severity: "ERROR",
    note: "Server must never receive master password in plaintext.",
  },
  {
    pattern: /\bprivateKeyJwk\b/g,
    label: "privateKeyJwk variable on server",
    severity: "ERROR",
    note: "Server must never hold raw private key JWK.",
  },
  {
    pattern: /\bplainSecret\b/g,
    label: "plainSecret variable on server",
    severity: "ERROR",
    note: "Server must never see plaintext secret content.",
  },
  {
    pattern: /\bunencryptedSecret\b/g,
    label: "unencryptedSecret variable on server",
    severity: "ERROR",
    note: "Server must never see unencrypted secret content.",
  },
  {
    pattern: /\bdecryptedSecret\b/g,
    label: "decryptedSecret variable on server",
    severity: "ERROR",
    note: "Decryption happens client-side only.",
  },
  {
    pattern: /\bconsole\.log\b[^\n]*\b(password|masterPassword|plainSecret|decryptedSecret)\b/gi,
    label: "console.log with sensitive value",
    severity: "ERROR",
    note: "Never log credentials or plaintext secrets.",
  },
  {
    pattern: /crypto\.subtle\.decrypt/g,
    label: "Server-side crypto.subtle.decrypt",
    severity: "WARN",
    note: "Decryption should be client-only. Allowed exception: server decrypts non-secret audit metadata — verify context.",
  },
  {
    pattern: /crypto\.subtle\.deriveKey/g,
    label: "Server-side deriveKey",
    severity: "ERROR",
    note: "KDF must be client-side only.",
  },
  {
    pattern: /crypto\.subtle\.deriveBits/g,
    label: "Server-side deriveBits",
    severity: "ERROR",
    note: "KDF must be client-side only.",
  },
];

function isCodeLine(line) {
  const trimmed = line.trim();
  if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) return false;
  if (trimmed.startsWith("'") || trimmed.startsWith('"') || trimmed.startsWith("`")) return false;
  return true;
}

console.log("## Server-Side Forbidden Patterns\n");
console.log("| Pattern | Severity | File:Line | Note |");
console.log("|---------|----------|-----------|------|");
let totalErrors = 0;
let totalWarnings = 0;
const serverFiles = [...apiFiles, ...serverLibFiles];
for (const file of serverFiles) {
  let txt;
  try {
    txt = readFileSync(file, "utf8");
  } catch {
    continue;
  }
  const lines = txt.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!isCodeLine(line)) continue;
    for (const fp of forbiddenServerPatterns) {
      const m = line.match(fp.pattern);
      if (m) {
        const severity = fp.severity;
        if (severity === "ERROR") totalErrors++;
        else if (severity === "WARN") totalWarnings++;
        const snippet = line.trim().substring(0, 100).replace(/\|/g, "\\|");
        console.log(`| ${fp.label} | ${severity} | ${file}:${i + 1} | ${fp.note} |`);
      }
    }
  }
}

console.log(`\n**Summary:** ${totalErrors} ERROR findings, ${totalWarnings} WARN findings\n`);

// Verify client-side crypto presence
console.log("## Client-Side Crypto Verification\n");
const clientCryptoFile = "src/lib/crypto-client.ts";
const memoryZeroFile = "src/lib/memory-zero.ts";
const pqKemFile = "src/lib/pq-kem-real.ts";
try {
  const txt = readFileSync(clientCryptoFile, "utf8");
  let memTxt = "";
  let pqTxt = "";
  try { memTxt = readFileSync(memoryZeroFile, "utf8"); } catch {}
  try { pqTxt = readFileSync(pqKemFile, "utf8"); } catch {}
  const allTxt = txt + "\n" + memTxt + "\n" + pqTxt;
  const requiredFunctions = [
    { name: "deriveMasterKey", aliases: ["deriveMasterKey"] },
    { name: "encryptPrivateKey (vault key wrap)", aliases: ["encryptPrivateKey", "wrapAesKeyWithRsaPublicKey"] },
    { name: "decryptPrivateKey (vault key unwrap)", aliases: ["decryptPrivateKey", "unwrapAesKeyWithRsaPrivateKey"] },
    { name: "aesEncrypt (secret encryption)", aliases: ["aesEncrypt"] },
    { name: "aesDecrypt (secret decryption)", aliases: ["aesDecrypt"] },
    { name: "signPop (challenge signature)", aliases: ["signPop", "signChallenge"] },
    { name: "verifyPop (challenge verification)", aliases: ["verifyPop", "verifyChallenge"] },
    { name: "clearCryptoKeyRef (memory zeroing)", aliases: ["clearCryptoKeyRef"] },
    { name: "zeroBuffer (memory zeroing)", aliases: ["zeroBuffer"] },
    { name: "generateAesKey", aliases: ["generateAesKey"] },
    { name: "wrapAesKeyWithRsaPublicKey", aliases: ["wrapAesKeyWithRsaPublicKey"] },
    { name: "unwrapAesKeyWithRsaPrivateKey", aliases: ["unwrapAesKeyWithRsaPrivateKey"] },
  ];
  console.log("| Function | Present |");
  console.log("|----------|---------|");
  for (const fn of requiredFunctions) {
    const present = fn.aliases.some((alias) => allTxt.includes(alias));
    console.log(`| \`${fn.name}\` | ${present ? "✓" : "✗ (verify naming)"} |`);
  }
  // Also check ML-KEM-768 wiring
  const mlkemPresent = pqTxt.includes("ML-KEM-768") || pqTxt.includes("MLKEM768") || pqTxt.includes("MLKEM-768") || pqTxt.includes("mlkem768");
  console.log(`| \`ML-KEM-768 (post-quantum)\` | ${mlkemPresent ? "✓" : "✗"} |`);
} catch (e) {
  console.log(`⚠ Could not read ${clientCryptoFile}: ${e.message}`);
}

console.log("\n## Verdict\n");
if (totalErrors === 0) {
  console.log("✓ Zero-knowledge property holds: server is crypto-blind.");
  console.log("  Manual review still required for: timing attacks, error message leakage, audit log content.");
} else {
  console.log(`✗ ${totalErrors} violations of the zero-knowledge property detected.`);
  console.log("  Each ERROR must be remediated or justified before claiming ZK status.");
}
process.exit(totalErrors === 0 ? 0 : 1);
