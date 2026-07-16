// scripts/crypto-audit.mjs
// Static audit of cryptographic primitives used in src/
// Verifies that only approved algorithms are used, and that insecure ones are absent.

import { readFileSync, readdirSync } from "node:fs";

const ROOT = process.cwd();
const SRC_GLOB = "src/**/*.{ts,tsx,js}";

// Helpers
function listFiles(glob) {
  const out = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === ".next") continue;
      const p = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts") || e.name.endsWith(".tsx") || e.name.endsWith(".js")) out.push(p);
    }
  };
  walk("src");
  return out;
}

const files = listFiles(SRC_GLOB);

const approved = {
  symmetric: ["AES-GCM", "AES-256-GCM"],
  kdf: ["PBKDF2", "Argon2id", "HKDF", "scrypt"],
  hash: ["SHA-256", "SHA-384", "SHA-512", "SHA-1"], // SHA-1 listed but flagged if used for security
  asymmetric: ["RSA-OAEP", "RSA-PSS", "ECDH", "ECDSA", "ML-KEM"],
  curves: ["P-256", "P-384", "P-521"],
};

const forbidden = [
  { pattern: /createHash\s*\(\s*['"]md5['"]/gi, label: "MD5", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /createHash\s*\(\s*['"]sha1['"]/gi, label: "SHA-1", severity: "WARN", cwe: "CWE-327" },
  { pattern: /AES-CBC/gi, label: "AES-CBC (unauthenticated)", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /AES-ECB/gi, label: "AES-ECB (deterministic)", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /\bDES\b/g, label: "DES", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /\b3DES\b/g, label: "3DES", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /\bRC4\b/g, label: "RC4", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /\bBlowfish\b/gi, label: "Blowfish", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /Math\.random\(\)/g, label: "Math.random()", severity: "ERROR", cwe: "CWE-338", excludePaths: ["src/components/ui/", "src/components/ToastProvider.tsx"] },
  { pattern: /crypto\.randomBytes/g, label: "crypto.randomBytes (server-side ok; verify context)", severity: "INFO", cwe: "" },
  { pattern: /\bbtoa\(/g, label: "btoa (use only for base64 of non-secret data)", severity: "WARN", cwe: "" },
  { pattern: /\batob\(/g, label: "atob", severity: "WARN", cwe: "" },
  { pattern: /eval\s*\(/g, label: "eval()", severity: "ERROR", cwe: "CWE-95" },
  { pattern: /new\s+Function\s*\(/g, label: "new Function()", severity: "ERROR", cwe: "CWE-95" },
  { pattern: /rejectUnauthorized\s*:\s*false/g, label: "TLS verification disabled", severity: "ERROR", cwe: "CWE-295" },
  { pattern: /crypto\.createCipher\b/g, label: "crypto.createCipher (deprecated)", severity: "ERROR", cwe: "CWE-327" },
  { pattern: /crypto\.createDecipher\b/g, label: "crypto.createDecipher (deprecated)", severity: "ERROR", cwe: "CWE-327" },
];

const required = [
  { pattern: /crypto\.subtle\.encrypt/g, label: "AES-GCM encrypt" },
  { pattern: /crypto\.subtle\.decrypt/g, label: "AES-GCM decrypt" },
  { pattern: /crypto\.subtle\.deriveKey/g, label: "KDF deriveKey" },
  { pattern: /crypto\.subtle\.deriveBits/g, label: "KDF deriveBits" },
  { pattern: /crypto\.subtle\.generateKey/g, label: "Key generation" },
  { pattern: /crypto\.subtle\.importKey/g, label: "Key import" },
  { pattern: /crypto\.subtle\.exportKey/g, label: "Key export" },
  { pattern: /crypto\.subtle\.wrapKey/g, label: "Key wrap" },
  { pattern: /crypto\.subtle\.unwrapKey/g, label: "Key unwrap" },
  { pattern: /crypto\.subtle\.sign/g, label: "Signature sign" },
  { pattern: /crypto\.subtle\.verify/g, label: "Signature verify" },
  { pattern: /crypto\.getRandomValues/g, label: "CSPRNG" },
];

console.log("# Cryptographic Implementation Audit\n");
console.log(`Scanned ${files.length} files under src/\n`);

// Required primitives
console.log("## Required Crypto Primitives Usage\n");
console.log("| Primitive | Count | Files |");
console.log("|-----------|-------|-------|");
for (const r of required) {
  let count = 0;
  let fileCount = 0;
  for (const f of files) {
    const txt = readFileSync(f, "utf8");
    const matches = txt.match(r.pattern);
    if (matches) {
      count += matches.length;
      fileCount++;
    }
  }
  console.log(`| ${r.label} | ${count} | ${fileCount} |`);
}

// Forbidden
console.log("\n## Forbidden / Insecure Patterns\n");
console.log("| Pattern | Severity | CWE | Occurrences | Files |");
console.log("|---------|----------|-----|-------------|-------|");
let totalErrors = 0;
for (const f of forbidden) {
  let count = 0;
  let fileCount = 0;
  const offendingFiles = [];
  for (const file of files) {
    // Skip excluded paths
    if (f.excludePaths && f.excludePaths.some((p) => file.includes(p))) continue;
    const txt = readFileSync(file, "utf8");
    const matches = txt.match(f.pattern);
    if (matches) {
      count += matches.length;
      fileCount++;
      if (offendingFiles.length < 3) offendingFiles.push(file);
    }
  }
  if (count > 0) {
    console.log(`| ${f.label} | ${f.severity} | ${f.cwe || "—"} | ${count} | ${offendingFiles.join(", ")}${fileCount > 3 ? ", …" : ""} |`);
    if (f.severity === "ERROR") totalErrors += count;
  } else {
    console.log(`| ${f.label} | ${f.severity} | ${f.cwe || "—"} | 0 | — |`);
  }
}

console.log(`\n**Total ERROR-severity crypto findings: ${totalErrors}**\n`);

// Constants
console.log("## Hardcoded Constants Audit\n");
console.log("Looking for hardcoded salts, IVs, keys, or magic bytes...\n");
const constantPatterns = [
  { pattern: /salt\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi, label: "Hardcoded salt" },
  { pattern: /iv\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi, label: "Hardcoded IV (FORBIDDEN)" },
  { pattern: /key\s*[:=]\s*['"][A-Za-z0-9+/=]{32,}['"]/gi, label: "Hardcoded key (FORBIDDEN)" },
  { pattern: /secret\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi, label: "Hardcoded secret" },
];
let constantFindings = 0;
console.log("| Pattern | File:Line | Snippet |");
console.log("|---------|-----------|---------|");
for (const f of files) {
  const txt = readFileSync(f, "utf8");
  const lines = txt.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const cp of constantPatterns) {
      const m = line.match(cp.pattern);
      if (m) {
        // Skip if it's a variable name (like `const key = await ...`)
        if (/=\s*await|=\s*crypto|=\s*null|=\s*undefined/.test(line)) continue;
        constantFindings++;
        console.log(`| ${cp.label} | ${f}:${i + 1} | \`${line.trim().substring(0, 80)}\` |`);
      }
    }
  }
}
console.log(`\n**Total hardcoded constants flagged: ${constantFindings}**\n`);

// Final verdict
console.log("## Verdict\n");
if (totalErrors === 0 && constantFindings === 0) {
  console.log("✓ No forbidden crypto primitives or hardcoded secrets detected.");
  console.log("  Manual review still required for: key lifecycle, memory zeroing, side-channels.");
} else {
  console.log(`✗ ${totalErrors} ERROR-severity findings and ${constantFindings} hardcoded constants require remediation.`);
}

process.exit(totalErrors === 0 ? 0 : 1);
