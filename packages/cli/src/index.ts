#!/usr/bin/env bun
/**
 * @zk-vault/cli — CLI tool for Zero-Knowledge Vault.
 *
 * Usage:
 *   zk-vault login <email>
 *   zk-vault list
 *   zk-vault get <id>
 *   zk-vault create <title> <content>
 *   zk-vault share <secretId> <recipientEmail>
 *   zk-vault export <output-file>
 */
import { deriveMasterKey, aesEncrypt, aesDecrypt, pbkdf2LegacyParams, randomBytes, bufToBase64, base64ToBuf } from "@zk-vault/crypto";

const VAULT_URL = process.env.VAULT_URL || "http://localhost:3000";

async function promptPassword(): Promise<string> {
  process.stdout.write("Master password: ");
  const buf = new Uint8Array(1024);
  const n = await Bun.stdin.read(buf);
  process.stdout.write("\n");
  return new TextDecoder().decode(buf.subarray(0, n ?? 0)).trim();
}

async function login(email: string) {
  const password = await promptPassword();
  const res = await fetch(`${VAULT_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const data = await res.json();
  if (!data.sessionToken) {
    console.error("Login failed: no session token");
    process.exit(1);
  }
  const kdfParams = pbkdf2LegacyParams(base64ToBuf(data.kdfSalt), data.kdfIterations);
  const masterKey = await deriveMasterKey(password, kdfParams);
  // Save session for later commands
  const session = { sessionToken: data.sessionToken, email, masterKeyExport: bufToBase64(await crypto.subtle.exportKey("raw", masterKey)) };
  await Bun.write(".zk-vault-session.json", JSON.stringify(session));
  console.log(`✓ Logged in as ${email}`);
}

async function loadSession() {
  const raw = await Bun.file(".zk-vault-session.json").text();
  return JSON.parse(raw);
}

async function list() {
  const session = await loadSession();
  const res = await fetch(`${VAULT_URL}/api/secrets`, {
    headers: { Authorization: `Bearer ${session.sessionToken}` },
  });
  const data = await res.json();
  if (!data.secrets) { console.error("Failed to list:", data.error); process.exit(1); }
  console.log(`\n${data.secrets.length} secrets:\n`);
  for (const s of data.secrets) {
    console.log(`  ${s.id.slice(-8)}  ${s.ownedByMe ? "★" : "○"}  ${s.encryptedTitle.slice(0, 40)}...`);
  }
}

async function create(title: string, content: string) {
  const session = await loadSession();
  const enc = await aesEncrypt(session.masterKey, title);
  const encData = await aesEncrypt(session.masterKey, content);
  const res = await fetch(`${VAULT_URL}/api/secrets`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.sessionToken}` },
    body: JSON.stringify({ encryptedTitle: enc.ciphertext, titleIv: enc.iv, encryptedData: encData.ciphertext, dataIv: encData.iv, wrappedKeyForOwner: "" }),
  });
  const data = await res.json();
  if (data.secretId) console.log(`✓ Secret created: ${data.secretId}`);
  else console.error("Failed:", data.error);
}

const [cmd, ...args] = process.argv.slice(2);
switch (cmd) {
  case "login": await login(args[0]); break;
  case "list": await list(); break;
  case "create": await create(args[0], args[1]); break;
  default: console.log("Usage: zk-vault <login|list|create> [args]"); break;
}
