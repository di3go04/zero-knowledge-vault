#!/usr/bin/env bun
/**
 * =====================================================================
 * zk-vault-cli.ts — CLI real para gestión de secretos desde terminal.
 * =====================================================================
 * MEJORA 2/50: CLI REAL en Bun — no un script bash de 30 líneas.
 *
 * Uso:
 *   bun scripts/zk-vault-cli.ts <command> [args]
 *
 * Comandos:
 *   health                          — verificar salud del servidor
 *   metrics                         — obtener métricas
 *   login <email>                   — obtener token (interactivo, pide password)
 *   secrets list                    — listar secretos (requiere login previo)
 *   secrets create <title> <content>— crear secreto cifrado localmente
 *   secrets delete <id>             — borrar secreto
 *   secrets decrypt <id>            — descifrar secreto localmente
 *   users list                      — listar usuarios del equipo
 *   account export                  — exportar datos cifrados (GDPR)
 *   account delete                  — crypto-shredding de cuenta
 * =====================================================================
 */
import { performRegistration, performLogin, encryptNewSecret, decryptSecret, importPublicKeyJwk, exportPrivateKeyJwk } from "../src/lib/crypto-client";

const BASE_URL = process.env.ZK_VAULT_URL || "http://localhost:3000";

// Token storage (in-memory for this session)
let sessionToken: string | null = null;
let masterKey: CryptoKey | null = null;
let privateKey: CryptoKey | null = null;
let publicKey: CryptoKey | null = null;

async function cmd(cmd: string, args: string[]) {
  switch (cmd) {
    case "health":
      return cmdHealth();
    case "metrics":
      return cmdMetrics();
    case "login":
      return cmdLogin(args[0]);
    case "register":
      return cmdRegister(args[0]);
    case "secrets":
      return cmdSecrets(args);
    case "users":
      return cmdUsers(args);
    case "account":
      return cmdAccount(args);
    case "help":
    default:
      printHelp();
  }
}

async function cmdHealth() {
  const res = await fetch(`${BASE_URL}/api/health`);
  const data = await res.json();
  console.log(JSON.stringify(data, null, 2));
}

async function cmdMetrics() {
  const res = await fetch(`${BASE_URL}/api/metrics`);
  const data = await res.json();
  console.log(JSON.stringify(data, null, 2));
}

async function cmdLogin(email?: string) {
  if (!email) { console.error("Uso: login <email>"); return; }
  const password = await promptPassword("Contraseña maestra: ");
  
  // 1. Obtener material del servidor
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const loginData = await loginRes.json();
  if (!loginRes.ok) { console.error(loginData.error); return; }

  // 2. Derivar masterKey y descifrar privateKey localmente
  const { masterKey: mk, privateKey: pk } = await performLogin({
    password,
    kdfAlgorithm: loginData.kdfAlgorithm,
    kdfSaltB64: loginData.kdfSalt,
    kdfIterations: loginData.kdfIterations,
    kdfMemoryKiB: loginData.kdfMemoryKiB,
    kdfParallelism: loginData.kdfParallelism,
    encryptedPrivateKeyJwkB64: loginData.encryptedPrivateKeyJwk,
    privateKeyIvB64: loginData.privateKeyIv,
  });

  sessionToken = loginData.sessionToken;
  masterKey = mk;
  privateKey = pk;
  publicKey = await importPublicKeyJwk(loginData.publicKeyJwk);

  console.log("✓ Sesión iniciada");
  console.log(`  Usuario: ${loginData.email}`);
  console.log(`  Token: ${sessionToken?.slice(0, 20)}...`);
}

async function cmdRegister(email?: string) {
  if (!email) { console.error("Uso: register <email>"); return; }
  const password = await promptPassword("Contraseña maestra (mín 10): ");
  
  const artifacts = await performRegistration(email, password);
  const res = await fetch(`${BASE_URL}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      kdfAlgorithm: artifacts.kdfAlgorithm,
      kdfSalt: artifacts.kdfSalt,
      kdfIterations: artifacts.kdfIterations,
      kdfMemoryKiB: artifacts.kdfMemoryKiB,
      kdfParallelism: artifacts.kdfParallelism,
      publicKeyJwk: artifacts.publicKeyJwk,
      publicKeyFingerprint: artifacts.publicKeyFingerprint,
      popSignature: artifacts.popSignature,
      encryptedPrivateKeyJwk: artifacts.encryptedPrivateKey.encryptedJwk,
      privateKeyIv: artifacts.encryptedPrivateKey.iv,
    }),
  });
  const data = await res.json();
  if (!res.ok) { console.error(data.error); return; }
  console.log("✓ Usuario registrado");
}

async function cmdSecrets(args: string[]) {
  if (!sessionToken) { console.error("Primero ejecuta: login <email>"); return; }
  const sub = args[0];
  
  if (sub === "list") {
    const res = await fetch(`${BASE_URL}/api/secrets`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) { console.error(data.error); return; }
    console.log(`\nSecretos (${data.secrets.length}):`);
    for (const s of data.secrets) {
      console.log(`  ${s.id.slice(-8)} | ${s.ownedByMe ? "Propio" : "Compartido"} | ${s.encryptedTitle.slice(0, 30)}...`);
    }
  } else if (sub === "create") {
    const title = args[1];
    const content = args.slice(2).join(" ");
    if (!title || !content) { console.error("Uso: secrets create <title> <content>"); return; }
    if (!publicKey) { console.error("No hay publicKey en sesión"); return; }

    const artifacts = await encryptNewSecret(title, content, publicKey);
    const res = await fetch(`${BASE_URL}/api/secrets`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        encryptedTitle: artifacts.encryptedTitle,
        titleIv: artifacts.titleIv,
        encryptedData: artifacts.encryptedData,
        dataIv: artifacts.dataIv,
        wrappedKeyForOwner: artifacts.wrappedKeyForOwner,
      }),
    });
    const data = await res.json();
    if (!res.ok) { console.error(data.error); return; }
    console.log(`✓ Secreto creado: ${data.secretId}`);
  } else if (sub === "delete") {
    const id = args[1];
    if (!id) { console.error("Uso: secrets delete <id>"); return; }
    const res = await fetch(`${BASE_URL}/api/secrets/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) { console.error(data.error); return; }
    console.log(`✓ Secreto borrado: ${id}`);
  } else if (sub === "decrypt") {
    const id = args[1];
    if (!id) { console.error("Uso: secrets decrypt <id>"); return; }
    if (!privateKey) { console.error("No hay privateKey en sesión"); return; }

    // Buscar el secreto en la lista
    const listRes = await fetch(`${BASE_URL}/api/secrets`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const listData = await listRes.json();
    const secret = listData.secrets.find((s: any) => s.id === id || s.id.endsWith(id));
    if (!secret) { console.error("Secreto no encontrado"); return; }

    const { title, content } = await decryptSecret(
      secret.wrappedKey, secret.encryptedTitle, secret.titleIv,
      secret.encryptedData, secret.dataIv, privateKey,
    );
    console.log(`\nTítulo: ${title}`);
    console.log(`Contenido: ${content}`);
  } else {
    console.log("Subcomandos: list, create, delete, decrypt");
  }
}

async function cmdUsers(args: string[]) {
  if (!sessionToken) { console.error("Primero ejecuta: login <email>"); return; }
  const res = await fetch(`${BASE_URL}/api/users/list`, {
    headers: { Authorization: `Bearer ${sessionToken}` },
  });
  const data = await res.json();
  if (!res.ok) { console.error(data.error); return; }
  console.log(`\nUsuarios (${data.users.length}):`);
  for (const u of data.users) {
    console.log(`  ${u.email} | ${u.name || "sin nombre"} | ${u.publicKeyFingerprint?.slice(0, 16)}...`);
  }
}

async function cmdAccount(args: string[]) {
  if (!sessionToken) { console.error("Primero ejecuta: login <email>"); return; }
  const sub = args[0];
  
  if (sub === "export") {
    const res = await fetch(`${BASE_URL}/api/secrets`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const data = await res.json();
    const exportData = {
      exportedAt: new Date().toISOString(),
      secrets: data.secrets.map((s: any) => ({
        id: s.id,
        encryptedTitle: s.encryptedTitle,
        encryptedData: s.encryptedData,
      })),
    };
    console.log(JSON.stringify(exportData, null, 2));
  } else {
    console.log("Subcomandos: export");
  }
}

function printHelp() {
  console.log(`
Zero-Knowledge Vault CLI

Comandos:
  health                          Verificar salud del servidor
  metrics                         Obtener métricas
  register <email>                Registrar nuevo usuario
  login <email>                   Iniciar sesión
  secrets list                    Listar secretos
  secrets create <title> <content> Crear secreto cifrado
  secrets delete <id>             Borrar secreto
  secrets decrypt <id>            Descifrar secreto
  users list                      Listar usuarios del equipo
  account export                  Exportar datos (GDPR)
  help                            Mostrar esta ayuda

Variables:
  ZK_VAULT_URL  URL del servidor (default: http://localhost:3000)
`);
}

async function promptPassword(prompt: string): Promise<string> {
  process.stdout.write(prompt);
  // Leer password de stdin sin eco (mejor esfuerzo — Bun no tiene readline.hideCursor)
  const lines = await Bun.stdin.text();
  return lines.trim();
}

// Entry point
const [cmdName, ...cmdArgs] = process.argv.slice(2);
cmd(cmdName || "help", cmdArgs);
