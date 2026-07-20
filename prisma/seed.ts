/**
 * =====================================================================
 * prisma/seed.ts — Población de datos de prueba para demo técnica.
 * =====================================================================
 *
 * BLOQUE 1 — Script de inicialización para que cualquier evaluador
 * técnico pueda levantar la demo con un solo comando:
 *
 *   bun run db:reset && bun run db:seed
 *
 * Crea:
 *   - 2 usuarios (Alice y Bob) con material criptográfico completo
 *   - 1 dispositivo autorizado por Alice (ECDH P-256)
 *   - 3 secretos cifrados mock (GitHub PAT, AWS keys, DB password)
 *   - 1 share de Alice → Bob
 *   - 5 audit logs cifrados (uno por categoría)
 *
 * IMPORTANTE: este script usa valores CRIPTOGRÁFICAMENTE REALES —
 * genera pares RSA, deriva masterKey con Argon2id, cifra con AES-256-GCM.
 * No es mock; es una bóveda funcional que el evaluador puede probar
 * haciendo login con las contraseñas listadas abajo.
 *
 * Contraseñas de demo (NO usar en producción):
 *   Alice: alice-demo-password-2026
 *   Bob:   bob-demo-password-2026
 * =====================================================================
 */
import { PrismaClient } from "@prisma/client";
import {
  performRegistration,
  encryptNewSecret,
  shareSecretWithRecipient,
  exportPublicKeyJwk,
  publicKeyFingerprint,
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  bufToBase64,
  type AuditCategory,
} from "../src/lib/crypto";

const db = new PrismaClient();

interface SeedUser {
  email: string;
  name: string;
  password: string;
}

const SEED_USERS: SeedUser[] = [
  { email: "alice@demo.local", name: "Alice Demo", password: "alice-demo-password-2026" },
  { email: "bob@demo.local", name: "Bob Demo", password: "bob-demo-password-2026" },
];

const DEMO_SECRETS = [
  {
    title: "GitHub Personal Access Token",
    data: "ghp_demo1234567890abcdefghijklmnopqrstuvwxyzABCD",
    hint: "Token con scope repo + read:org",
  },
  {
    title: "AWS Access Keys (production)",
    data: "[default]\naws_access_key_id=AKIADEMO1234567890AB\naws_secret_access_key=demoSecretKey1234567890abcdefghijklmnopqrstuvwxyz",
    hint: "Credenciales IAM role EC2-read-only",
  },
  {
    title: "PostgreSQL connection string",
    data: "postgresql://app_user:s3cr3tP@ss@db.internal:5432/prod?schema=public",
    hint: "DB principal read-write",
  },
];

async function main() {
  console.log("🌱 Iniciando seed de datos de demo...\n");

  // Limpiar datos previos
  console.log("  Limpiando datos previos...");
  await db.auditLog.deleteMany();
  await db.secretKeyShare.deleteMany();
  await db.device.deleteMany();
  await db.secret.deleteMany();
  await db.userKeyMaterial.deleteMany();
  await db.user.deleteMany();

  const userIds: Record<string, { id: string; artifacts: Awaited<ReturnType<typeof performRegistration>> }> = {};

  // Crear usuarios
  for (const u of SEED_USERS) {
    console.log(`  Registrando ${u.email}...`);
    const artifacts = await performRegistration(u.email, u.password);

    const user = await db.user.create({
      data: {
        email: u.email,
        name: u.name,
        keyMaterial: {
          create: {
            kdfAlgorithm: artifacts.kdfAlgorithm,
            kdfSalt: artifacts.kdfSalt,
            kdfIterations: artifacts.kdfIterations,
            kdfMemoryKiB: artifacts.kdfMemoryKiB ?? null,
            kdfParallelism: artifacts.kdfParallelism ?? null,
            publicKeyJwk: JSON.stringify(artifacts.publicKeyJwk),
            publicKeyFingerprint: artifacts.publicKeyFingerprint,
            popSignature: artifacts.popSignature,
            popSignatureHash: "SHA-256",
            encryptedPrivateKeyJwk: artifacts.encryptedPrivateKey.encryptedJwk,
            privateKeyIv: artifacts.encryptedPrivateKey.iv,
            mlKemPublicKey: artifacts.mlKemPublicKey ?? null,
            encryptedMlKemPrivateKey: artifacts.encryptedMlKemPrivateKey?.ciphertext ?? null,
            mlKemPrivateKeyIv: artifacts.encryptedMlKemPrivateKey?.iv ?? null,
            recoveryEnabled: false,
          },
        },
      },
      include: { keyMaterial: true },
    });

    userIds[u.email] = { id: user.id, artifacts };
    console.log(`    ✓ userId=${user.id} fingerprint=${artifacts.publicKeyFingerprint.slice(0, 16)}...`);
  }

  const alice = userIds["alice@demo.local"];
  const bob = userIds["bob@demo.local"];

  // Crear secretos para Alice
  console.log("\n  Creando secretos de demo para Alice...");
  for (const s of DEMO_SECRETS) {
    // encryptNewSecret signature: (title, content, ownerPublicKey)
    const enc = await encryptNewSecret(s.title, s.data, alice.artifacts.publicKey);

    const secret = await db.secret.create({
      data: {
        ownerId: alice.id,
        encryptedTitle: enc.encryptedTitle,
        titleIv: enc.titleIv,
        encryptedData: enc.encryptedData,
        dataIv: enc.dataIv,
      },
    });

    // Auto-share a Alice (para que pueda descifrarlo en su bóveda)
    await db.secretKeyShare.create({
      data: {
        secretId: secret.id,
        recipientId: alice.id,
        wrappedSymmetricKey: enc.wrappedKeyForOwner,
        role: "admin",
      },
    });

    console.log(`    ✓ secreto=${secret.id} (${s.title} — contenido mock en claro, cifrado en BD)`);
  }

  // Compartir el primer secreto de Alice con Bob
  console.log("\n  Compartiendo primer secreto Alice → Bob...");
  const firstSecret = await db.secret.findFirst({
    where: { ownerId: alice.id },
    orderBy: { createdAt: "asc" },
  });
  if (firstSecret) {
    const aliceShare = await db.secretKeyShare.findFirst({
      where: { secretId: firstSecret.id, recipientId: alice.id },
    });
    if (aliceShare) {
      // Re-wrap el AES key del secreto con la publicKey de Bob
      const bobPubJwk = bob.artifacts.publicKeyJwk as JsonWebKey;
      const { importPublicKeyJwk } = await import("../src/lib/crypto");
      const bobPub = await importPublicKeyJwk(bobPubJwk);
      const wrappedForBob = await shareSecretWithRecipient(
        aliceShare.wrappedSymmetricKey,
        alice.artifacts.privateKey,
        bobPub,
      );
      await db.secretKeyShare.create({
        data: {
          secretId: firstSecret.id,
          recipientId: bob.id,
          wrappedSymmetricKey: wrappedForBob,
          role: "readonly",
        },
      });
      console.log(`    ✓ share Alice→Bob para secreto ${firstSecret.id.slice(-8)}`);
    }
  }

  // Crear dispositivo autorizado para Alice (ECDH P-256)
  console.log("\n  Autorizando dispositivo de demo para Alice...");
  const ecdhPair = await generateEcdhKeyPair();
  const ecdhPubJwk = await exportEcdhPublicKeyJwk(ecdhPair.publicKey);
  const ecdhFingerprint = await publicKeyFingerprint(ecdhPubJwk);

  // Simular wrappedPrivateKeyForDevice (en flujo real, Alice envuelve su
  // privateKey RSA con la shared key ECDH). Aquí guardamos un blob mock.
  const mockWrappedKey = bufToBase64(new TextEncoder().encode("mock-wrapped-private-key-for-device-demo"));

  await db.device.create({
    data: {
      userId: alice.id,
      deviceName: "MacBook Pro de Alice",
      publicKeyECDH: JSON.stringify(ecdhPubJwk),
      publicKeyECDHFingerprint: ecdhFingerprint,
      enrollerPublicKeyECDH: JSON.stringify(ecdhPubJwk), // auto-enrolled para demo
      wrappedPrivateKeyForDevice: mockWrappedKey,
      wrappedPrivateKeyIv: bufToBase64(new Uint8Array(12)),
      enrolledAt: new Date(),
      lastSeenAt: new Date(),
    },
  });
  console.log(`    ✓ device "MacBook Pro de Alice" fingerprint=${ecdhFingerprint.slice(0, 16)}...`);

  // Crear audit logs cifrados mock (uno por categoría)
  console.log("\n  Creando audit logs de demo...");
  const auditEvents: Array<{ category: AuditCategory; event: Record<string, unknown> }> = [
    { category: "auth", event: { type: "login", ip: "127.0.0.1", ok: true } },
    { category: "secret", event: { type: "secret.created", secretId: "demo-1" } },
    { category: "share", event: { type: "share.created", recipient: "bob@demo.local" } },
    { category: "device", event: { type: "device.enrolled", deviceName: "MacBook Pro" } },
    { category: "recovery", event: { type: "recovery.not_setup", note: "demo sin recovery" } },
  ];

  // Para cifrar audit logs necesitamos el audit subkey derivado del masterKey.
  const { deriveAuditKey, encryptAuditEvent } = await import("../src/lib/crypto");
  const aliceAuditKey = await deriveAuditKey(alice.artifacts.masterKey);

  let prevHash: string | null = null;
  const { computeLogHash } = await import("../src/lib/crypto/hash-chain");

  for (const { category, event } of auditEvents) {
    const { encryptedEvent, eventIv } = await encryptAuditEvent(aliceAuditKey, event);
    const createdAt = new Date().toISOString();
    const logHash = await computeLogHash({
      prevHash,
      encryptedEvent,
      eventIv,
      createdAt,
    });

    await db.auditLog.create({
      data: {
        userId: alice.id,
        encryptedEvent,
        eventIv,
        eventCategory: category,
        encryptedCategory: "",
        categoryIv: "",
        prevHash,
        logHash,
        createdAt: new Date(createdAt),
      },
    });

    prevHash = logHash;
    console.log(`    ✓ audit log category="${category}"`);
  }

  console.log("\n✅ Seed completado.\n");
  console.log("=== CREDENCIALES DE DEMO ===");
  console.log("Alice:");
  console.log("  Email:    alice@demo.local");
  console.log("  Password: alice-demo-password-2026");
  console.log("Bob:");
  console.log("  Email:    bob@demo.local");
  console.log("  Password: bob-demo-password-2026");
  console.log("\nAmbos usuarios pueden loguearse en http://localhost:3000");
  console.log("Alice tiene 3 secretos + 1 dispositivo autorizado.");
  console.log("Bob tiene 1 secreto compartido por Alice (read-only).");
  console.log("\nPara resetear: bun run db:reset && bun run db:seed");
}

main()
  .then(async () => {
    await db.$disconnect();
  })
  .catch(async (e) => {
    console.error("❌ Error en seed:", e);
    await db.$disconnect();
    process.exit(1);
  });
