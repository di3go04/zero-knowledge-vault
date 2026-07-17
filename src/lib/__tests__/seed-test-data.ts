/**
 * Test data seeder for Zero-Knowledge Vault.
 * Run with: bun run src/lib/__tests__/seed-test-data.ts
 *
 * Seeds:
 * - Test users with known keys
 * - Sample secrets (encrypted)
 * - Device enrollments
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function seed() {
  console.log("🌱 Seeding test data...");

  // Create test users
  const alice = await prisma.user.upsert({
    where: { email: "alice@test.zkvault" },
    update: {},
    create: {
      email: "alice@test.zkvault",
      name: "Alice Test",
      userKeyMaterial: {
        create: {
          kdfAlgorithm: "pbkdf2",
          kdfIterations: 600000,
          kdfSalt: Buffer.from("test-salt-123456789012").toString("base64"),
          publicKeyJwk: JSON.stringify({}),
          publicKeyFingerprint: "test-fingerprint-alice",
          popSignature: "test-pop-signature",
        },
      },
    },
    include: { userKeyMaterial: true },
  });
  console.log(`  ✓ Created user: ${alice.email}`);

  const bob = await prisma.user.upsert({
    where: { email: "bob@test.zkvault" },
    update: {},
    create: {
      email: "bob@test.zkvault",
      name: "Bob Test",
      userKeyMaterial: {
        create: {
          kdfAlgorithm: "pbkdf2",
          kdfIterations: 600000,
          kdfSalt: Buffer.from("test-salt-123456789012").toString("base64"),
          publicKeyJwk: JSON.stringify({}),
          publicKeyFingerprint: "test-fingerprint-bob",
          popSignature: "test-pop-signature",
        },
      },
    },
    include: { userKeyMaterial: true },
  });
  console.log(`  ✓ Created user: ${bob.email}`);

  // Create test secrets
  const secret1 = await prisma.secret.create({
    data: {
      ownerId: alice.id,
      encryptedTitle: Buffer.from("encrypted-title-1").toString("base64"),
      titleIv: Buffer.from("title-iv-1").toString("base64"),
      encryptedData: Buffer.from("encrypted-data-1").toString("base64"),
      dataIv: Buffer.from("data-iv-1").toString("base64"),
    },
  });
  console.log(`  ✓ Created secret: ${secret1.id}`);

  // Share secret with Bob
  await prisma.secretKeyShare.create({
    data: {
      secretId: secret1.id,
      recipientId: bob.id,
      wrappedSymmetricKey: Buffer.from("wrapped-key").toString("base64"),
    },
  });
  console.log(`  ✓ Shared secret with ${bob.email}`);

  console.log("\n✅ Seeding complete!");
  console.log("\nTest credentials:");
  console.log("  Alice: alice@test.zkvault");
  console.log("  Bob:   bob@test.zkvault");

  await prisma.$disconnect();
}

seed().catch((e) => {
  console.error("❌ Seeding failed:", e);
  process.exit(1);
});
