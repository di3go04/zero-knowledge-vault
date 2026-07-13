/**
 * Database migration script — para actualizaciones de schema.
 * Ejecuta: bun scripts/migrate.ts
 */
import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();

async function migrate() {
  console.log("🔄 Iniciando migración...");

  // Verificar conexión
  await db.$queryRaw`SELECT 1`;
  console.log("✅ BD conectada");

  // Verificar tablas
  const tables = await db.$queryRaw`
    SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_prisma%'
  ` as Array<{ name: string }>;

  console.log(`📋 Tablas existentes: ${tables.map((t) => t.name).join(", ")}`);

  // Verificar que todas las tablas esperadas existen
  const expected = ["User", "UserKeyMaterial", "Secret", "SecretKeyShare", "Device", "AuditLog", "SecretVersion", "SecretComment", "TeamVault", "TeamVaultMember"];
  const existing = tables.map((t) => t.name);
  const missing = expected.filter((e) => !existing.includes(e));

  if (missing.length > 0) {
    console.log(`⚠️  Tablas faltantes: ${missing.join(", ")}`);
    console.log("   Ejecuta: bunx prisma db push --force-reset");
  } else {
    console.log("✅ Todas las tablas existen");
  }

  // Contar registros
  for (const table of expected) {
    if (existing.includes(table)) {
      const count = await (db as any)[table.charAt(0).toLowerCase() + table.slice(1)].count();
      console.log(`   ${table}: ${count} registros`);
    }
  }

  console.log("✅ Migración verificada");
  await db.$disconnect();
}

migrate().catch(console.error);
