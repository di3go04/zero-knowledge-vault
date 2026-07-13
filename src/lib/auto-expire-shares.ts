/**
 * auto-expire-shares.ts — Expiración automática de shares.
 *
 *
 */
import { db } from "@/lib/db";

/**
 * Elimina shares expirados. Debe llamarse periódicamente (cron).
 */
export async function purgeExpiredShares(): Promise<{ deleted: number }> {
  // Buscar shares read-only creados hace >30 días sin ser vistos
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  
  const result = await db.secretKeyShare.deleteMany({
    where: {
      createdAt: { lt: thirtyDaysAgo },
      seenAt: null,
      role: "readonly", // solo expirar shares read-only no vistos
    },
  });

  return { deleted: result.count };
}

/**
 * Marca un share como expirado (soft delete — se borra después).
 */
export async function expireShare(secretId: string, recipientId: string): Promise<void> {
  await db.secretKeyShare.delete({
    where: {
      secretId_recipientId: { secretId, recipientId },
    },
  });
}
