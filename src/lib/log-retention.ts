/**
 * log-retention.ts — Política de retención de logs (auto-purge 90 días).
 *
 */
import { db } from "@/lib/db";

const RETENTION_DAYS = 90;

export async function purgeOldLogs(): Promise<{ deleted: number }> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);

  const result = await db.auditLog.deleteMany({
    where: { createdAt: { lt: cutoff } },
  });

  return { deleted: result.count };
}
