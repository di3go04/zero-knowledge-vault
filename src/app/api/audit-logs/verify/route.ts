/**
 * GET /api/audit-logs/verify
 *
 * Recorre todos los audit logs del usuario y verifica que la cadena
 * de hashes SHA-256 es íntegra:
 *   - Cada log.prevHash === logHash del log anterior
 *   - Cada log.logHash === SHA-256(prevHash + encryptedEvent + eventIv + createdAt)
 *
 * Si cualquier hash no coincide, la cadena ha sido manipulada y se
 * reporta el índice del primer log corrupto.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { verifyChain } from "@/lib/crypto/hash-chain";
import { logger } from "@/lib/logger";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  try {
    // Fetch all logs ordered by creation time (ascending — chain order)
    const logs = await db.auditLog.findMany({
      where: { userId },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        prevHash: true,
        logHash: true,
        encryptedEvent: true,
        eventIv: true,
        createdAt: true,
      },
    });

    if (logs.length === 0) {
      return NextResponse.json({
        ok: true,
        totalLogs: 0,
        message: "No audit logs to verify.",
      });
    }

    // Verify the hash chain
    const result = await verifyChain(
      logs.map((l) => ({
        prevHash: l.prevHash,
        logHash: l.logHash,
        encryptedEvent: l.encryptedEvent,
        eventIv: l.eventIv,
        createdAt: l.createdAt.toISOString(),
      }))
    );

    if (result.ok) {
      logger.info({ userId, totalLogs: logs.length }, "audit chain verified");
      return NextResponse.json({
        ok: true,
        totalLogs: logs.length,
        firstBrokenIndex: null,
        message: "Chain is intact.",
      });
    }

    // Chain is broken — report the first broken entry
    const brokenIndex = result.firstBrokenIndex ?? 0;
    const brokenLog = logs[brokenIndex];
    logger.warn(
      { userId, brokenIndex, brokenLogId: brokenLog?.id },
      "audit chain verification FAILED"
    );
    return NextResponse.json({
      ok: false,
      totalLogs: logs.length,
      firstBrokenIndex: brokenIndex,
      brokenLogId: brokenLog?.id ?? null,
      message: `Chain broken at log #${brokenIndex + 1} (id: ${brokenLog?.id ?? "unknown"}).`,
    });
  } catch (err) {
    logger.error({ err, userId }, "failed to verify audit chain");
    return NextResponse.json(
      { error: "Error al verificar la cadena de auditoría" },
      { status: 500 }
    );
  }
}
