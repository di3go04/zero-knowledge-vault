/**
 * Middleware de tracking de uso por usuario.
 * Cuenta requests por endpoint para facturación y rate limiting adaptativo.
 */
import { NextRequest, NextResponse } from "next/server";

const usageMap = new Map<string, { requests: number; lastReset: number }>();
const RESET_INTERVAL = 60 * 60 * 1000; // 1 hora

export function trackUsage(req: NextRequest, userId: string): { requestsThisHour: number } {
  const now = Date.now();
  let entry = usageMap.get(userId);
  if (!entry || now - entry.lastReset > RESET_INTERVAL) {
    entry = { requests: 0, lastReset: now };
    usageMap.set(userId, entry);
  }
  entry.requests++;
  return { requestsThisHour: entry.requests };
}

export function getUsageStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const [userId, entry] of usageMap) {
    stats[userId] = entry.requests;
  }
  return stats;
}
