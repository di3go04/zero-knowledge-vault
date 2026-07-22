import { db } from "./db";
import { sendEmail } from "./email";
import { logger } from "./logger";

export interface DeadManSwitchCreate {
  userId: string;
  gracePeriodMs?: number;
  notifyEmail: string;
  message?: string;
}

export interface DeadManSwitchRecord {
  id: string;
  userId: string;
  enabled: boolean;
  gracePeriodMs: number;
  lastPulseAt: Date;
  notifyEmail: string;
  message: string | null;
  createdAt: Date;
  updatedAt: Date;
}

function toRecord(r: Awaited<ReturnType<typeof db.deadManSwitch.findUnique>>): DeadManSwitchRecord | null {
  if (!r) return null;
  return {
    id: r.id,
    userId: r.userId,
    enabled: r.enabled,
    gracePeriodMs: r.gracePeriodMs,
    lastPulseAt: r.lastPulseAt,
    notifyEmail: r.notifyEmail,
    message: r.message,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  };
}

export async function createSwitch(params: DeadManSwitchCreate): Promise<DeadManSwitchRecord> {
  const record = await db.deadManSwitch.create({
    data: {
      userId: params.userId,
      gracePeriodMs: params.gracePeriodMs ?? 86400000,
      notifyEmail: params.notifyEmail,
      message: params.message ?? null,
    },
  });
  const r = toRecord(record);
  if (!r) throw new Error("failed to create dead man switch");
  logger.info({ switchId: r.id, userId: r.userId }, "dead man switch created");
  return r;
}

export async function getSwitch(userId: string): Promise<DeadManSwitchRecord | null> {
  const record = await db.deadManSwitch.findUnique({ where: { userId } });
  return toRecord(record);
}

export async function pulse(userId: string): Promise<void> {
  await db.deadManSwitch.upsert({
    where: { userId },
    update: { lastPulseAt: new Date() },
    create: {
      userId,
      gracePeriodMs: 86400000,
      notifyEmail: "",
    },
  });
  logger.info({ userId }, "dead man switch pulsed");
}

export async function updateSwitch(
  userId: string,
  data: { enabled?: boolean; gracePeriodMs?: number; notifyEmail?: string; message?: string },
): Promise<DeadManSwitchRecord | null> {
  const record = await db.deadManSwitch.update({
    where: { userId },
    data: {
      ...(data.enabled !== undefined ? { enabled: data.enabled } : {}),
      ...(data.gracePeriodMs !== undefined ? { gracePeriodMs: data.gracePeriodMs } : {}),
      ...(data.notifyEmail !== undefined ? { notifyEmail: data.notifyEmail } : {}),
      ...(data.message !== undefined ? { message: data.message } : {}),
    },
  });
  return toRecord(record);
}

export async function deleteSwitch(userId: string): Promise<boolean> {
  try {
    await db.deadManSwitch.delete({ where: { userId } });
    logger.info({ userId }, "dead man switch deleted");
    return true;
  } catch {
    return false;
  }
}

export interface CheckResult {
  switchId: string;
  userId: string;
  triggered: boolean;
  reason: string;
}

export async function checkAllSwitches(): Promise<CheckResult[]> {
  const now = new Date();
  const active = await db.deadManSwitch.findMany({
    where: { enabled: true },
  });

  const results: CheckResult[] = [];

  for (const sw of active) {
    const elapsed = now.getTime() - sw.lastPulseAt.getTime();
    if (elapsed > sw.gracePeriodMs) {
      logger.warn(
        { switchId: sw.id, userId: sw.userId, elapsedMs: elapsed, graceMs: sw.gracePeriodMs },
        "dead man switch triggered",
      );

      const message = sw.message ?? "El Dead Man's Switch se ha activado. No se ha recibido el pulso a tiempo.";
      await sendEmail({
        to: sw.notifyEmail,
        subject: "[ZK Vault] Dead Man's Switch activado",
        text: `${message}\n\nÚltimo pulso: ${sw.lastPulseAt.toISOString()}\nPlazo configurado: ${sw.gracePeriodMs}ms`,
      });

      results.push({
        switchId: sw.id,
        userId: sw.userId,
        triggered: true,
        reason: `grace_period_exceeded: ${elapsed}ms > ${sw.gracePeriodMs}ms`,
      });
    } else {
      results.push({
        switchId: sw.id,
        userId: sw.userId,
        triggered: false,
        reason: "within_grace_period",
      });
    }
  }

  return results;
}
