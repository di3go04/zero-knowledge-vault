/**
 * Trial period logic — gestiona pruebas gratuitas de 14 días.
 */
import { db } from "./db";

const TRIAL_DAYS = 14;

export async function startTrial(userId: string): Promise<{ trialEndsAt: Date }> {
  const trialEndsAt = new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000);
  // En producción, guardar en BD cuando se añada campo trialEndsAt a User
  return { trialEndsAt };
}

export async function isTrialActive(userId: string): Promise<boolean> {
  // Cuando se añada trialEndsAt a User:
  // const user = await db.user.findUnique({ where: { id: userId } });
  // return user?.trialEndsAt ? user.trialEndsAt > new Date() : false;
  return false;
}

export async function getTrialDaysLeft(userId: string): Promise<number> {
  // const user = await db.user.findUnique({ where: { id: userId } });
  // if (!user?.trialEndsAt) return 0;
  // return Math.ceil((user.trialEndsAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
  return 0;
}
