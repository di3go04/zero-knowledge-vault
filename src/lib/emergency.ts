import { db } from "./db";

export async function processExpiredEmergencyAccess(): Promise<{ processed: number }> {
  const now = new Date();
  return { processed: 0 };
}

export async function checkEmergencyAccess(grantorId: string, granteeId: string): Promise<{
  canAccess: boolean;
  unlockAt: Date | null;
}> {
  return { canAccess: false, unlockAt: null };
}
