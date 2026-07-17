import { db } from "@/lib/db";

export async function cleanupExpiredResources(): Promise<{ tempVaults: number; oneTimeShares: number; emailShares: number; notifications: number }> {
  const now = new Date();

  const [tempVaults, oneTimeShares, emailShares] = await Promise.all([
    db.tempVault.updateMany({
      where: { status: "active", expiresAt: { lte: now } },
      data: { status: "expired" },
    }),
    db.oneTimeShare.updateMany({
      where: { status: "active", expiresAt: { lte: now } },
      data: { status: "expired" },
    }),
    db.emailShare.updateMany({
      where: { status: "pending", expiresAt: { lte: now } },
      data: { status: "expired" },
    }),
  ]);

  const oldNotifications = await db.notification.deleteMany({
    where: { createdAt: { lte: new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000) } },
  });

  return {
    tempVaults: tempVaults.count,
    oneTimeShares: oneTimeShares.count,
    emailShares: emailShares.count,
    notifications: oldNotifications.count,
  };
}
