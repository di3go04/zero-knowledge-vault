/**
 * rtbf-verify.ts — Right to be Forgotten: verificación post-delete.
 *
 */
import { db } from "@/lib/db";

export async function verifyUserDeleted(userId: string): Promise<{
  verified: boolean;
  details: Record<string, number>;
}> {
  const details: Record<string, number> = {};

  details.users = await db.user.count({ where: { id: userId } });
  details.keyMaterial = await db.userKeyMaterial.count({ where: { userId } });
  details.secrets = await db.secret.count({ where: { ownerId: userId } });
  details.secretKeyShares = await db.secretKeyShare.count({ where: { recipientId: userId } });
  details.devices = await db.device.count({ where: { userId } });
  details.auditLogs = await db.auditLog.count({ where: { userId } });
  details.secretComments = await db.secretComment.count({ where: { authorId: userId } });
  details.teamVaultMembers = await db.teamVaultMember.count({ where: { userId } });

  const verified = Object.values(details).every((c) => c === 0);

  return { verified, details };
}
