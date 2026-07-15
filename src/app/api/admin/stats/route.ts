import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const now = new Date();
  const last24h = new Date(now.getTime() - 24 * 3600_000);
  const last7d = new Date(now.getTime() - 7 * 24 * 3600_000);

  const [
    totalUsers,
    newUsers24h,
    activeDevices,
    totalSecrets,
    totalShares,
    pendingEmergencyAccess,
    pendingApprovalRequests,
    pendingBreakGlass,
    totalRoles,
    totalGroups,
    totalWebhooks,
    totalSsoProviders,
    totalDirectoryConnectors,
    auditLogs24h,
  ] = await Promise.all([
    db.user.count(),
    db.user.count({ where: { createdAt: { gte: last24h } } }),
    db.device.count({ where: { revokedAt: null } }),
    db.secret.count(),
    db.secretKeyShare.count(),
    db.emergencyAccess.count({ where: { status: { in: ["pending", "active"] } } }),
    db.approvalRequest.count({ where: { status: "pending" } }),
    db.breakGlassAccess.count({ where: { status: "pending" } }),
    db.role.count(),
    db.userGroup.count(),
    db.webhookConfig.count(),
    db.ssoProvider.count(),
    db.directoryConnector.count(),
    db.auditLog.count({ where: { createdAt: { gte: last24h } } }),
  ]);

  return NextResponse.json({
    totalUsers,
    newUsers24h,
    activeDevices,
    totalSecrets,
    totalShares,
    pendingEmergencyAccess,
    pendingApprovalRequests,
    pendingBreakGlass,
    totalRoles,
    totalGroups,
    totalWebhooks,
    totalSsoProviders,
    totalDirectoryConnectors,
    auditLogs24h,
    generatedAt: now,
  });
}
