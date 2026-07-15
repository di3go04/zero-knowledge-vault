import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { eDiscoverySearchSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const exports = await db.eDiscoveryExport.findMany({
    skip: offset,
    take: limit,
    orderBy: { createdAt: "desc" },
  });

  const total = await db.eDiscoveryExport.count();

  return NextResponse.json({ exports, total, offset, limit });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(eDiscoverySearchSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const { targetEmail, targetUserId, reason, dataTypes } = validation.data;

  let targetId = targetUserId;
  if (targetEmail && !targetId) {
    const user = await db.user.findUnique({ where: { email: targetEmail } });
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }
    targetId = user.id;
  }
  if (!targetId) {
    return NextResponse.json({ error: "targetUserId or targetEmail required" }, { status: 400 });
  }

  const exportData: Record<string, unknown> = {};
  const includeAll = dataTypes.includes("audit-logs");
  if (dataTypes.includes("audit-logs") || includeAll) {
    exportData.auditLogs = await db.auditLog.findMany({ where: { userId: targetId }, orderBy: { createdAt: "desc" } });
  }
  if (dataTypes.includes("devices") || includeAll) {
    exportData.devices = await db.device.findMany({ where: { userId: targetId } });
  }
  if (dataTypes.includes("shares") || includeAll) {
    exportData.shares = await db.secretKeyShare.findMany({ where: { recipientId: targetId } });
  }
  if (dataTypes.includes("user-profile") || includeAll) {
    exportData.userProfile = await db.user.findUnique({
      where: { id: targetId },
      include: { keyMaterial: true, scimUser: true },
    });
  }
  if (dataTypes.includes("secrets") || includeAll) {
    exportData.secrets = await db.secret.findMany({ where: { ownerId: targetId } });
  }
  if (dataTypes.includes("sessions") || includeAll) {
    exportData.sessions = await db.device.findMany({ where: { userId: targetId, revokedAt: null } });
  }

  const exportRecord = await db.eDiscoveryExport.create({
    data: {
      requestedById: auth.userId,
      targetUserId: targetId,
      reason,
      dataTypes: JSON.stringify(dataTypes),
      status: "completed",
      exportData: JSON.stringify(exportData),
      completedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 3600_000),
    },
  });

  return NextResponse.json(exportRecord, { status: 201 });
}
