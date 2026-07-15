import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { complianceReportSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const status = req.nextUrl.searchParams.get("status");
  const reportType = req.nextUrl.searchParams.get("reportType");

  const where: any = {};
  if (status && ["pending", "generating", "completed", "failed"].includes(status)) {
    where.status = status;
  }
  if (reportType) {
    where.reportType = reportType;
  }

  const reports = await db.complianceReport.findMany({
    where,
    include: {
      generatedBy: { select: { id: true, email: true, name: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ reports });
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

  const validation = validatePayload(complianceReportSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const report = await db.complianceReport.create({
    data: {
      reportType: validation.data.reportType,
      periodStart: new Date(validation.data.periodStart),
      periodEnd: new Date(validation.data.periodEnd),
      status: "pending",
      parameters: validation.data.parameters ?? null,
      generatedById: auth.userId,
    },
    include: {
      generatedBy: { select: { id: true, email: true, name: true } },
    },
  });

  setTimeout(async () => {
    try {
      const auditLogs = await db.auditLog.findMany({
        where: {
          createdAt: { gte: report.periodStart, lte: report.periodEnd },
        },
        orderBy: { createdAt: "desc" },
        take: 10000,
      });

      const emergencyGrants = await db.emergencyAccess.findMany({
        where: {
          createdAt: { gte: report.periodStart, lte: report.periodEnd },
        },
      });

      await db.complianceReport.update({
        where: { id: report.id },
        data: {
          status: "completed",
          resultData: JSON.stringify({
            generatedAt: new Date().toISOString(),
            summary: {
              totalAuditLogs: auditLogs.length,
              totalEmergencyGrants: emergencyGrants.length,
              periodStart: report.periodStart,
              periodEnd: report.periodEnd,
            },
            reportType: report.reportType,
          }),
          completedAt: new Date(),
        },
      });
    } catch {
      await db.complianceReport.update({
        where: { id: report.id },
        data: { status: "failed" },
      });
    }
  }, 0);

  return NextResponse.json(report, { status: 201 });
}
