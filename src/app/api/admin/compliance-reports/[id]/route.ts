import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const report = await db.complianceReport.findUnique({
    where: { id },
    include: {
      generatedBy: { select: { id: true, email: true, name: true } },
    },
  });
  if (!report) {
    return NextResponse.json({ error: "Compliance report not found" }, { status: 404 });
  }

  return NextResponse.json(report);
}
