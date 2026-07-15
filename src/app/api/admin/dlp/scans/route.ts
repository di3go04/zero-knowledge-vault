import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const ruleId = req.nextUrl.searchParams.get("ruleId");
  const resolved = req.nextUrl.searchParams.get("resolved");

  const where: Record<string, unknown> = {};
  if (ruleId) where.ruleId = ruleId;
  if (resolved === "true") where.resolved = true;
  else if (resolved === "false") where.resolved = false;

  const scans = await db.dlpScanResult.findMany({
    where,
    skip: offset,
    take: limit,
    include: { rule: { select: { name: true, severity: true } } },
    orderBy: { createdAt: "desc" },
  });

  const total = await db.dlpScanResult.count({ where });

  return NextResponse.json({ scans, total, offset, limit });
}
