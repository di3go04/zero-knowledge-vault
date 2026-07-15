import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const status = req.nextUrl.searchParams.get("status");

  const monitor = await db.uptimeMonitor.findUnique({ where: { id } });
  if (!monitor) {
    return NextResponse.json({ error: "Monitor not found" }, { status: 404 });
  }

  const where: Record<string, unknown> = { monitorId: id };
  if (status && ["up", "down", "degraded"].includes(status)) where.status = status;

  const checks = await db.healthCheckLog.findMany({
    where,
    skip: offset,
    take: limit,
    orderBy: { checkedAt: "desc" },
  });

  const total = await db.healthCheckLog.count({ where });

  const stats = await db.healthCheckLog.groupBy({
    by: ["status"],
    where: { monitorId: id },
    _count: { status: true },
  });

  return NextResponse.json({ checks, total, offset, limit, stats });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const monitor = await db.uptimeMonitor.findUnique({ where: { id } });
  if (!monitor) {
    return NextResponse.json({ error: "Monitor not found" }, { status: 404 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const check = await db.healthCheckLog.create({
    data: {
      monitorId: id,
      status: body.status || "up",
      statusCode: body.statusCode || null,
      responseTimeMs: body.responseTimeMs || null,
      errorMessage: body.errorMessage || null,
    },
  });

  return NextResponse.json(check, { status: 201 });
}
