import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const config = await db.directorySyncConfig.findUnique({ where: { id } });
  if (!config) {
    return NextResponse.json({ error: "Directory sync config not found" }, { status: 404 });
  }

  const logs = await db.directorySyncLog.findMany({
    where: { configId: id },
    skip: offset,
    take: limit,
    orderBy: { createdAt: "desc" },
  });

  const total = await db.directorySyncLog.count({ where: { configId: id } });

  return NextResponse.json({ logs, total, offset, limit });
}
