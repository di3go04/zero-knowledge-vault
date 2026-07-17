import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const action = req.nextUrl.searchParams.get("action");
  const resourceType = req.nextUrl.searchParams.get("resourceType");

  const where: Record<string, unknown> = { userId };
  if (action) where.action = action;
  if (resourceType) where.resourceType = resourceType;

  const [events, total] = await Promise.all([
    db.activityEvent.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.activityEvent.count({ where }),
  ]);

  return NextResponse.json({ events, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
