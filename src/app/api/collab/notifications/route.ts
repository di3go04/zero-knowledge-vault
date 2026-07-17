import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const readParam = req.nextUrl.searchParams.get("read");
  const limit = Math.min(parseInt(req.nextUrl.searchParams.get("limit") ?? "50", 10), 100);

  const where: Record<string, unknown> = { userId };
  if (readParam === "true") where.read = true;
  else if (readParam === "false") where.read = false;

  const [notifications, total, unread] = await Promise.all([
    db.notification.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
    }),
    db.notification.count({ where: { userId } }),
    db.notification.count({ where: { userId, read: false } }),
  ]);

  return NextResponse.json({ notifications, total, unread });
}

export async function PATCH(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const notificationIds = body.ids as string[] | undefined;
  if (notificationIds && Array.isArray(notificationIds)) {
    await db.notification.updateMany({
      where: { id: { in: notificationIds }, userId },
      data: { read: true },
    });
  } else {
    await db.notification.updateMany({
      where: { userId, read: false },
      data: { read: true },
    });
  }

  return NextResponse.json({ markedRead: true });
}
