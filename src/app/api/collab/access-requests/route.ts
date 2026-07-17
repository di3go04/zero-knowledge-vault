import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { accessRequestSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const requesterId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(accessRequestSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { secretId, reason } = validation.data;

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId === requesterId) return NextResponse.json({ error: "Eres el owner de este secreto" }, { status: 400 });

  const existing = await db.accessRequest.findFirst({
    where: { secretId, requesterId, status: "pending" },
  });
  if (existing) return NextResponse.json({ error: "Ya tienes una solicitud pendiente para este secreto" }, { status: 409 });

  const request = await db.accessRequest.create({
    data: { secretId, requesterId, reason },
  });

  await db.notification.create({
    data: {
      userId: secret.ownerId,
      type: "access-request",
      title: "Solicitud de acceso a un secreto",
      body: reason ?? null,
      data: JSON.stringify({ accessRequestId: request.id, secretId }),
    },
  });

  return NextResponse.json(request, { status: 201 });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const status = req.nextUrl.searchParams.get("status");

  const where: Record<string, unknown> = {
    OR: [
      { requesterId: userId },
      { secret: { ownerId: userId } },
    ],
  };
  if (status) where.status = status;

  const [requests, total] = await Promise.all([
    db.accessRequest.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
      include: {
        requester: { select: { id: true, email: true, name: true } },
      },
    }),
    db.accessRequest.count({ where }),
  ]);

  const requestsWithSecret = await Promise.all(requests.map(async (r) => {
    const s = await db.secret.findUnique({ where: { id: r.secretId }, select: { ownerId: true } });
    return { ...r, secretOwnerId: s?.ownerId };
  }));

  return NextResponse.json({ requests: requestsWithSecret, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
