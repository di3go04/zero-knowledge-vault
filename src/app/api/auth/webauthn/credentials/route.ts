import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const credentials = await db.webAuthnCredential.findMany({
    where: { userId: auth.userId },
    select: {
      id: true,
      credentialId: true,
      deviceName: true,
      credentialType: true,
      createdAt: true,
      lastUsedAt: true,
    },
    orderBy: { createdAt: "desc" },
  });

  return new Response(JSON.stringify(credentials), {
    headers: { "Content-Type": "application/json" },
  });
}

export async function DELETE(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const url = new URL(req.url);
  const credentialId = url.searchParams.get("id");
  if (!credentialId) {
    return new Response(JSON.stringify({ error: "Missing credential id" }), { status: 400 });
  }

  await db.webAuthnCredential.deleteMany({
    where: { id: credentialId, userId: auth.userId },
  });

  return new Response(JSON.stringify({ deleted: true }), {
    headers: { "Content-Type": "application/json" },
  });
}