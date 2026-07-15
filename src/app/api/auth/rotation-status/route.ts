import { requireAuth } from "@/lib/auth-helper";
import { prisma } from "@/lib/db";

export async function GET(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const keyMaterial = await prisma.userKeyMaterial.findUnique({
    where: { userId: auth.userId },
    select: { lastKeyRotationAt: true },
  });

  return new Response(
    JSON.stringify({
      lastKeyRotationAt: keyMaterial?.lastKeyRotationAt?.toISOString() ?? null,
    }),
    { headers: { "Content-Type": "application/json" } },
  );
}