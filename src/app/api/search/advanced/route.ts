import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const query = req.nextUrl.searchParams.get("q");
  if (!query) return NextResponse.json({ results: [] });

  // Blind search: search in encrypted titles using LIKE on base64
  // This is a substring match on ciphertext — limited but zero-knowledge
  const shares = await db.secretKeyShare.findMany({
    where: { recipientId: auth.userId },
    include: { secret: true },
  });

  // Client-side: filter by decrypted title. Server returns all, client filters.
  return NextResponse.json({
    results: shares.map(s => ({
      id: s.secret.id,
      encryptedTitle: s.secret.encryptedTitle,
      titleIv: s.secret.titleIv,
      note: "Client must decrypt and filter locally for real search.",
    })),
    query,
  });
}
