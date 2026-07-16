import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id } = await params;
  const share = await db.secretKeyShare.findUnique({
    where: { secretId_recipientId: { secretId: id, recipientId: userId } },
  });
  if (!share) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  const versions = await db.secretVersion.findMany({
    where: { secretId: id },
    orderBy: { version: "desc" },
    take: 2,
  });

  if (versions.length < 2) {
    return NextResponse.json({ diff: null, note: "Need at least 2 versions for diff" });
  }

  return NextResponse.json({
    current: versions[0],
    previous: versions[1],
    diff: {
      encryptedDataChanged: versions[0].encryptedData !== versions[1].encryptedData,
      versionDelta: versions[0].version - versions[1].version,
      timeDelta: new Date(versions[0].createdAt).getTime() - new Date(versions[1].createdAt).getTime(),
    },
    note: "Client must decrypt both versions to compute plaintext diff.",
  });
}
