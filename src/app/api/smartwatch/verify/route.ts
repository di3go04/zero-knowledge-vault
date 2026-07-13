import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

const verifySchema = z.object({
  userId: z.string(),
  code: z.string().length(6),
});

export async function POST(req: NextRequest) {
  const body = await req.json();
  const validation = verifySchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid" }, { status: 400 });

  return NextResponse.json({ verified: false, note: "Smartwatch 2FA — pair device first" });
}
