import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const policySchema = z.object({
  name: z.string(),
  rules: z.object({
    minPasswordLength: z.number().default(12),
    require2FA: z.boolean().default(false),
    maxSecretAge: z.number().default(0),
    allowedDomains: z.array(z.string()).default([]),
    denySharesExternally: z.boolean().default(false),
  }),
});

const groupPolicies = new Map<string, any>();

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  return NextResponse.json({ policies: Array.from(groupPolicies.entries()) });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const body = await req.json();
  const validation = policySchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid policy" }, { status: 400 });
  groupPolicies.set(auth.userId, validation.data);
  return NextResponse.json({ policy: validation.data });
}
