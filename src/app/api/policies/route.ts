import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const policySchema = z.object({
  minPasswordLength: z.number().min(8).max(128).default(12),
  requireUppercase: z.boolean().default(true),
  requireNumbers: z.boolean().default(true),
  requireSymbols: z.boolean().default(true),
  maxSecretAge: z.number().min(0).max(3650).default(0),
  require2FA: z.boolean().default(false),
  allowedDomains: z.array(z.string()).default([]),
});

export type SecurityPolicy = z.infer<typeof policySchema>;

const orgPolicies = new Map<string, SecurityPolicy>();

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const policy = orgPolicies.get(auth.userId) ?? policySchema.parse({});
  return NextResponse.json({ policy });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = policySchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  orgPolicies.set(auth.userId, validation.data);
  return NextResponse.json({ policy: validation.data });
}
