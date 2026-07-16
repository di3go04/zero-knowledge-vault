import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const connectorSchema = z.object({
  provider: z.enum(["okta", "azure-ad", "google-workspace", "jumpcloud"]),
  apiKey: z.string(),
  domain: z.string().optional(),
});

const connectors = new Map<string, { provider: string; domain?: string; syncedAt: string }>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = connectorSchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid config" }, { status: 400 });

  const { provider, domain } = validation.data;
  connectors.set(auth.userId, { provider, domain, syncedAt: new Date().toISOString() });

  return NextResponse.json({ connected: true, provider, domain });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  return NextResponse.json({ connectors: Array.from(connectors.entries()) });
}
