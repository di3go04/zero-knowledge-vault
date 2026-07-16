import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const siemSchema = z.object({
  events: z.array(z.object({
    timestamp: z.string(),
    type: z.string(),
    user: z.string().optional(),
    ip: z.string().optional(),
    outcome: z.enum(["success", "failure", "warning"]),
    detail: z.string(),
  })).min(1).max(100),
});

const siemWebhooks = new Map<string, string>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = siemSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  const { events } = validation.data;

  for (const [orgId, webhookUrl] of siemWebhooks) {
    if (webhookUrl) {
      try {
        await fetch(webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: "zk-vault",
            events: events.map(e => ({
              ...e,
              "@version": "1",
              "@timestamp": e.timestamp,
              "event.category": "iam",
              "event.type": e.type,
              "event.outcome": e.outcome,
            })),
          }),
        });
      } catch {}
    }
  }

  return NextResponse.json({ forwarded: events.length });
}
