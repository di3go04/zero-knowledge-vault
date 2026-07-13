import { NextRequest, NextResponse } from "next/server";
import { createCheckoutSession, PLANS, type PlanId } from "@/lib/stripe-billing";
import { requireAuth } from "@/lib/auth-helper";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { searchParams } = new URL(req.url);
  const planId = (searchParams.get("plan") || "team") as PlanId;

  if (!PLANS[planId] || planId === "free") {
    return NextResponse.json({ error: "Plan inválido" }, { status: 400 });
  }

  const session = useSession.getState();
  const url = await createCheckoutSession(session.email, planId);
  return NextResponse.json({ url });
}

import { useSession } from "@/lib/session-store";
