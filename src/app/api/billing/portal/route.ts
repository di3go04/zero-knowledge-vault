import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import Stripe from "stripe";
import { useSession } from "@/lib/session-store";

let _stripe: Stripe | null = null;
function getStripe(): Stripe {
  if (!_stripe) {
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_dummy", {
      apiVersion: "2026-06-24" as any,
    });
  }
  return _stripe;
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const session = useSession.getState();
  if (!process.env.STRIPE_SECRET_KEY) {
    return NextResponse.json({ error: "Billing no configurado" }, { status: 501 });
  }

  const customers = await getStripe().customers.list({ email: session.email, limit: 1 });
  if (customers.data.length === 0) {
    return NextResponse.json({ error: "No customer found" }, { status: 404 });
  }

  const portal = await getStripe().billingPortal.sessions.create({
    customer: customers.data[0].id,
    return_url: `${process.env.APP_URL || "http://localhost:3000"}/`,
  });

  return NextResponse.json({ url: portal.url });
}
