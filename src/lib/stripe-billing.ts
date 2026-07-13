import Stripe from "stripe";

let _stripe: Stripe | null = null;

function getStripe(): Stripe {
  if (!_stripe) {
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_dummy", {
      apiVersion: "2026-06-24" as any,
    });
  }
  return _stripe;
}

export const PLANS = {
  free: { priceId: null, maxSecrets: 50, maxDevices: 1, maxUsers: 1 },
  team: { priceId: process.env.STRIPE_TEAM_PRICE_ID, maxSecrets: Infinity, maxDevices: 10, maxUsers: 50 },
  business: { priceId: process.env.STRIPE_BUSINESS_PRICE_ID, maxSecrets: Infinity, maxDevices: 50, maxUsers: 500 },
  enterprise: { priceId: process.env.STRIPE_ENTERPRISE_PRICE_ID, maxSecrets: Infinity, maxDevices: Infinity, maxUsers: Infinity },
} as const;

export type PlanId = keyof typeof PLANS;

export async function createCheckoutSession(email: string, planId: PlanId, trialDays: number = 14): Promise<string> {
  const plan = PLANS[planId];
  if (!plan.priceId) throw new Error("Plan free no requiere checkout");

  const session = await getStripe().checkout.sessions.create({
    customer_email: email,
    mode: "subscription",
    line_items: [{ price: plan.priceId, quantity: 1 }],
    subscription_data: { trial_period_days: trialDays },
    success_url: `${process.env.APP_URL}/?billing=success`,
    cancel_url: `${process.env.APP_URL}/?billing=cancelled`,
  });

  return session.url!;
}

export async function handleWebhook(rawBody: string, signature: string): Promise<void> {
  const event = getStripe().webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!);

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      const email = session.customer_email!;
      await updatePlanForUser(email, "team");
      break;
    }
    case "customer.subscription.deleted": {
      const sub = event.data.object as Stripe.Subscription;
      const customer = await getStripe().customers.retrieve(sub.customer as string);
      if (customer && !("deleted" in customer) && customer.email) {
        await updatePlanForUser(customer.email, "free");
      }
      break;
    }
  }
}

async function updatePlanForUser(email: string, planId: PlanId): Promise<void> {
  const { db } = await import("./db");
  await db.user.update({
    where: { email: email.toLowerCase() },
    data: { name: `${planId}:${Date.now()}` },
  });
}
