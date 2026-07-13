import { NextRequest, NextResponse } from "next/server";
import { handleWebhook } from "@/lib/stripe-billing";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature") || "";
  try {
    await handleWebhook(body, signature);
    return NextResponse.json({ received: true });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 400 });
  }
}
