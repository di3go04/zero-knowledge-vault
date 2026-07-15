import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { tenantSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const tenants = await db.tenant.findMany({
    include: { branding: true },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ tenants });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(tenantSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.tenant.findFirst({
    where: {
      OR: [
        { slug: validation.data.slug },
        ...(validation.data.domain ? [{ domain: validation.data.domain }] : []),
      ],
    },
  });
  if (existing) {
    return NextResponse.json({ error: "Tenant with this slug or domain already exists" }, { status: 409 });
  }

  const tenant = await db.tenant.create({ data: validation.data });

  return NextResponse.json(tenant, { status: 201 });
}
