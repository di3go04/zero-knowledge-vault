import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { groupPolicySchema, groupPolicyUpdateSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const group = await db.userGroup.findUnique({ where: { id } });
  if (!group) {
    return NextResponse.json({ error: "Group not found" }, { status: 404 });
  }

  const policies = await db.groupPolicy.findMany({
    where: { groupId: id },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ policies });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const group = await db.userGroup.findUnique({ where: { id } });
  if (!group) {
    return NextResponse.json({ error: "Group not found" }, { status: 404 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(groupPolicySchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const policy = await db.groupPolicy.create({
    data: { groupId: id, ...validation.data, enabled: validation.data.enabled ?? true },
  });

  return NextResponse.json(policy, { status: 201 });
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const searchParams = req.nextUrl.searchParams;
  const policyId = searchParams.get("policyId");
  if (!policyId) {
    return NextResponse.json({ error: "policyId query param required" }, { status: 400 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(groupPolicyUpdateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.groupPolicy.findUnique({ where: { id: policyId } });
  if (!existing || existing.groupId !== id) {
    return NextResponse.json({ error: "Policy not found for this group" }, { status: 404 });
  }

  const policy = await db.groupPolicy.update({
    where: { id: policyId },
    data: validation.data,
  });

  return NextResponse.json(policy);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const searchParams = req.nextUrl.searchParams;
  const policyId = searchParams.get("policyId");
  if (!policyId) {
    return NextResponse.json({ error: "policyId query param required" }, { status: 400 });
  }

  const policy = await db.groupPolicy.findUnique({ where: { id: policyId } });
  if (!policy || policy.groupId !== id) {
    return NextResponse.json({ error: "Policy not found for this group" }, { status: 404 });
  }

  await db.groupPolicy.delete({ where: { id: policyId } });
  return NextResponse.json({}, { status: 204 });
}
