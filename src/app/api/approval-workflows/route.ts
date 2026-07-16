import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const approvalSchema = z.object({
  action: z.string(),
  targetId: z.string(),
  requestedBy: z.string(),
});

const pendingApprovals = new Map<string, { action: string; targetId: string; requestedBy: string; approvers: string[]; createdAt: string }>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const body = await req.json();
  const validation = approvalSchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid" }, { status: 400 });

  const id = `approval:${Date.now()}`;
  pendingApprovals.set(id, { ...validation.data, approvers: [auth.userId], createdAt: new Date().toISOString() });
  return NextResponse.json({ id, status: "pending" });
}

export async function PUT(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const body = await req.json();
  const { approvalId } = body;
  const approval = pendingApprovals.get(approvalId);
  if (!approval) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (!approval.approvers.includes(auth.userId)) approval.approvers.push(auth.userId);
  const approved = approval.approvers.length >= 2;
  if (approved) pendingApprovals.delete(approvalId);
  return NextResponse.json({ approved, approvers: approval.approvers.length });
}
