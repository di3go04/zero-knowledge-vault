import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { createEmergencyAccessSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const validation = validatePayload(createEmergencyAccessSchema, body);
  if (!validation.success) {
    return new Response(JSON.stringify({ error: validation.error }), { status: 400 });
  }

  const { beneficiaryEmail, message, delayHours } = validation.data;

  const beneficiary = await db.user.findUnique({
    where: { email: beneficiaryEmail.toLowerCase().trim() },
  });
  if (!beneficiary) {
    return new Response(JSON.stringify({ error: "Beneficiary not found" }), { status: 404 });
  }
  if (beneficiary.id === auth.userId) {
    return new Response(JSON.stringify({ error: "Cannot set yourself as beneficiary" }), { status: 400 });
  }

  const existing = await db.emergencyAccess.findUnique({
    where: { grantorId_beneficiaryId: { grantorId: auth.userId, beneficiaryId: beneficiary.id } },
  });
  if (existing && existing.status !== "cancelled") {
    return new Response(JSON.stringify({ error: "Emergency access already exists" }), { status: 409 });
  }

  const grant = await db.emergencyAccess.upsert({
    where: { grantorId_beneficiaryId: { grantorId: auth.userId, beneficiaryId: beneficiary.id } },
    update: { status: "pending", message, delayHours, claimedAt: null, completedAt: null },
    create: {
      grantorId: auth.userId,
      beneficiaryId: beneficiary.id,
      message,
      delayHours,
      status: "pending",
    },
  });

  return new Response(JSON.stringify({
    id: grant.id,
    beneficiaryId: beneficiary.id,
    beneficiaryEmail: beneficiary.email,
    beneficiaryName: beneficiary.name,
    status: grant.status,
    delayHours: grant.delayHours,
    message: grant.message,
    createdAt: grant.createdAt,
  }), { headers: { "Content-Type": "application/json" }, status: 201 });
}

export async function GET(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const [asGrantor, asBeneficiary] = await Promise.all([
    db.emergencyAccess.findMany({
      where: { grantorId: auth.userId },
      include: { beneficiary: { select: { id: true, email: true, name: true } } },
      orderBy: { createdAt: "desc" },
    }),
    db.emergencyAccess.findMany({
      where: { beneficiaryId: auth.userId },
      include: { grantor: { select: { id: true, email: true, name: true } } },
      orderBy: { createdAt: "desc" },
    }),
  ]);

  return new Response(JSON.stringify({ asGrantor, asBeneficiary }), {
    headers: { "Content-Type": "application/json" },
  });
}