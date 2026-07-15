import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { claimEmergencyAccessSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const { id } = await params;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const validation = validatePayload(claimEmergencyAccessSchema, body);
  if (!validation.success) {
    return new Response(JSON.stringify({ error: validation.error }), { status: 400 });
  }

  const { action } = validation.data;

  const grant = await db.emergencyAccess.findUnique({ where: { id } });
  if (!grant) {
    return new Response(JSON.stringify({ error: "Grant not found" }), { status: 404 });
  }

  switch (action) {
    case "claim": {
      if (grant.beneficiaryId !== auth.userId) {
        return new Response(JSON.stringify({ error: "Only beneficiary can claim" }), { status: 403 });
      }
      if (grant.status !== "pending") {
        return new Response(JSON.stringify({ error: `Grant is ${grant.status}, not pending` }), { status: 400 });
      }
      const updated = await db.emergencyAccess.update({
        where: { id },
        data: { status: "active", claimedAt: new Date() },
      });
      return new Response(JSON.stringify({
        status: "active",
        claimedAt: updated.claimedAt,
        releaseAt: new Date(updated.claimedAt!.getTime() + grant.delayHours * 3600_000),
      }), { headers: { "Content-Type": "application/json" } });
    }

    case "cancel": {
      if (grant.grantorId !== auth.userId) {
        return new Response(JSON.stringify({ error: "Only grantor can cancel" }), { status: 403 });
      }
      if (grant.status === "completed") {
        return new Response(JSON.stringify({ error: "Cannot cancel completed grant" }), { status: 400 });
      }
      await db.emergencyAccess.update({
        where: { id },
        data: { status: "cancelled" },
      });
      return new Response(JSON.stringify({ status: "cancelled" }), { headers: { "Content-Type": "application/json" } });
    }

    case "recover": {
      if (grant.beneficiaryId !== auth.userId) {
        return new Response(JSON.stringify({ error: "Only beneficiary can recover" }), { status: 403 });
      }
      if (grant.status !== "active") {
        return new Response(JSON.stringify({ error: "Grant is not active" }), { status: 400 });
      }
      if (!grant.claimedAt) {
        return new Response(JSON.stringify({ error: "Grant not yet claimed" }), { status: 400 });
      }
      const elapsed = Date.now() - grant.claimedAt.getTime();
      const delayMs = grant.delayHours * 3600_000;
      if (elapsed < delayMs) {
        const remaining = Math.ceil((delayMs - elapsed) / 1000);
        return new Response(JSON.stringify({
          error: `Time-lock not expired. ${remaining}s remaining.`,
          remainingSeconds: remaining,
        }), { status: 423 });
      }

      const keyMaterial = await db.userKeyMaterial.findUnique({
        where: { userId: grant.grantorId },
      });
      if (!keyMaterial || !keyMaterial.encryptedPrivateKeyForRecovery) {
        return new Response(JSON.stringify({ error: "Grantor has no recovery backup" }), { status: 404 });
      }

      await db.emergencyAccess.update({
        where: { id },
        data: { status: "completed", completedAt: new Date() },
      });

      return new Response(JSON.stringify({
        status: "completed",
        recoveryBlob: keyMaterial.encryptedPrivateKeyForRecovery,
        recoveryIv: keyMaterial.recoveryIv,
        recoverySalt: keyMaterial.recoverySalt,
        recoveryIterations: keyMaterial.recoveryIterations,
        grantorId: grant.grantorId,
      }), { headers: { "Content-Type": "application/json" } });
    }

    default:
      return new Response(JSON.stringify({ error: "Invalid action" }), { status: 400 });
  }
}