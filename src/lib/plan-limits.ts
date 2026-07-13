import { PLANS, type PlanId } from "./stripe-billing";
import { db } from "./db";

export async function getUserPlan(email: string): Promise<PlanId> {
  const user = await db.user.findUnique({ where: { email: email.toLowerCase() } });
  if (!user?.name) return "free";
  const match = user.name.match(/^(free|team|business|enterprise):/);
  return (match?.[1] as PlanId) || "free";
}

export async function checkPlanLimit(email: string, action: "createSecret" | "addDevice" | "addUser"): Promise<boolean> {
  const planId = await getUserPlan(email);
  const plan = PLANS[planId];

  if (action === "createSecret") {
    if (plan.maxSecrets === Infinity) return true;
    const user = await db.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) return false;
    const count = await db.secret.count({ where: { ownerId: user.id } });
    return count < plan.maxSecrets;
  }

  if (action === "addDevice") {
    if (plan.maxDevices === Infinity) return true;
    const user = await db.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) return false;
    const count = await db.device.count({ where: { userId: user.id, revokedAt: null } });
    return count < plan.maxDevices;
  }

  return true;
}
