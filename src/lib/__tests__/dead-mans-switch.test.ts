import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createSwitch, getSwitch, pulse, updateSwitch, checkAllSwitches, deleteSwitch } from "../dead-mans-switch";
import { db } from "../db";

describe("DeadManSwitch", () => {
  let userId: string;
  let userId2: string;

  beforeAll(async () => {
    const user = await db.user.create({
      data: { email: `dms-test-${Date.now()}@test.com`, name: "DMS Test" },
    });
    userId = user.id;

    const user2 = await db.user.create({
      data: { email: `dms-test-2-${Date.now()}@test.com`, name: "DMS Test 2" },
    });
    userId2 = user2.id;
  });

  it("crea un switch con valores por defecto", async () => {
    const sw = await createSwitch({
      userId,
      notifyEmail: "backup@test.com",
      message: "Emergency access needed",
    });

    expect(sw.userId).toBe(userId);
    expect(sw.enabled).toBe(true);
    expect(sw.gracePeriodMs).toBe(86400000);
    expect(sw.notifyEmail).toBe("backup@test.com");
    expect(sw.message).toBe("Emergency access needed");
  });

  it("recupera el switch por userId", async () => {
    const sw = await getSwitch(userId);
    expect(sw).not.toBeNull();
    expect(sw!.userId).toBe(userId);
  });

  it("actualiza el pulso (pulse)", async () => {
    const old = await getSwitch(userId);
    expect(old).not.toBeNull();

    await new Promise((r) => setTimeout(r, 10));

    await pulse(userId);
    const updated = await getSwitch(userId);
    expect(updated!.lastPulseAt.getTime()).toBeGreaterThan(old!.lastPulseAt.getTime());
  });

  it("actualiza campos del switch", async () => {
    await updateSwitch(userId, { gracePeriodMs: 3600000, message: "Updated message" });

    const sw = await getSwitch(userId);
    expect(sw!.gracePeriodMs).toBe(3600000);
    expect(sw!.message).toBe("Updated message");
  });

  it("checkAllSwitches no dispara switches dentro del plazo", async () => {
    await pulse(userId);
    const results = await checkAllSwitches();
    const ours = results.find((r) => r.userId === userId);
    expect(ours).toBeDefined();
    expect(ours!.triggered).toBe(false);
    expect(ours!.reason).toBe("within_grace_period");
  });

  it("checkAllSwitches dispara un switch vencido", async () => {
    const sw = await createSwitch({
      userId: userId2,
      notifyEmail: "alert@test.com",
      gracePeriodMs: 1,
      message: "Expired test",
    });

    await new Promise((r) => setTimeout(r, 5));

    const results = await checkAllSwitches();
    const ours = results.find((r) => r.userId === userId2);
    expect(ours).toBeDefined();
    expect(ours!.triggered).toBe(true);
    expect(ours!.reason).toContain("grace_period_exceeded");
  });

  it("elimina el switch", async () => {
    const deleted = await deleteSwitch(userId2);
    expect(deleted).toBe(true);

    const sw = await getSwitch(userId2);
    expect(sw).toBeNull();
  });

  it("persiste correctamente (no es Map en memoria)", async () => {
    const fromDb = await db.deadManSwitch.findUnique({ where: { userId } });
    expect(fromDb).not.toBeNull();
    expect(fromDb!.notifyEmail).toBe("backup@test.com");
  });
});
