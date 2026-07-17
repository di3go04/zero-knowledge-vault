import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { getRotationStatus } from "../key-rotation";

const DAY_MS = 24 * 60 * 60 * 1000;

describe("Key Rotation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("should require rotation when never rotated", () => {
    const status = getRotationStatus(null);
    expect(status.needsRotation).toBe(true);
    expect(status.daysSinceRotation).toBe(999);
  });

  it("should require rotation after 30 days", () => {
    const thirtyOneDaysAgo = new Date(Date.now() - 31 * DAY_MS).toISOString();
    const status = getRotationStatus(thirtyOneDaysAgo);
    expect(status.needsRotation).toBe(true);
    expect(status.daysSinceRotation).toBeGreaterThanOrEqual(31);
  });

  it("should not require rotation within 30 days", () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * DAY_MS).toISOString();
    const status = getRotationStatus(fiveDaysAgo);
    expect(status.needsRotation).toBe(false);
    expect(status.daysSinceRotation).toBe(5);
  });

  it("should warn 3 days before expiry", () => {
    const daysAgo = 28;
    const pastDate = new Date(Date.now() - daysAgo * DAY_MS).toISOString();
    const status = getRotationStatus(pastDate);
    expect(status.daysUntilWarning).toBe(0);
    expect(status.daysUntilOverdue).toBe(2);
  });

  it("should not warn when far from expiry", () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * DAY_MS).toISOString();
    const status = getRotationStatus(fiveDaysAgo);
    expect(status.daysUntilWarning).toBe(22);
    expect(status.daysUntilOverdue).toBe(25);
  });

  it("should report exact overdue days when rotation is late", () => {
    const daysAgo = 35;
    const pastDate = new Date(Date.now() - daysAgo * DAY_MS).toISOString();
    const status = getRotationStatus(pastDate);
    expect(status.needsRotation).toBe(true);
    expect(status.daysSinceRotation).toBe(35);
  });
});
