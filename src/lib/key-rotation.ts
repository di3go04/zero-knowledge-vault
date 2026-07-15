"use client";

import { useSession } from "./session-store";

const ROTATION_INTERVAL_DAYS = 30;
const ROTATION_WARN_DAYS = 3;

export interface RotationStatus {
  needsRotation: boolean;
  daysSinceRotation: number;
  daysUntilWarning: number;
  daysUntilOverdue: number;
}

export function getRotationStatus(
  lastRotationAt: string | null | undefined,
): RotationStatus {
  if (!lastRotationAt) {
    return { needsRotation: true, daysSinceRotation: 999, daysUntilWarning: 0, daysUntilOverdue: 0 };
  }
  const last = new Date(lastRotationAt).getTime();
  const now = Date.now();
  const daysSince = Math.floor((now - last) / (1000 * 60 * 60 * 24));
  return {
    needsRotation: daysSince >= ROTATION_INTERVAL_DAYS,
    daysSinceRotation: daysSince,
    daysUntilWarning: Math.max(0, ROTATION_INTERVAL_DAYS - ROTATION_WARN_DAYS - daysSince),
    daysUntilOverdue: Math.max(0, ROTATION_INTERVAL_DAYS - daysSince),
  };
}

export async function checkRotationAndNotify(): Promise<void> {
  const state = useSession.getState();
  if (!state.userId) return;
  try {
    const res = await fetch("/api/auth/rotation-status");
    if (!res.ok) return;
    const data = await res.json();
    const status = getRotationStatus(data.lastKeyRotationAt);
    if (status.needsRotation) {
      const { toast } = await import("sonner");
      toast.warning(
        `Tu contraseña maestra necesita rotación (${status.daysSinceRotation} días sin cambiar).`,
        {
          description: "Cambia tu contraseña para mantener la seguridad de tu bóveda.",
          action: { label: "Rotar ahora", onClick: () => window.dispatchEvent(new CustomEvent("open-rotate-password")) },
          duration: 10000,
        },
      );
    } else if (status.daysUntilWarning === 0) {
      const { toast } = await import("sonner");
      toast.info(
        `Tu contraseña caduca en ${status.daysUntilOverdue} días.`,
        { duration: 8000 },
      );
    }
  } catch {
    // Silent fail
  }
}