"use client";

import { useState, useEffect } from "react";

interface RotationStatus {
  daysRemaining: number;
  needsRotation: boolean;
  inWarningWindow: boolean;
}

export function RotationBanner() {
  const [status, setStatus] = useState<RotationStatus | null>(null);

  useEffect(() => {
    fetch("/api/auth/rotation-status")
      .then((res) => res.json())
      .then((data) => setStatus(data))
      .catch(() => setStatus(null));
  }, []);

  if (!status || (!status.needsRotation && !status.inWarningWindow)) {
    return null;
  }

  const message = status.needsRotation
    ? `⚠️ Tu contraseña maestra necesita ser rotada. Tu seguridad podría estar comprometida.`
    : `ℹ️ Tu contraseña maestra expirará en ${status.daysRemaining} días.`;

  return (
    <div
      className={`px-4 py-3 text-sm ${
        status.needsRotation
          ? "bg-destructive/10 text-destructive border border-destructive/20"
          : "bg-amber-50 text-amber-800 border border-amber-200"
      }`}
    >
      <div className="flex items-center justify-between max-w-7xl mx-auto">
        <span>{message}</span>
        <a href="/settings/security" className="underline font-medium hover:no-underline">
          Rotar ahora
        </a>
      </div>
    </div>
  );
}
