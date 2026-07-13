"use client";

import { checkPasswordStrength, MIN_PASSWORD_SCORE } from "@/lib/password-strength";
import { useMemo } from "react";

interface PasswordStrengthMeterProps {
  password: string;
  email?: string;
}

/**
 * Medidor visual de fortaleza de contraseña con zxcvbn.
 *
 */
export function PasswordStrengthMeter({ password, email }: PasswordStrengthMeterProps) {
  const result = useMemo(
    () => (password ? checkPasswordStrength(password, email) : null),
    [password, email],
  );

  if (!result || !password) return null;

  const bars = [1, 2, 3, 4];
  const barColors = ["bg-destructive", "bg-destructive", "bg-amber-500", "bg-primary"];

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1">
        {bars.map((bar) => (
          <div
            key={bar}
            className={`h-1 flex-1 rounded-full transition-colors ${
              result.score >= bar ? barColors[result.score - 1] ?? "bg-primary" : "bg-muted"
            }`}
          />
        ))}
        <span className={`ml-2 text-[10px] font-medium ${result.color}`}>
          {result.label}
        </span>
      </div>
      {result.score < MIN_PASSWORD_SCORE && result.suggestions.length > 0 ? (
        <p className="text-[10px] text-muted-foreground">
          {result.suggestions[0]}
        </p>
      ) : null}
    </div>
  );
}
