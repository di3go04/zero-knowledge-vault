"use client";

import { estimatePasswordStrength } from "@/lib/password-strength";
import { useMemo } from "react";

interface Props {
  password: string;
  email?: string;
}

const COLORS = [
  "bg-red-500",
  "bg-orange-500",
  "bg-yellow-500",
  "bg-lime-500",
  "bg-green-500",
];

export function PasswordStrengthMeter({ password, email }: Props) {
  const strength = useMemo(
    () => (password ? estimatePasswordStrength(password, email ? [email] : []) : null),
    [password, email]
  );

  if (!strength) {
    return null;
  }

  return (
    <div className="space-y-1">
      <div className="flex gap-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full ${
              i <= strength.score ? COLORS[strength.score] : "bg-muted"
            }`}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {strength.label}
        {strength.suggestions.length > 0 && (
          <span className="block text-[10px]">{strength.suggestions[0]}</span>
        )}
      </p>
    </div>
  );
}
