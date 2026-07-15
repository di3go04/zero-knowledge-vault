"use client";

import { validatePassword, type PasswordPolicy, DEFAULT_POLICY } from "./password-policy";
import { checkPasswordBreach } from "./breach-detection";

export interface PasswordHealth {
  score: number;
  label: "critical" | "weak" | "fair" | "strong" | "excellent";
  issues: string[];
  pwned: boolean;
  pwnedCount: number;
  recommendations: string[];
}

export async function analyzePasswordHealth(password: string, policy: PasswordPolicy = DEFAULT_POLICY): Promise<PasswordHealth> {
  const issues: string[] = [];
  const recommendations: string[] = [];

  const validation = validatePassword(password, policy);
  issues.push(...validation.errors);

  const breachResult = await checkPasswordBreach(password);
  if (breachResult.pwned) {
    issues.push(`Password appears in ${breachResult.count.toLocaleString()} data breaches`);
    recommendations.push("Change this password immediately — it has been exposed in a data breach");
  }

  if (password.length < 8) {
    recommendations.push("Use at least 12 characters for better security");
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    recommendations.push("Add symbols (!@#$%^&*) to increase complexity");
  }
  if (password.toLowerCase().includes("password") || password.toLowerCase().includes("123456")) {
    recommendations.push("Avoid common patterns like 'password' or '123456'");
  }

  let score = validation.score;
  if (breachResult.pwned) score = Math.min(score, 20);
  if (issues.length > 3) score = Math.min(score, 30);

  let label: PasswordHealth["label"];
  if (score >= 90) label = "excellent";
  else if (score >= 70) label = "strong";
  else if (score >= 50) label = "fair";
  else if (score >= 25) label = "weak";
  else label = "critical";

  return { score, label, issues, pwned: breachResult.pwned, pwnedCount: breachResult.count, recommendations };
}

export function scoreToColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#84cc16";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#f97316";
  return "#ef4444";
}