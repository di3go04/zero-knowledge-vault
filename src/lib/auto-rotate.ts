"use client";

export interface RotationRule {
  id: string;
  secretId: string;
  serviceType: "generic" | "aws" | "github" | "gitlab" | "database" | "custom";
  rotationDays: number;
  lastRotation: string | null;
  webhookUrl?: string;
  enabled: boolean;
}

export interface RotationResult {
  secretId: string;
  rotated: boolean;
  newPassword: string;
  error?: string;
}

const STORAGE_KEY = "zk-vault-rotation-rules";

export function getRotationRules(): RotationRule[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

export function saveRotationRule(rule: RotationRule): void {
  const rules = getRotationRules().filter((r) => r.id !== rule.id);
  rules.push(rule);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
}

export function deleteRotationRule(id: string): void {
  const rules = getRotationRules().filter((r) => r.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
}

export async function checkDueRotations(): Promise<RotationRule[]> {
  const rules = getRotationRules();
  const now = Date.now();
  return rules.filter((r) => {
    if (!r.enabled) return false;
    if (!r.lastRotation) return true;
    const last = new Date(r.lastRotation).getTime();
    const due = last + r.rotationDays * 86400_000;
    return now >= due;
  });
}

export function generateRotationPassword(): string {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()_-+=<>?";
  const all = upper + lower + digits + symbols;
  let pwd = upper[Math.floor(Math.random() * upper.length)];
  pwd += lower[Math.floor(Math.random() * lower.length)];
  pwd += digits[Math.floor(Math.random() * digits.length)];
  pwd += symbols[Math.floor(Math.random() * symbols.length)];
  for (let i = pwd.length; i < 32; i++) {
    pwd += all[Math.floor(Math.random() * all.length)];
  }
  return pwd.split("").sort(() => Math.random() - 0.5).join("");
}