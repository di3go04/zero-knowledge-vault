import type { SecurityPolicy } from "../app/api/policies/route";

export function validatePasswordAgainstPolicy(password: string, policy: SecurityPolicy): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  if (password.length < policy.minPasswordLength) {
    errors.push(`Password must be at least ${policy.minPasswordLength} characters`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Password must contain uppercase letters");
  }
  if (policy.requireNumbers && !/[0-9]/.test(password)) {
    errors.push("Password must contain numbers");
  }
  if (policy.requireSymbols && !/[^A-Za-z0-9]/.test(password)) {
    errors.push("Password must contain symbols");
  }
  return { valid: errors.length === 0, errors };
}

export function checkSecretExpiry(createdAt: Date, maxAgeDays: number): boolean {
  if (maxAgeDays === 0) return false;
  const ageMs = Date.now() - createdAt.getTime();
  return ageMs > maxAgeDays * 86400000;
}
