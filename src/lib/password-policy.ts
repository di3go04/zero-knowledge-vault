export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  expirationDays: number;
  minUniqueChars: number;
  historySize: number;
  maxFailedAttempts: number;
  lockoutMinutes: number;
}

export const DEFAULT_POLICY: PasswordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  expirationDays: 90,
  minUniqueChars: 6,
  historySize: 5,
  maxFailedAttempts: 5,
  lockoutMinutes: 15,
};

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  score: number;
}

export function validatePassword(password: string, policy: PasswordPolicy = DEFAULT_POLICY): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < policy.minLength) {
    errors.push(`Minimum ${policy.minLength} characters`);
  }
  if (password.length > policy.maxLength) {
    errors.push(`Maximum ${policy.maxLength} characters`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("At least one uppercase letter");
  }
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push("At least one lowercase letter");
  }
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push("At least one number");
  }
  if (policy.requireSymbols && !/[^A-Za-z0-9]/.test(password)) {
    errors.push("At least one symbol");
  }

  const uniqueChars = new Set(password).size;
  if (uniqueChars < policy.minUniqueChars) {
    errors.push(`At least ${policy.minUniqueChars} unique characters`);
  }

  let score = 0;
  score += Math.min(40, password.length * 2);
  if (/[A-Z]/.test(password)) score += 10;
  if (/[a-z]/.test(password)) score += 10;
  if (/\d/.test(password)) score += 10;
  if (/[^A-Za-z0-9]/.test(password)) score += 15;
  if (password.length >= 20) score += 15;
  score = Math.min(100, score);

  return {
    valid: errors.length === 0,
    errors,
    score,
  };
}

export function generateStrongPassword(length: number = 24, policy: PasswordPolicy = DEFAULT_POLICY): string {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
  const all = upper + lower + digits + symbols;

  let password = "";
  if (policy.requireUppercase) password += upper[Math.floor(Math.random() * upper.length)];
  if (policy.requireLowercase) password += lower[Math.floor(Math.random() * lower.length)];
  if (policy.requireNumbers) password += digits[Math.floor(Math.random() * digits.length)];
  if (policy.requireSymbols) password += symbols[Math.floor(Math.random() * symbols.length)];

  for (let i = password.length; i < length; i++) {
    password += all[Math.floor(Math.random() * all.length)];
  }

  return password.split("").sort(() => Math.random() - 0.5).join("");
}