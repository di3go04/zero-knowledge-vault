/**
 * password-strength.ts — Validación de fortaleza de contraseña con zxcvbn.
 *
 */
import zxcvbn from "zxcvbn";

export interface PasswordStrengthResult {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  color: string;
  suggestions: string[];
  crackTime: string;
}

export function checkPasswordStrength(password: string, email?: string): PasswordStrengthResult {
  // Pasar el email como user_input para que zxcvbn penalice contraseñas
  // que contengan partes del email
  const result = zxcvbn(password, email ? [email] : []);

  const labels = ["Muy débil", "Débil", "Regular", "Fuerte", "Muy fuerte"];
  const colors = [
    "text-destructive",
    "text-destructive",
    "text-amber-500",
    "text-primary",
    "text-primary",
  ];

  return {
    score: result.score as 0 | 1 | 2 | 3 | 4,
    label: labels[result.score],
    color: colors[result.score],
    suggestions: result.feedback.suggestions ?? [],
    crackTime: result.crack_times_display.offline_slow_hashing_1e4_per_second,
  };
}

export const MIN_PASSWORD_SCORE = 3;

export function isPasswordStrongEnough(password: string, email?: string): boolean {
  return checkPasswordStrength(password, email).score >= MIN_PASSWORD_SCORE;
}
