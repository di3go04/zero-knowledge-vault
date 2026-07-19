/**
 * Password strength estimator — thin wrapper around zxcvbn.
 * Returns a score 0-4 and a crack-time display string.
 */
import zxcvbn from "zxcvbn";

export interface PasswordStrength {
  score: 0 | 1 | 2 | 3 | 4;
  label: "Very weak" | "Weak" | "Fair" | "Strong" | "Very strong";
  suggestions: string[];
}

const LABELS: PasswordStrength["label"][] = [
  "Very weak",
  "Weak",
  "Fair",
  "Strong",
  "Very strong",
];

export function estimatePasswordStrength(
  password: string,
  userInputs?: string[]
): PasswordStrength {
  const result = zxcvbn(password, userInputs);
  const score = Math.max(0, Math.min(4, result.score)) as PasswordStrength["score"];
  return {
    score,
    label: LABELS[score],
    suggestions: result.feedback.suggestions ?? [],
  };
}
