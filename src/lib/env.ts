import { z } from "zod";

const envSchema = z.object({
  DATABASE_URL: z.string().default("file:./db/custom.db"),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),
  REDIS_URL: z.string().optional(),
  DECOY_HMAC_KEY: z.string().optional(),
  WEBAUTHN_RP_NAME: z.string().default("Zero-Knowledge Vault"),
  WEBAUTHN_ORIGINS: z.string().default("http://localhost:3000"),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  TURNSTILE_SITE_KEY: z.string().optional(),
  TURNSTILE_SECRET_KEY: z.string().optional(),
  HCAPTCHA_SITE_KEY: z.string().optional(),
  HCAPTCHA_SECRET_KEY: z.string().optional(),
  VAULT_API_URL: z.string().default("http://localhost:3000"),
});

function validateEnv() {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    console.error("❌ Invalid environment variables:");
    for (const issue of result.error.issues) {
      console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
    }
    if (result.error.issues.some(i => i.path.includes("SESSION_SECRET"))) {
      throw new Error("SESSION_SECRET is required (min 32 chars). Generate with: openssl rand -base64 48");
    }
    // Fallback: use process.env directly for non-critical failures
    return process.env as unknown as z.infer<typeof envSchema>;
  }
  return result.data;
}

export const env = validateEnv();

if (!env.DECOY_HMAC_KEY) {
  console.warn("⚠️  DECOY_HMAC_KEY is not set. Decoy login responses will not be available.");
}
