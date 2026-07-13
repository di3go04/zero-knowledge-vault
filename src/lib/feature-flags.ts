/**
 * Feature flags — controla qué features están activas por entorno.
 */
export const FEATURE_FLAGS = {
  argon2id: process.env.FEATURE_ARGON2ID !== "false",
  websockets: process.env.FEATURE_WEBSOCKETS === "true",
  oidc: !!process.env.OIDC_CLIENT_ID,
  stripe: !!process.env.STRIPE_SECRET_KEY,
  teamVaults: process.env.FEATURE_TEAM_VAULTS === "true",
  totp2fa: process.env.FEATURE_TOTP_2FA === "true",
  hibpCheck: process.env.FEATURE_HIBP_CHECK !== "false",
  blindIndex: process.env.FEATURE_BLIND_INDEX === "true",
  pqkem: process.env.FEATURE_PQKEM === "true",
} as const;

export type FeatureFlag = keyof typeof FEATURE_FLAGS;

export function isFeatureEnabled(flag: FeatureFlag): boolean {
  return FEATURE_FLAGS[flag];
}
