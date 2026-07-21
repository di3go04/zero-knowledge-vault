import { createHash } from "node:crypto";
const API_KEYS = new Map<string, { userId: string; scopes: string[] }>();
export function generateApiKey(userId: string, scopes: string[] = ["read"]): string {
  const raw = `zkv_${crypto.randomUUID()}_${crypto.randomUUID()}`;
  const hash = createHash("sha256").update(raw).digest("hex");
  API_KEYS.set(hash, { userId, scopes });
  return raw;
}
export function verifyApiKey(req: Request): { userId: string; scopes: string[] } | null {
  const auth = req.headers.get("x-api-key");
  if (!auth) return null;
  const hash = createHash("sha256").update(auth).digest("hex");
  return API_KEYS.get(hash) ?? null;
}
