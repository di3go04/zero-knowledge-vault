import { randomBytes } from "crypto";

const CSRF_TOKEN_LENGTH = 32;
const tokenStore = new Map<string, number>();
const TOKEN_TTL_MS = 60 * 60 * 1000;

export function generateCsrfToken(): string {
  const token = randomBytes(CSRF_TOKEN_LENGTH).toString("hex");
  tokenStore.set(token, Date.now() + TOKEN_TTL_MS);
  if (tokenStore.size > 1000) {
    const now = Date.now();
    for (const [key, expiry] of tokenStore) {
      if (expiry < now) tokenStore.delete(key);
    }
  }
  return token;
}

export function validateCsrfToken(token: string): boolean {
  const expiry = tokenStore.get(token);
  if (!expiry) return false;
  if (Date.now() > expiry) {
    tokenStore.delete(token);
    return false;
  }
  tokenStore.delete(token);
  return true;
}

export function csrfMiddleware(request: Request): Response | null {
  if (request.method === "GET" || request.method === "HEAD" || request.method === "OPTIONS") {
    return null;
  }

  const csrfToken = request.headers.get("x-csrf-token");
  if (!csrfToken || !validateCsrfToken(csrfToken)) {
    return new Response(JSON.stringify({ error: "CSRF token inválido" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  return null;
}
