/**
 * Server-side CAPTCHA verification.
 * Soporta Cloudflare Turnstile y hCaptcha.
 * Configura con TURNSTILE_SECRET_KEY o HCAPTCHA_SECRET_KEY en .env
 */

const TURNSTILE_VERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const HCAPTCHA_VERIFY = "https://hcaptcha.com/siteverify";

export type CaptchaProvider = "turnstile" | "hcaptcha";

export async function verifyCaptcha(token: string, provider: CaptchaProvider = "turnstile"): Promise<boolean> {
  const secretKey = provider === "turnstile"
    ? process.env.TURNSTILE_SECRET_KEY
    : process.env.HCAPTCHA_SECRET_KEY;

  if (!secretKey) return true;

  const url = provider === "turnstile" ? TURNSTILE_VERIFY : HCAPTCHA_VERIFY;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: secretKey, response: token }),
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

export function requireCaptcha(req: Request): boolean {
  const url = new URL(req.url);
  const path = url.pathname;
  const captchaPaths = ["/api/auth/login", "/api/auth/register", "/api/devices/enroll/init"];
  return captchaPaths.includes(path);
}