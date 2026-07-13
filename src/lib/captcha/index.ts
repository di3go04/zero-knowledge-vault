/**
 * Simple CAPTCHA verification using hCaptcha or reCAPTCHA.
 */

export async function verifyCaptcha(token: string, remoteIp: string): Promise<boolean> {
  const secret = process.env.CAPTCHA_SECRET_KEY;
  if (!secret) return true; // Skip if not configured

  try {
    const res = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret, response: token, remoteip: remoteIp }),
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}
