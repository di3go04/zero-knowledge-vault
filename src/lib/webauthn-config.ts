import { env } from "@/lib/env";

export function getWebAuthnConfig(): {
  rpName: string;
  rpId: string;
  origin: string;
} {
  const rpName = env.WEBAUTHN_RP_NAME;
  const origins = env.WEBAUTHN_ORIGINS.split(",");
  const origin = origins[0].trim();
  const rpId = new URL(origin).hostname;
  return { rpName, rpId, origin };
}

export function base64urldecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export function base64urlencode(buf: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}