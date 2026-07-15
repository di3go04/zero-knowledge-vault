"use client";

export interface BreachResult {
  pwned: boolean;
  count: number;
  error?: string;
}

const HIBP_API = "https://api.pwnedpasswords.com/range/";

export async function checkPasswordBreach(password: string): Promise<BreachResult> {
  try {
    const hash = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
    const hashHex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    const res = await fetch(`${HIBP_API}${prefix}`);
    if (!res.ok) {
      return { pwned: false, count: 0, error: `API error: ${res.status}` };
    }

    const text = await res.text();
    const match = text.split("\n").find((line) => line.startsWith(suffix.toUpperCase()));
    if (match) {
      const count = parseInt(match.split(":")[1]?.trim() || "0", 10);
      return { pwned: true, count };
    }

    return { pwned: false, count: 0 };
  } catch (err: any) {
    return { pwned: false, count: 0, error: err.message };
  }
}