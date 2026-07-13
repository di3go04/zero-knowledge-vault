export interface BreachReport {
  email: string;
  breaches: { name: string; date: string; count: number }[];
  lastChecked: string;
}

export async function generateBreachReport(email: string): Promise<BreachReport> {
  try {
    const hash = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(email));
    const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const prefix = hex.slice(0, 5);
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: { "hibp-api-key": process.env.HIBP_API_KEY || "", "user-agent": "zk-vault" },
    });
    if (!res.ok) return { email, breaches: [], lastChecked: new Date().toISOString() };
    const data = await res.json();
    return { email, breaches: data.map((b: any) => ({ name: b.Name, date: b.BreachDate, count: b.PwnCount })), lastChecked: new Date().toISOString() };
  } catch {
    return { email, breaches: [], lastChecked: new Date().toISOString() };
  }
}
