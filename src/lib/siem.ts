export async function sendSiemEvent(event: {
  type: string;
  user?: string;
  ip?: string;
  outcome: "success" | "failure" | "warning";
  detail: string;
}): Promise<void> {
  const siemUrl = process.env.SIEM_WEBHOOK_URL;
  if (!siemUrl) return;

  try {
    await fetch(siemUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: "zk-vault",
        timestamp: new Date().toISOString(),
        ...event,
        "event.category": "iam",
        "event.outcome": event.outcome,
      }),
    });
  } catch {}
}
