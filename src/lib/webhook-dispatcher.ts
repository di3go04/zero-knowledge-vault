import { db } from "@/lib/db";
import { createHmac } from "node:crypto";

interface WebhookPayload {
  event: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export async function dispatchWebhook(
  event: string,
  data: Record<string, unknown>,
): Promise<void> {
  const webhooks = await db.webhookConfig.findMany({
    where: { enabled: true },
  });

  const matching = webhooks.filter((wh) => {
    try {
      const events: string[] = JSON.parse(wh.events);
      return events.includes(event);
    } catch {
      return false;
    }
  });

  const payload: WebhookPayload = {
    event,
    timestamp: new Date().toISOString(),
    data,
  };

  const body = JSON.stringify(payload);

  for (const webhook of matching) {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "ZK-Vault-Webhook/1.0",
    };

    if (webhook.secret) {
      const signature = createHmac("sha256", webhook.secret)
        .update(body)
        .digest("hex");
      headers["X-Webhook-Signature"] = signature;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), webhook.timeoutMs);

    try {
      const response = await fetch(webhook.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        console.error(
          `[Webhook] ${webhook.name} returned ${response.status} for event ${event}`,
        );
      }

      await db.webhookConfig.update({
        where: { id: webhook.id },
        data: { lastTriggeredAt: new Date() },
      });
    } catch (err) {
      console.error(
        `[Webhook] Failed to dispatch ${event} to ${webhook.name}:`,
        err,
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}
