/**
 * POST /api/webhooks — Registro y envío de webhooks cifrados.
 *
 *
 * Los webhooks notifican a sistemas externos cuando:
 *   - Un secreto es creado/borrado
 *   - Un secreto es compartido/revocado
 *   - Una rotación de llaves ocurre
 *
 * El payload del webhook es HMAC-signed para verificar autenticidad.
 * El contenido del secreto NUNCA se envía — solo el tipo de evento.
 */
import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { createHmac } from "node:crypto";
import { db } from "@/lib/db";

interface WebhookConfig {
  url: string;
  secret: string;
  events: string[];
}

// Store en BD (cuando se implemente tabla) o en memoria por ahora
const webhooks = new Map<string, WebhookConfig[]>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { action, url, secret, events } = body;

  if (action === "register") {
    // Registrar webhook
    if (!url || !secret || !Array.isArray(events)) {
      return NextResponse.json({ error: "url, secret, events requeridos" }, { status: 400 });
    }
    if (!webhooks.has(userId)) {
      webhooks.set(userId, []);
    }
    webhooks.get(userId)!.push({ url, secret, events });
    return NextResponse.json({ registered: true, url, events });
  }

  if (action === "list") {
    return NextResponse.json({ webhooks: webhooks.get(userId) ?? [] });
  }

  return NextResponse.json({ error: "action debe ser 'register' o 'list'" }, { status: 400 });
}

/**
 * Envía notificaciones webhook a todas las URLs registradas.
 * Llamado por los endpoints de secrets/shares tras una acción.
 */
export async function sendWebhook(
  userId: string,
  event: { type: string; secretId?: string; timestamp: string },
) {
  const configs = webhooks.get(userId);
  if (!configs || configs.length === 0) return;

  for (const config of configs) {
    if (!config.events.includes(event.type)) continue;

    const payload = JSON.stringify(event);
    const signature = createHmac("sha256", config.secret).update(payload).digest("hex");

    try {
      await fetch(config.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZK-Vault-Signature": `sha256=${signature}`,
          "X-ZK-Vault-Event": event.type,
        },
        body: payload,
      });
    } catch {
      // Silently fail — el webhook es best-effort
    }
  }
}
