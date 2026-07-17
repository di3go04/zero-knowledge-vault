/**
 * audit-log-helper.ts — Helper para enviar logs cifrados desde el cliente.
 */
"use client";

import { useSession } from "./session-store";
import { deriveAuditKey, encryptAuditEvent, type AuditCategory } from "./crypto";

let auditKeyCache: CryptoKey | null = null;

async function getAuditKey(masterKey: CryptoKey): Promise<CryptoKey> {
  if (auditKeyCache) return auditKeyCache;
  auditKeyCache = await deriveAuditKey(masterKey);
  return auditKeyCache;
}

export async function logAuditEvent(
  masterKey: CryptoKey | null,
  sessionToken: string | null,
  category: AuditCategory,
  event: Record<string, unknown>,
): Promise<void> {
  if (!masterKey || !sessionToken) return;
  try {
    const auditKey = await getAuditKey(masterKey as CryptoKey);
    const { encryptedEvent, eventIv } = await encryptAuditEvent(auditKey, event);
    await fetch("/api/audit-logs", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ encryptedEvent, eventIv, eventCategory: category }),
    });
  } catch {
    // Silently fail — audit logs are best-effort
  }
}
