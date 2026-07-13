/**
 * API key management — claves de API para acceso programático.
 * Permite a integraciones (CLI, SDK, extensiones) autenticarse
 * sin usar session tokens.
 */
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { db } from "./db";

const API_KEY_PREFIX = "zkv_";

export function generateApiKey(): { key: string; hash: string } {
  const raw = randomBytes(32).toString("hex");
  const key = `${API_KEY_PREFIX}${raw}`;
  const hash = createHash("sha256").update(key).digest("hex");
  return { key, hash };
}

export async function verifyApiKey(key: string): Promise<string | null> {
  if (!key.startsWith(API_KEY_PREFIX)) return null;
  const hash = createHash("sha256").update(key).digest("hex");

  // Buscar en BD (cuando se añada tabla ApiKey) o en memoria por ahora
  // Por ahora, devolver null — requiere schema change
  return null;
}

export async function createApiKeyForUser(userId: string, name: string): Promise<{ key: string; id: string }> {
  const { key, hash } = generateApiKey();
  // Guardar hash + userId + name cuando se añada tabla ApiKey
  // Por ahora, devolver la key sin persistir
  return { key, id: "pending" };
}
