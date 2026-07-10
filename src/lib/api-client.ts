/**
 * api-client.ts — Wrapper de fetch que inyecta automáticamente el
 * Authorization: Bearer header y maneja expiración de sesión.
 *
 * MEJORA Ciclo 2: centraliza la lógica de autenticación para que
 * ningún componente olvide el header.
 *
 * IMPORTANTE: leemos el token directamente del store en cada llamada
 * (no por closure) para evitar stale references cuando el token cambia.
 */
"use client";

import { useSession } from "./session-store";

export function useApi() {
  const logout = useSession((s) => s.logout);

  async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
    // Leer token FRESH del store en cada llamada (no por closure)
    const state = useSession.getState();
    const sessionToken = state.sessionToken;
    const expiresAt = state.expiresAt;

    // Verificar expiración antes de hacer la request
    if (expiresAt !== null && expiresAt <= Math.floor(Date.now() / 1000)) {
      logout();
      throw new Error("Sesión expirada. Vuelve a iniciar sesión.");
    }

    const headers = new Headers(init.headers);
    if (sessionToken) {
      headers.set("Authorization", `Bearer ${sessionToken}`);
    }
    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const res = await fetch(path, { ...init, headers });

    // Si el server responde 401, la sesión ya no es válida
    if (res.status === 401) {
      logout();
      throw new Error("Sesión inválida. Vuelve a iniciar sesión.");
    }

    return res;
  }

  return { apiFetch };
}
