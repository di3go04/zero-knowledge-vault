import { session } from "./session";
import { env } from "@/lib/env";

const API_ORIGIN = env.VAULT_API_URL;

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = session.load();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${API_ORIGIN}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    apiFetch<{ token: string; userId: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  listSecrets: (token: string) =>
    apiFetch<{ data: Array<{ id: string; title: string; createdAt: string }> }>(
      "/api/secrets",
      { headers: { Authorization: `Bearer ${token}` } },
    ),

  getSecret: (token: string, id: string) =>
    apiFetch<{
      id: string;
      title: string;
      createdAt: string;
      encryptedData?: string;
    }>(`/api/secrets/${id}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),

  createSecret: (token: string, title: string, content: string) =>
    apiFetch<{ id: string }>("/api/secrets", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ title, content }),
    }),

  rotatePassword: (token: string, oldPassword: string, newPassword: string) =>
    apiFetch<{ ok: boolean }>("/api/auth/rotate", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ oldPassword, newPassword }),
    }),
};
