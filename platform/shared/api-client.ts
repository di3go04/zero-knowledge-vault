/**
 * Shared API client — generic HTTP wrapper for the ZK Vault API.
 *
 * Each platform imports/adapts this to its own HTTP and storage layer:
 *   - Browser extensions: use fetch + chrome.storage
 *   - React Native: use fetch + AsyncStorage
 *   - Tauri: use fetch + Tauri Store plugin
 */

export interface ApiConfig {
  baseUrl: string;
  getToken: () => Promise<string | null>;
  onUnauthorized?: () => void;
}

export interface SecretListItem {
  id: string;
  title: string;
  createdAt: string;
}

export interface SecretDetail extends SecretListItem {
  encryptedData: string;
  dataIv: string;
  encryptedTitle: string;
  titleIv: string;
  wrappedKey: string;
}

export function createApiClient(config: ApiConfig) {
  async function request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const token = await config.getToken();
    const headers = new Headers(init.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const res = await fetch(`${config.baseUrl}${path}`, { ...init, headers });

    if (res.status === 401) {
      config.onUnauthorized?.();
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`API ${res.status}: ${text || res.statusText}`);
    }

    return res.json();
  }

  return {
    login: (email: string, password: string) =>
      request<{ token: string; userId: string }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      }),

    listSecrets: () =>
      request<{ data: SecretListItem[] }>("/api/secrets"),

    getSecret: (id: string) =>
      request<SecretDetail>(`/api/secrets/${id}`),

    createSecret: (title: string, encryptedData: string, iv: string) =>
      request<{ id: string }>("/api/secrets", {
        method: "POST",
        body: JSON.stringify({ encryptedData, iv }),
      }),

    deleteSecret: (id: string) =>
      request<void>(`/api/secrets/${id}`, { method: "DELETE" }),

    rotatePassword: (oldPassword: string, newPassword: string) =>
      request<{ ok: boolean }>("/api/auth/rotate", {
        method: "POST",
        body: JSON.stringify({ oldPassword, newPassword }),
      }),
  };
}
