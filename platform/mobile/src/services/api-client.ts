// React Native API Client
//
// Thin wrapper around fetch for the vault API. Injects session token from
// AsyncStorage. Crypto operations (Web Crypto API) are not available in RN;
// the mobile app delegates crypto to the native Keychain/Keystore + NaCl.

import AsyncStorage from "@react-native-async-storage/async-storage";

const API_ORIGIN = __DEV__
  ? "http://localhost:3000"
  : "https://vault.zk.example.com";

export interface Secret {
  id: string;
  title: string;
  createdAt: string;
}

export interface SecretDetail extends Secret {
  encryptedData: string;
  dataIv: string;
}

export async function getSessionToken(): Promise<string | null> {
  return AsyncStorage.getItem("sessionToken");
}

export async function setSessionToken(token: string): Promise<void> {
  await AsyncStorage.setItem("sessionToken", token);
}

export async function clearSession(): Promise<void> {
  await AsyncStorage.removeItem("sessionToken");
}

async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token = await getSessionToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${API_ORIGIN}${path}`, { ...init, headers });
  if (!res.ok) {
    if (res.status === 401) await clearSession();
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    apiFetch<{ token: string; userId: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  listSecrets: () =>
    apiFetch<{ data: Secret[] }>("/api/secrets"),

  getSecret: (id: string) =>
    apiFetch<SecretDetail>(`/api/secrets/${id}`),

  createSecret: (title: string, encryptedData: string, iv: string) =>
    apiFetch<{ id: string }>("/api/secrets", {
      method: "POST",
      body: JSON.stringify({ title, encryptedData, iv }),
    }),

  deleteSecret: (id: string) =>
    apiFetch<void>(`/api/secrets/${id}`, { method: "DELETE" }),
};
