/**
 * API client — thin wrapper around fetch that:
 *  - Adds JSON Content-Type headers
 *  - Throws on non-2xx responses
 *  - Returns parsed JSON
 *
 * Also exports a `useApi` hook for React components that need a
 * fetcher bound to the current session.
 */
import { useCallback } from "react";

export async function api<T = unknown>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "same-origin",
  });

  if (!res.ok) {
    let message = `Request failed: ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // ignore JSON parse errors
    }
    throw new Error(message);
  }

  return res.json() as Promise<T>;
}

/**
 * React hook that returns fetch helpers tied to the current session.
 * `apiFetch` is a thin wrapper around fetch with credentials included.
 * `serverLogout` calls /api/auth/logout and clears the local session.
 */
export function useApi() {
  const apiFetch = useCallback(
    (path: string, init?: RequestInit) =>
      fetch(path, {
        ...init,
        headers: {
          "Content-Type": "application/json",
          ...(init?.headers ?? {}),
        },
        credentials: "same-origin",
      }),
    []
  );

  const serverLogout = useCallback(async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
      });
    } catch {
      // ignore network errors on logout
    }
  }, []);

  return { apiFetch, serverLogout };
}
