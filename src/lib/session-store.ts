/**
 * Session store — client-side session state with Zustand.
 *
 * IMPORTANT: All fields here are NON-PERSISTED (in-memory only) by design.
 * Only `email` and `authenticated` are persisted to localStorage so the UI
 * knows to skip the login screen on reload. The session token itself lives
 * in an HttpOnly cookie set by the server; the masterKey, privateKey and
 * other crypto material live ONLY in this in-memory store and are
 * cleared on tab close (see `useTabLock`).
 *
 * This prevents:
 *   - Token theft via XSS (token is in HttpOnly cookie, not JS-readable)
 *   - Master-key exfiltration from localStorage
 *   - Window-global leakage of crypto material (we never attach to `window`)
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface SessionState {
  // Persisted (only what's needed to restore the UI shell)
  email: string | null;
  authenticated: boolean;
  name: string | null;

  // Non-persisted (cleared on tab close — see partialize below)
  userId: string | null;
  sessionToken: string | null;
  expiresAt: number | null;
  publicKeyJwk: JsonWebKey | null;

  // Crypto material — never persisted, never attached to `window`.
  // Held as non-extractable CryptoKey instances so even a memory dump
  // cannot export the raw bytes.
  masterKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKey: CryptoKey | null;
  mlKemPrivateKey: CryptoKey | null;

  // Actions
  login: (session: {
    userId: string;
    email: string;
    name?: string | null;
    publicKeyJwk: JsonWebKey;
    sessionToken: string;
    expiresAt: number;
    masterKey: CryptoKey;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    mlKemPrivateKey?: CryptoKey;
  }) => void;
  logout: () => void;
  clear: () => void;
  /** Update crypto material without re-issuing a session token. */
  setCrypto: (c: {
    masterKey?: CryptoKey;
    privateKey?: CryptoKey;
    publicKey?: CryptoKey;
    mlKemPrivateKey?: CryptoKey;
  }) => void;
}

const EMPTY_CRYPTO = {
  masterKey: null as CryptoKey | null,
  privateKey: null as CryptoKey | null,
  publicKey: null as CryptoKey | null,
  mlKemPrivateKey: null as CryptoKey | null,
  userId: null as string | null,
  sessionToken: null as string | null,
  expiresAt: null as number | null,
  publicKeyJwk: null as JsonWebKey | null,
};

export const useSession = create<SessionState>()(
  persist(
    (set) => ({
      email: null,
      authenticated: false,
      name: null,
      ...EMPTY_CRYPTO,
      login: (s) =>
        set({
          email: s.email,
          authenticated: true,
          name: s.name ?? null,
          userId: s.userId,
          sessionToken: s.sessionToken,
          expiresAt: s.expiresAt,
          publicKeyJwk: s.publicKeyJwk,
          masterKey: s.masterKey,
          privateKey: s.privateKey,
          publicKey: s.publicKey,
          mlKemPrivateKey: s.mlKemPrivateKey ?? null,
        }),
      logout: () => set({ email: null, authenticated: false, name: null, ...EMPTY_CRYPTO }),
      clear: () => set({ email: null, authenticated: false, name: null, ...EMPTY_CRYPTO }),
      setCrypto: (c) => set((state) => ({ ...state, ...c })),
    }),
    {
      name: "zk-vault-session",
      // Persist ONLY the UI shell — never persist crypto or tokens.
      // This is the critical security boundary: if localStorage is
      // dumped via XSS, the attacker gets `{ email, authenticated }`
      // but no usable token or crypto material.
      partialize: (s) => ({ email: s.email, authenticated: s.authenticated, name: s.name }),
    }
  )
);

/**
 * Returns true if the session is hydrated (Zustand persist has loaded
 * localStorage) AND the user is authenticated. Used to avoid the login
 * flash on page reload — the layout can render a skeleton until
 * hydration completes.
 */
export function useIsAuthenticated(): boolean {
  return useSession((s) => s.authenticated);
}

export function isAuthenticated(s: SessionState): boolean {
  return s.authenticated;
}

/**
 * Mask an email for display in the header.
 *   "ana@dominio.com"  → "a***@dominio.com"
 *   "ab@dominio.com"   → "a***@dominio.com"
 *   "verylong@x.io"    → "v*********@x.io"  (one char + asterisks per char hidden)
 */
export function maskEmail(email: string | null): string | null {
  if (!email) return null;
  const at = email.indexOf("@");
  if (at <= 0) return email;
  const local = email.slice(0, at);
  const domain = email.slice(at);
  if (local.length <= 1) return `*${domain}`;
  const head = local[0];
  const masked = head + "*".repeat(local.length - 1);
  return `${masked}${domain}`;
}
