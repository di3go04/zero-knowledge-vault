/**
 * Session store — client-side session state with Zustand.
 * Persisted to localStorage so the session survives page reloads.
 * The session token itself is stored in an HttpOnly cookie by the server;
 * here we only keep the user's email and a flag indicating auth status.
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface SessionState {
  email: string | null;
  authenticated: boolean;
  setSession: (email: string) => void;
  logout: () => void;
  clear: () => void;
}

export const useSession = create<SessionState>()(
  persist(
    (set) => ({
      email: null,
      authenticated: false,
      setSession: (email) => set({ email, authenticated: true }),
      logout: () => set({ email: null, authenticated: false }),
      clear: () => set({ email: null, authenticated: false }),
    }),
    { name: "zk-vault-session" }
  )
);

export function isAuthenticated(s: SessionState): boolean {
  return s.authenticated;
}
