/**
 * useSessionTimeout — auto-locks the vault after N minutes of inactivity.
 * Calls the provided callback (or clears the session by default) when
 * the timer fires.
 */
import { useEffect, useRef } from "react";
import { useSession } from "./session-store";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

export function useSessionTimeout(timeoutMs: number = DEFAULT_TIMEOUT_MS): void {
  const logout = useSession((s) => s.logout);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const reset = () => {
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        logout();
      }, timeoutMs);
    };

    const events: (keyof WindowEventMap)[] = [
      "mousemove",
      "keydown",
      "click",
      "scroll",
      "touchstart",
    ];

    events.forEach((e) => window.addEventListener(e, reset));
    reset();

    return () => {
      events.forEach((e) => window.removeEventListener(e, reset));
      if (timer.current) clearTimeout(timer.current);
    };
  }, [logout, timeoutMs]);
}
