/**
 * useTabLock — locks the vault when the user switches to another tab
 * or minimizes the window. Restores nothing automatically; the user
 * must re-authenticate.
 */
import { useEffect } from "react";
import { useSession } from "./session-store";

export function useTabLock(): void {
  const logout = useSession((s) => s.logout);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        logout();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [logout]);
}
