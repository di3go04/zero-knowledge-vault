"use client";

import { useEffect, useRef } from "react";
import { useSession } from "./session-store";
import { useApi } from "./api-client";

/**
 * Hook que detecta cuando el usuario minimiza la pestaña o cambia
 * a otra pestaña (document.visibilitychange) y fuerza logout si
 * han pasado más de 30 segundos fuera.
 *
 *
 * Previene que alguien use el equipo del usuario mientras está away.
 */
const AWAY_TIMEOUT_MS = 30 * 1000; // 30 segundos fuera → lock

export function useTabLock() {
  const hiddenSinceRef = useRef<number | null>(null);
  const sessionToken = useSession((s) => s.sessionToken);
  const { serverLogout } = useApi();

  useEffect(() => {
    if (!sessionToken) return;

    const onVisibilityChange = async () => {
      if (document.hidden) {
        // Pestaña oculta — empezar contador
        hiddenSinceRef.current = Date.now();
      } else {
        // Pestaña visible de nuevo
        if (hiddenSinceRef.current !== null) {
          const awayMs = Date.now() - hiddenSinceRef.current;
          hiddenSinceRef.current = null;
          if (awayMs >= AWAY_TIMEOUT_MS) {
            console.warn("[session] Lock por abandono de pestaña — cerrando sesión");
            await serverLogout();
          }
        }
      }
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [sessionToken, serverLogout]);
}
