"use client";

import { useEffect, useRef, useCallback } from "react";
import { useSession } from "./session-store";
import { useApi } from "./api-client";

const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutos
const CHECK_INTERVAL_MS = 30 * 1000; // verificar cada 30s
const WARNING_BEFORE_MS = 60 * 1000; // avisar 1 min antes

/**
 * Hook que detecta inactividad del usuario y fuerza logout automático
 * tras 15 minutos sin actividad (mouse, keyboard, scroll, touch).
 *
 *
 * Limpia las llaves de memoria y llama al logout server-side.
 */
export function useSessionTimeout() {
  const lastActivityRef = useRef<number>(Date.now());
  const warnedRef = useRef<boolean>(false);
  const { serverLogout } = useApi();
  const sessionToken = useSession((s) => s.sessionToken);

  const resetActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
    warnedRef.current = false;
  }, []);

  useEffect(() => {
    if (!sessionToken) return;

    // Registrar eventos de actividad
    const events = ["mousedown", "keydown", "scroll", "touchstart", "mousemove"];

    const onActivity = () => resetActivity();
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));

    // Verificar inactividad cada 30s
    const interval = setInterval(async () => {
      const elapsed = Date.now() - lastActivityRef.current;
      
      if (elapsed >= INACTIVITY_TIMEOUT_MS) {
        // Timeout — forzar logout
        console.warn("[session] Timeout por inactividad — cerrando sesión");
        await serverLogout();
      } else if (elapsed >= INACTIVITY_TIMEOUT_MS - WARNING_BEFORE_MS && !warnedRef.current) {
        // Advertir 1 min antes
        warnedRef.current = true;
        console.info("[session] Sesión expirará en 1 minuto por inactividad");
      }
    }, CHECK_INTERVAL_MS);

    return () => {
      events.forEach((e) => window.removeEventListener(e, onActivity));
      clearInterval(interval);
    };
  }, [sessionToken, resetActivity, serverLogout]);

  return { resetActivity };
}
