/**
 * Módulo 2: hooks de UX y seguridad global.
 *
 *   - useOnlineStatus: detecta pérdida de conexión y dispara toasts.
 *   - useCmdKShortcut: captura Cmd/Ctrl+K y enfoca el campo de búsqueda.
 *   - useHydratedSession: evita el flash de login durante la hidratación
 *     de Zustand persist.
 *
 * Estos hooks son globales — solo se montan una vez (en el layout o en
 * el componente raíz) y operan a través de refs globales para no
 * causar re-renders masivos.
 */
"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "./session-store";

/**
 * Detecta navigator.onLine y dispara un toast cuando cambia.
 *
 * El toast de "perdiste conexión" es destructivo (rojo) para que el
 * usuario sepa que NUEVAS operaciones (crear, compartir, descifrar)
 * van a fallar hasta que vuelva la red. Los secretos ya descifrados
 * siguen accesibles porque viven en memoria.
 */
export function useOnlineStatus(): boolean {
  const { toast } = useToast();
  const [online, setOnline] = useState(
    typeof navigator !== "undefined" ? navigator.onLine : true
  );
  const wasOnlineRef = useRef(online);

  useEffect(() => {
    const onOnline = () => {
      setOnline(true);
      if (!wasOnlineRef.current) {
        wasOnlineRef.current = true;
        toast({
          title: "Conexión restablecida",
          description: "Puedes seguir usando la bóveda con normalidad.",
        });
      }
    };
    const onOffline = () => {
      setOnline(false);
      if (wasOnlineRef.current) {
        wasOnlineRef.current = false;
        toast({
          variant: "destructive",
          title: "Sin conexión a internet",
          description:
            "Las operaciones que requieren red (crear, compartir, refrescar) fallarán hasta que vuelva la conexión. Los secretos ya descifrados siguen accesibles.",
        });
      }
    };
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, [toast]);

  return online;
}

/**
 * Ref global al campo de búsqueda del VaultView.
 * VaultView registra su input aquí cuando se monta; el atajo global
 * Cmd+K / Ctrl+K lo enfoca sin necesidad de pasar props por el árbol.
 */
const searchInputRef: { current: HTMLInputElement | null } = { current: null };

export function registerSearchInput(el: HTMLInputElement | null): void {
  searchInputRef.current = el;
}

/**
 * Captura Cmd+K (macOS) / Ctrl+K (Linux/Windows) y enfoca el campo
 * de búsqueda. Solo se monta una vez en el layout raíz.
 */
export function useCmdKShortcut(): void {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const el = searchInputRef.current;
        if (el) {
          el.focus();
          el.select();
        }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
}

/**
 * Devuelve true cuando Zustand persist ha terminado de hidratar
 * localStorage. Esto evita el "login flash" — el parpadeo donde la
 * AuthView aparece un instante antes de que el store cargue la sesión.
 *
 * Uso en page.tsx:
 *   const hydrated = useHydratedSession();
 *   if (!hydrated) return <SplashSkeleton />;
 */
export function useHydratedSession(): boolean {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    // Zustand persist hydrates synchronously on the client after mount.
    setHydrated(true);
  }, []);
  return hydrated;
}

/**
 * Hook que retorna el email enmascarado para mostrar en headers/UI.
 * Reactivo a cambios de sesión — si el usuario hace login/logout,
 * el componente que use este hook se re-renderiza solo.
 */
export function useMaskedEmail(): string | null {
  const email = useSession((s) => s.email);
  return maskEmailHelper(email);
}

function maskEmailHelper(email: string | null): string | null {
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

/**
 * Hook para validar que la sesión está completa (token + crypto).
 * Si falta algo, se considera "no autenticada de verdad" y el VaultView
 * debe forzar re-login.
 */
export function useSessionHealth(): { ok: boolean; missing: string[] } {
  const session = useSession();
  const missing: string[] = [];
  if (!session.authenticated) missing.push("authenticated");
  if (!session.sessionToken) missing.push("sessionToken");
  if (!session.userId) missing.push("userId");
  if (!session.masterKey) missing.push("masterKey");
  if (!session.privateKey) missing.push("privateKey");
  return { ok: missing.length === 0, missing };
}

/**
 * Helper memoizado para limpiar TODA la sesión + crypto de la memoria.
 * Llamado por:
 *   - Botón "Cerrar Sesión" del header dropdown
 *   - useSessionTimeout (auto-lock por inactividad)
 *   - useTabLock (al cambiar de pestaña)
 *
 * Las CryptoKey son no-extractables, pero desreferenciarlas permite
 * que el GC las recolecte. No podemos forzar zeroing de CryptoKey en
 * JS, pero sí podemos asegurarnos de que no queden referencias.
 */
export function useClearSessionCallback(): () => void {
  const logout = useSession((s) => s.logout);
  return useCallback(() => {
    // Best-effort: desreferenciar todas las CryptoKey para acelerar GC.
    // En navegadores con FinalizationRegistry configurado en memory.ts,
    // esto dispara el cleanup automático.
    logout();
  }, [logout]);
}
