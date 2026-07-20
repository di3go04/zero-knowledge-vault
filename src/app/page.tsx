"use client";

import { useEffect, useRef, useState } from "react";
import { AuthView } from "@/components/AuthView";
import { VaultView } from "@/components/VaultView";
import { ErrorBoundary } from "@/components/errors/ErrorBoundary";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useSession, isAuthenticated } from "@/lib/session-store";
import {
  useOnlineStatus,
  useCmdKShortcut,
  useHydratedSession,
  useMaskedEmail,
  useClearSessionCallback,
} from "@/lib/use-global-ux";
import { Lock, LogOut, ChevronDown, ShieldCheck, WifiOff } from "lucide-react";

const ALGO_BADGES: Array<{ label: string; tone: "primary" | "accent" | "destructive" }> = [
  { label: "AES-256-GCM", tone: "primary" },
  { label: "ML-KEM-768", tone: "accent" },
  { label: "ECDH", tone: "destructive" },
];

const TONE_CLASSES: Record<string, string> = {
  primary: "border-primary/30 bg-primary/10 text-primary",
  accent: "border-sky-500/30 bg-sky-500/10 text-sky-400",
  destructive: "border-amber-500/30 bg-amber-500/10 text-amber-500",
};

export default function Home() {
  const session = useSession();
  const authed = isAuthenticated(session);
  const hydrated = useHydratedSession();
  const online = useOnlineStatus();
  useCmdKShortcut();
  const clearSession = useClearSessionCallback();
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
      }).catch(() => {}); // network failure is OK — we clear locally anyway
    } finally {
      clearSession();
      setLoggingOut(false);
    }
  };

  // Módulo 1: defensa en profundidad — aseguramos que ninguna llave
  // criptográfica se filtre al objeto global `window`. El store de
  // Zustand ya evita persistir crypto material, pero por si alguna
  // librería third-party lo hace, lo limpiamos.
  useEffect(() => {
    const forbidden = ["__masterKey", "__privateKey", "__sessionToken", "ZK_VAULT"];
    for (const key of forbidden) {
      if (key in window) {
        try {
          delete (window as Record<string, unknown>)[key];
        } catch {
          // ignore — read-only
        }
      }
    }
  }, []);

  // Módulo 1: estado de carga durante hidratación para evitar parpadeo.
  if (!hydrated) {
    return <SplashSkeleton />;
  }

  return (
    <div className="flex h-screen flex-col bg-background text-foreground overflow-hidden">
      {/* Módulo 2: Header fijo de verdad (sticky top-0 con altura fija) */}
      <header className="sticky top-0 z-30 h-14 shrink-0 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="mx-auto flex h-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
          {/* Logo + título */}
          <div className="flex items-center gap-2.5">
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary/15">
              <Lock className="size-5 text-primary" />
            </div>
            <div>
              <h1 className="text-sm font-semibold leading-tight sm:text-base" translate="no">
                Zero-Knowledge Vault
              </h1>
              <p className="hidden text-[10px] text-muted-foreground sm:block">
                Gestor de contraseñas · cifrado end-to-end en el navegador
              </p>
            </div>
          </div>

          {/* Módulo 3: badges técnicos — algoritmos separados en bloques visuales */}
          <div className="hidden items-center gap-1.5 md:flex">
            {ALGO_BADGES.map((b) => (
              <span
                key={b.label}
                className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium ${TONE_CLASSES[b.tone]}`}
                translate="no"
              >
                <ShieldCheck className="size-2.5" />
                {b.label}
              </span>
            ))}
          </div>

          {/* Módulo 2: Dropdown interactivo del usuario (reemplaza span estático) */}
          <div className="flex items-center gap-2">
            {authed ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-card px-2.5 text-[11px] text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label="Menú de cuenta"
                  >
                    <span className="font-mono" translate="no">
                      <MaskedEmail />
                    </span>
                    <ChevronDown className="size-3 opacity-60" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel className="font-normal">
                    <div className="flex flex-col space-y-1">
                      <p className="text-xs font-medium leading-none" translate="no">
                        {session.email}
                      </p>
                      {session.name ? (
                        <p className="text-[10px] text-muted-foreground">{session.name}</p>
                      ) : null}
                      <p className="text-[10px] text-muted-foreground">
                        Sesión HMAC · token en HttpOnly cookie
                      </p>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={handleLogout}
                    disabled={loggingOut}
                    className="text-destructive focus:bg-destructive/10 focus:text-destructive"
                  >
                    <LogOut className="mr-2 size-3.5" />
                    {loggingOut ? "Cerrando…" : "Cerrar sesión"}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
          </div>
        </div>
      </header>

      {/* Módulo 2: banner offline (debajo del header) */}
      {!online ? (
        <div className="shrink-0 border-b border-amber-500/40 bg-amber-500/10 px-4 py-1.5">
          <div className="mx-auto flex max-w-7xl items-center gap-2 text-[11px] text-amber-500">
            <WifiOff className="size-3.5 shrink-0" />
            <span>Sin conexión — operaciones de red no disponibles</span>
          </div>
        </div>
      ) : null}

      {/* Módulo 2: contenedor con scroll interno independiente.
          El header queda fijo y solo el contenido scrollea. */}
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 sm:py-8">
          {authed ? (
            <ErrorBoundary
              fallback={({ error, reset }) => (
                <div className="mx-auto max-w-md space-y-3 rounded-lg border border-destructive/40 bg-destructive/5 p-6 text-center">
                  <h2 className="text-sm font-semibold text-destructive">
                    Error al procesar la bóveda
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    Se detectó un payload corrupto o un error criptográfico inesperado.
                    La sesión sigue activa, pero la vista actual no pudo renderizarse.
                  </p>
                  <pre className="max-h-32 overflow-auto rounded bg-muted p-2 text-left text-[10px] text-muted-foreground">
                    {error?.message ?? "Error desconocido"}
                  </pre>
                  <button
                    type="button"
                    onClick={reset}
                    className="rounded-md border border-border bg-background px-3 py-1.5 text-xs hover:bg-accent"
                  >
                    Reintentar
                  </button>
                </div>
              )}
            >
              <VaultView />
            </ErrorBoundary>
          ) : (
            <AuthView />
          )}
        </div>
      </main>

      {/* Footer opcional */}
      <footer className="shrink-0 border-t border-border bg-background/50 py-2">
        <div className="mx-auto max-w-7xl px-4 text-center text-[10px] text-muted-foreground sm:px-6">
          <p>
            Implementación de referencia · Web Crypto API · El servidor nunca recibe llaves
            maestras, llaves privadas en claro, ni llaves simétricas.
          </p>
        </div>
      </footer>
    </div>
  );
}

function MaskedEmail() {
  const masked = useMaskedEmail();
  return <>{masked ?? "—"}</>;
}

function SplashSkeleton() {
  // Módulo 1: skeleton mostrado durante la hidratación de Zustand persist.
  // Evita el flash de AuthView cuando ya hay una sesión persistida.
  return (
    <div className="flex h-screen items-center justify-center bg-background text-foreground">
      <div className="flex flex-col items-center gap-3">
        <div className="flex size-12 animate-pulse items-center justify-center rounded-xl bg-primary/15">
          <Lock className="size-6 text-primary" />
        </div>
        <div className="h-3 w-32 animate-pulse rounded bg-muted" />
        <div className="h-2 w-24 animate-pulse rounded bg-muted" />
      </div>
    </div>
  );
}
