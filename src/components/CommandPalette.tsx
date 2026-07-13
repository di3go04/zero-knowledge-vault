"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "@/lib/session-store";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Search, Lock, Plus, ShieldCheck, Smartphone, KeyRound, ScrollText, LogOut, RefreshCw } from "lucide-react";

interface Command {
  id: string;
  label: string;
  icon: React.ReactNode;
  shortcut?: string;
  action: () => void;
  group: "Navegación" | "Secretos" | "Cuenta" | "Herramientas";
}

/**
 * Command Palette (Cmd+K) — búsqueda global de acciones.
 *
 */
export function CommandPalette({
  open,
  onOpenChange,
  actions,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  actions: {
    onNewSecret?: () => void;
    onLogout?: () => void;
    onRefresh?: () => void;
    onRotate?: () => void;
    onEnrollDevice?: () => void;
    onRecovery?: () => void;
    onAudit?: () => void;
  };
}) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const session = useSession();

  const commands: Command[] = [
    {
      id: "new-secret",
      label: "Crear nuevo secreto",
      icon: <Plus className="size-4" />,
      shortcut: "Ctrl+N",
      action: () => { actions.onNewSecret?.(); onOpenChange(false); },
      group: "Secretos",
    },
    {
      id: "refresh",
      label: "Refrescar bóveda",
      icon: <RefreshCw className="size-4" />,
      shortcut: "Ctrl+R",
      action: () => { actions.onRefresh?.(); onOpenChange(false); },
      group: "Secretos",
    },
    {
      id: "rotate",
      label: "Rotar contraseña maestra",
      icon: <KeyRound className="size-4" />,
      action: () => { actions.onRotate?.(); onOpenChange(false); },
      group: "Cuenta",
    },
    {
      id: "enroll-device",
      label: "Autorizar nuevo dispositivo",
      icon: <Smartphone className="size-4" />,
      action: () => { actions.onEnrollDevice?.(); onOpenChange(false); },
      group: "Cuenta",
    },
    {
      id: "recovery",
      label: "Configurar backup de recuperación",
      icon: <ShieldCheck className="size-4" />,
      action: () => { actions.onRecovery?.(); onOpenChange(false); },
      group: "Cuenta",
    },
    {
      id: "audit",
      label: "Ver audit log",
      icon: <ScrollText className="size-4" />,
      action: () => { actions.onAudit?.(); onOpenChange(false); },
      group: "Herramientas",
    },
    {
      id: "logout",
      label: "Cerrar sesión",
      icon: <LogOut className="size-4" />,
      shortcut: "Ctrl+L",
      action: () => { actions.onLogout?.(); onOpenChange(false); },
      group: "Cuenta",
    },
  ];

  const filtered = query
    ? commands.filter((c) => c.label.toLowerCase().includes(query.toLowerCase()))
    : commands;

  // Reset al abrir
  useEffect(() => {
    if (open) {
      // Usar microtask para evitar setState síncrono en effect
      Promise.resolve().then(() => {
        setQuery("");
        setSelectedIndex(0);
      });
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Navegación por teclado
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      filtered[selectedIndex]?.action();
    }
  }, [filtered, selectedIndex]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="overflow-hidden p-0 sm:max-w-xl" >
        <div className="flex items-center border-b border-border/40 px-3" >
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Escribe un comando o búsqueda…"
            className="h-12 w-full bg-transparent px-2 text-sm outline-none placeholder:text-muted-foreground"
            aria-label="Búsqueda de comandos"
            role="combobox"
            aria-expanded={true}
            aria-controls="command-list"
          />
          <kbd className="hidden shrink-0 rounded border border-border/40 px-1.5 py-0.5 text-[10px] text-muted-foreground sm:block">
            ESC
          </kbd>
        </div>
        <div className="max-h-80 overflow-y-auto p-2" id="command-list" role="listbox">
          {filtered.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No se encontraron comandos
            </div>
          ) : (
            filtered.map((cmd, i) => (
              <button
                key={cmd.id}
                role="option"
                aria-selected={i === selectedIndex}
                onMouseEnter={() => setSelectedIndex(i)}
                onClick={() => cmd.action()}
                className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  i === selectedIndex ? "bg-primary/10 text-primary" : "text-foreground"
                }`}
              >
                {cmd.icon}
                <span className="flex-1">{cmd.label}</span>
                {cmd.shortcut ? (
                  <kbd className="shrink-0 rounded border border-border/40 px-1.5 py-0.5 text-[10px] text-muted-foreground">
                    {cmd.shortcut}
                  </kbd>
                ) : null}
                <span className="shrink-0 text-[10px] text-muted-foreground/60">{cmd.group}</span>
              </button>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
