"use client";
import { useState, useEffect } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Keyboard } from "lucide-react";

const SHORTCUTS = [
  { keys: "Ctrl+N", action: "Crear nuevo secreto" },
  { keys: "Ctrl+F", action: "Buscar en bóveda" },
  { keys: "Ctrl+L", action: "Cerrar sesión (lock)" },
  { keys: "Ctrl+R", action: "Refrescar bóveda" },
  { keys: "Ctrl+K", action: "Command Palette" },
  { keys: "Esc", action: "Cerrar diálogo" },
];

export function KeyboardShortcutsHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Keyboard className="size-4" /> Atajos de teclado</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          {SHORTCUTS.map((s) => (
            <div key={s.keys} className="flex items-center justify-between py-1">
              <span className="text-sm">{s.action}</span>
              <kbd className="rounded border border-border/40 bg-muted px-2 py-0.5 text-xs font-mono">{s.keys}</kbd>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
