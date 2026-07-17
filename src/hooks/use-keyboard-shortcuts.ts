"use client";

import { useEffect, useCallback, useRef } from "react";

export type ShortcutMap = Record<
  string,
  {
    handler: (e: KeyboardEvent) => void;
    description: string;
    preventDefault?: boolean;
  }
>;

/**
 * useKeyboardShortcuts — Global keyboard shortcut manager.
 *
 * Usage:
 * ```ts
 * useKeyboardShortcuts({
 *   "ctrl+k": { handler: () => openSearch(), description: "Open search" },
 *   "ctrl+n": { handler: () => createSecret(), description: "New secret" },
 *   "escape": { handler: () => closeDialog(), description: "Close dialog" },
 * });
 * ```
 *
 * Shortcut format: [modifiers+]key
 * Modifiers: ctrl, shift, alt, meta
 * Key: single character or key name (Escape, Enter, etc.)
 * Examples: "ctrl+k", "ctrl+shift+f", "escape", "ctrl+alt+n"
 */
export function useKeyboardShortcuts(shortcuts: ShortcutMap) {
  const shortcutsRef = useRef(shortcuts);
  shortcutsRef.current = shortcuts;

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    const parts: string[] = [];
    if (e.ctrlKey) parts.push("ctrl");
    if (e.shiftKey) parts.push("shift");
    if (e.altKey) parts.push("alt");
    if (e.metaKey) parts.push("meta");

    const key = e.key.length === 1 ? e.key.toLowerCase() : e.key.toLowerCase();
    parts.push(key);
    const combo = parts.join("+");

    const shortcut = shortcutsRef.current[combo];
    if (shortcut) {
      if (shortcut.preventDefault !== false) {
        e.preventDefault();
        e.stopPropagation();
      }
      shortcut.handler(e);
    }
  }, []);

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}

/**
 * Returns common vault shortcuts for use in useKeyboardShortcuts.
 */
export function getDefaultShortcuts(handlers: {
  openSearch?: () => void;
  createSecret?: () => void;
  closeDialog?: () => void;
  focusVault?: () => void;
}): ShortcutMap {
  const s: ShortcutMap = {};

  if (handlers.openSearch) {
    s["ctrl+k"] = { handler: handlers.openSearch, description: "Buscar secretos" };
  }
  if (handlers.createSecret) {
    s["ctrl+n"] = { handler: handlers.createSecret, description: "Nuevo secreto" };
  }
  if (handlers.closeDialog) {
    s["escape"] = { handler: handlers.closeDialog, description: "Cerrar diálogo" };
  }
  if (handlers.focusVault) {
    s["ctrl+\\"] = { handler: handlers.focusVault, description: "Ir a la bóveda" };
  }

  return s;
}
