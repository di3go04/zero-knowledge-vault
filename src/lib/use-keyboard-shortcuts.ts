"use client";

import { useEffect, useCallback } from "react";

interface ShortcutHandlers {
  onNewSecret?: () => void;
  onSearch?: () => void;
  onLock?: () => void;
  onRefresh?: () => void;
}

/**
 * Hook de atajos de teclado globales.
 *
 */
export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  const handleKey = useCallback((e: KeyboardEvent) => {
    // Solo si Ctrl/Cmd está presionado
    if (!(e.ctrlKey || e.metaKey)) return;
    
    switch (e.key.toLowerCase()) {
      case "n":
        e.preventDefault();
        handlers.onNewSecret?.();
        break;
      case "f":
        e.preventDefault();
        handlers.onSearch?.();
        break;
      case "l":
        e.preventDefault();
        handlers.onLock?.();
        break;
      case "r":
        e.preventDefault();
        handlers.onRefresh?.();
        break;
    }
  }, [handlers]);

  useEffect(() => {
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [handleKey]);
}
