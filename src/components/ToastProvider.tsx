"use client";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Check, X, AlertTriangle, Info } from "lucide-react";

type ToastType = "success" | "error" | "warning" | "info";
interface Toast { id: string; type: ToastType; title: string; description?: string; action?: { label: string; onClick: () => void } }
interface Ctx { toasts: Toast[]; add: (t: Omit<Toast, "id">) => void; remove: (id: string) => void }

const ToastCtx = createContext<Ctx>({ toasts: [], add: () => {}, remove: () => {} });
export const useToastCtx = () => useContext(ToastCtx);

const icons = { success: Check, error: X, warning: AlertTriangle, info: Info };
const colors = { success: "text-primary", error: "text-destructive", warning: "text-amber-500", info: "text-muted-foreground" };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const add = (t: Omit<Toast, "id">) => {
    const id = (crypto.randomUUID?.() ?? `id-${Date.now()}-${Math.floor(performance.now())}`);
    setToasts((prev) => [...prev, { ...t, id }]);
    setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), 5000);
  };
  const remove = (id: string) => setToasts((prev) => prev.filter((x) => x.id !== id));

  return (
    <ToastCtx.Provider value={{ toasts, add, remove }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
        {toasts.map((t) => {
          const Icon = icons[t.type];
          return (
            <div key={t.id} className="flex items-start gap-3 rounded-lg border border-border/60 bg-card p-4 shadow-lg max-w-sm animate-in slide-in-from-right">
              <Icon className={`mt-0.5 size-4 shrink-0 ${colors[t.type]}`} />
              <div className="flex-1">
                <p className="text-sm font-medium">{t.title}</p>
                {t.description ? <p className="mt-0.5 text-xs text-muted-foreground">{t.description}</p> : null}
                {t.action ? <button onClick={t.action.onClick} className="mt-1 text-xs text-primary hover:underline">{t.action.label}</button> : null}
              </div>
              <button onClick={() => remove(t.id)} className="text-muted-foreground hover:text-foreground"><X className="size-3.5" /></button>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}
