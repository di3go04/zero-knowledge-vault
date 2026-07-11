"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useApi } from "@/lib/api-client";
import { useSession } from "@/lib/session-store";
import { deriveAuditKey, decryptAuditEvent, type AuditCategory } from "@/lib/crypto-client";
import { clearCryptoKeyRef } from "@/lib/memory-zero";
import {
  Loader2,
  ScrollText,
  RefreshCw,
  Lock,
  AlertTriangle,
  Clock,
} from "lucide-react";

interface AuditLogViewerProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

interface RawLogEntry {
  id: string;
  encryptedEvent: string;
  eventIv: string;
  eventCategory: string;
  createdAt: string;
}

interface DecryptedLogEntry extends RawLogEntry {
  decrypted?: Record<string, unknown>;
  decryptError?: string;
}

const CATEGORY_LABELS: Record<string, string> = {
  auth: "Autenticación",
  secret: "Secreto",
  share: "Share",
  device: "Dispositivo",
  recovery: "Recuperación",
};

const CATEGORY_COLORS: Record<string, string> = {
  auth: "border-primary/40 bg-primary/10 text-primary",
  secret: "border-amber-500/40 bg-amber-500/10 text-amber-500",
  share: "border-purple-500/40 bg-purple-500/10 text-purple-500",
  device: "border-cyan-500/40 bg-cyan-500/10 text-cyan-500",
  recovery: "border-rose-500/40 bg-rose-500/10 text-rose-500",
};

/**
 * Audit Log Viewer — descarga blobs cifrados del servidor y los
 * descifra localmente con la llave de auditoría derivada de masterKey.
 *
 * LIMPIEZA DE MEMORIA: al cerrar, todas las refs a CryptoKey y logs
 * descifrados se setean a null/vacío. La llave de auditoría solo vive
 * en memoria mientras el diálogo está abierto.
 */
export function AuditLogViewer({ open, onOpenChange }: AuditLogViewerProps) {
  const { toast } = useToast();
  const session = useSession();
  const { apiFetch } = useApi();

  const [logs, setLogs] = useState<DecryptedLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  // Refs para limpieza de memoria
  const auditKeyRef = useRef<CryptoKey | null>(null);

  const loadAndDecrypt = useCallback(async () => {
    if (!session.masterKey) return;
    setLoading(true);
    try {
      // 1. Derivar audit key si no está en cache
      if (!auditKeyRef.current) {
        auditKeyRef.current = await deriveAuditKey(session.masterKey);
      }
      const auditKey = auditKeyRef.current;

      // 2. Descargar logs cifrados
      const url = `/api/audit-logs${
        categoryFilter !== "all" ? `?category=${categoryFilter}` : ""
      }`;
      const res = await apiFetch(url);
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al cargar logs");

      const rawLogs: RawLogEntry[] = data.logs ?? [];

      // 3. Descifrar cada log localmente
      const decrypted: DecryptedLogEntry[] = await Promise.all(
        rawLogs.map(async (log) => {
          try {
            const event = await decryptAuditEvent(
              auditKey,
              log.encryptedEvent,
              log.eventIv,
            );
            return { ...log, decrypted: event };
          } catch (err: any) {
            return { ...log, decryptError: err?.message ?? "Error de descifrado" };
          }
        }),
      );

      setLogs(decrypted);
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al cargar logs",
        description: err?.message,
      });
    } finally {
      setLoading(false);
    }
  }, [session.masterKey, categoryFilter, apiFetch, toast]);

  useEffect(() => {
    if (open) {
      loadAndDecrypt();
    }
  }, [open, loadAndDecrypt]);

  // Cleanup al cerrar — zeroing de audit key y logs descifrados
  useEffect(() => {
    if (!open) {
      setLogs([]);
      setCategoryFilter("all");
      // LIMPIEZA DE MEMORIA: desreferenciar audit key
      clearCryptoKeyRef(auditKeyRef);
    }
  }, [open]);

  // Limpieza al desmontar
  useEffect(() => {
    return () => {
      setLogs([]);
      clearCryptoKeyRef(auditKeyRef);
    };
  }, []);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ScrollText className="size-4 text-primary" /> Audit Log
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed">
            Logs cifrados end-to-end. Solo tú puedes descifrarlos con tu llave de auditoría
            (derivada de tu masterKey). El servidor solo ve blobs cifrados + categoría.
          </DialogDescription>
        </DialogHeader>

        {/* Controles */}
        <div className="flex items-center gap-2">
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="h-8 w-44 text-xs">
              <SelectValue placeholder="Todas las categorías" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Todas las categorías</SelectItem>
              <SelectItem value="auth">Autenticación</SelectItem>
              <SelectItem value="secret">Secretos</SelectItem>
              <SelectItem value="share">Shares</SelectItem>
              <SelectItem value="device">Dispositivos</SelectItem>
              <SelectItem value="recovery">Recuperación</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            onClick={loadAndDecrypt}
            disabled={loading}
            className="h-8"
          >
            <RefreshCw className={`mr-1.5 size-3 ${loading ? "animate-spin" : ""}`} />
            Refrescar
          </Button>
          <Badge variant="outline" className="text-[10px]">
            {logs.length} eventos
          </Badge>
        </div>

        {/* Lista de logs */}
        <div className="flex-1 overflow-y-auto rounded-md border border-border/40 bg-background/40 max-h-[55vh]">
          {loading && logs.length === 0 ? (
            <div className="flex items-center justify-center gap-2 p-8 text-xs text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> Cargando y descifrando logs…
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 p-8 text-center">
              <ScrollText className="size-6 text-muted-foreground/60" />
              <p className="text-xs text-muted-foreground">No hay eventos de auditoría.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/30">
              {logs.map((log) => (
                <div key={log.id} className="p-3 hover:bg-background/60">
                  <div className="mb-1.5 flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge
                        variant="outline"
                        className={`text-[9px] ${
                          CATEGORY_COLORS[log.eventCategory] ?? ""
                        }`}
                      >
                        {CATEGORY_LABELS[log.eventCategory] ?? log.eventCategory}
                      </Badge>
                      {log.decrypted?.type ? (
                        <span className="text-[11px] font-medium text-foreground">
                          {String(log.decrypted.type)}
                        </span>
                      ) : null}
                    </div>
                    <div className="flex items-center gap-1 text-[9px] text-muted-foreground">
                      <Clock className="size-2.5" />
                      {new Date(log.createdAt).toLocaleString("es-ES", {
                        day: "2-digit",
                        month: "short",
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </div>
                  </div>

                  {log.decryptError ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-destructive">
                      <AlertTriangle className="size-3" />
                      Error de descifrado: {log.decryptError}
                    </div>
                  ) : log.decrypted ? (
                    <pre className="overflow-x-auto rounded bg-muted/30 p-2 font-mono text-[10px] leading-relaxed text-foreground/80">
                      {JSON.stringify(log.decrypted, null, 2)}
                    </pre>
                  ) : (
                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                      <Lock className="size-3" />
                      Cifrado (no se pudo descifrar)
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="text-center text-[10px] text-muted-foreground">
          Logs descifrados localmente — el servidor nunca vio su contenido.
        </div>
      </DialogContent>
    </Dialog>
  );
}
