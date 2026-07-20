"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { useApi } from "@/lib/api-client";
import { registerSearchInput } from "@/lib/use-global-ux";
import { exportVaultToEncryptedJson } from "@/lib/vault-export";
import {
  Lock,
  Plus,
  RefreshCw,
  Share2,
  Eye,
  Loader2,
  Inbox,
  ShieldCheck,
  LogOut,
  KeyRound,
  Clock,
  Trash2,
  UserX,
  KeyRound as RotateIcon,
  Smartphone,
  KeyRound as RecoveryIcon,
  ScrollText,
  Search,
  Download,
  WifiOff,
} from "lucide-react";
import { CreateSecretDialog } from "./CreateSecretDialog";
import { ViewSecretDialog, type SecretListItem } from "./ViewSecretDialog";
import { ShareSecretDialog } from "./ShareSecretDialog";
import { RotatePasswordDialog } from "./RotatePasswordDialog";
import { EnrollDeviceDialog } from "./EnrollDeviceDialog";
import { RecoverySetupDialog } from "./RecoverySetupDialog";
import { AuditLogViewer } from "./AuditLogViewer";
import { useSessionTimeout } from "@/lib/use-session-timeout";
import { useTabLock } from "@/lib/use-tab-lock";

export function VaultView() {
  const { toast } = useToast();
  const session = useSession();
  const logout = useSession((s) => s.logout);
  const { apiFetch, serverLogout } = useApi();
  useSessionTimeout(); //
  useTabLock(); //

  const [secrets, setSecrets] = useState<SecretListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [viewOpen, setViewOpen] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const [selected, setSelected] = useState<SecretListItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SecretListItem | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<SecretListItem | null>(null);
  const [busyAction, setBusyAction] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [enrollDeviceOpen, setEnrollDeviceOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const [auditLogOpen, setAuditLogOpen] = useState(false);

  // Módulo 2: campo de búsqueda para Cmd+K
  const [search, setSearch] = useState("");
  const searchRef = useRef<HTMLInputElement | null>(null);

  // Módulo 4: diálogo de exportación cifrada
  const [exportOpen, setExportOpen] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);

  // Módulo 2: registrar input para que el atajo global Cmd+K lo enfoque
  useEffect(() => {
    registerSearchInput(searchRef.current);
    return () => registerSearchInput(null);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/api/secrets");
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al cargar");
      setSecrets(data.secrets ?? []);
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al cargar secretos",
        description: err?.message,
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  function openView(s: SecretListItem) {
    setSelected(s);
    setViewOpen(true);
  }
  function openShare(s: SecretListItem) {
    setSelected(s);
    setShareOpen(true);
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setBusyAction(true);
    try {
      const res = await apiFetch(`/api/secrets/${deleteTarget.id}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al borrar");
      toast({
        title: "Secreto borrado",
        description:
          "Secreto y todas sus shares eliminados del servidor. Copias descifradas localmente por destinatarios previos no pueden ser revocadas.",
      });
      setDeleteTarget(null);
      load();
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al borrar",
        description: err?.message,
      });
    } finally {
      setBusyAction(false);
    }
  }

  async function confirmRevoke() {
    if (!revokeTarget) return;
    setBusyAction(true);
    try {
      const res = await apiFetch(`/api/shares`, {
        method: "DELETE",
        body: JSON.stringify({
          secretId: revokeTarget.id,
          recipientId: session.userId, // esto es para "compartidos conmigo" — salir del share
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al revocar");
      toast({
        title: "Has salido del secreto",
        description: `Ya no verás "${revokeTarget.id.slice(-8)}" en tu bóveda.`,
      });
      setRevokeTarget(null);
      load();
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error",
        description: err?.message,
      });
    } finally {
      setBusyAction(false);
    }
  }

  const mine = useMemo(() => secrets.filter((s) => s.ownedByMe), [secrets]);
  const shared = useMemo(() => secrets.filter((s) => !s.ownedByMe), [secrets]);

  // Módulo 2: filtrado por búsqueda — busca en el título cifrado (que
  // sigue siendo ilegible para el server, pero el cliente puede buscar
  // coincidencias parciales en los bytes base64) + en el owner email
  // para compartidos. Para títulos legibles, el filtrado real se hace
  // después del descifrado en el cliente (ver ViewSecretDialog).
  const filterFn = useCallback(
    (s: SecretListItem) => {
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        s.id.toLowerCase().includes(q) ||
        s.ownerEmail?.toLowerCase().includes(q) ||
        s.encryptedTitle.toLowerCase().includes(q)
      );
    },
    [search]
  );

  const mineFiltered = useMemo(() => mine.filter(filterFn), [mine, filterFn]);
  const sharedFiltered = useMemo(() => shared.filter(filterFn), [shared, filterFn]);

  // Módulo 4: exportación cifrada de la bóveda
  async function handleExport(password: string) {
    if (exportBusy || !password) return;
    setExportBusy(true);
    try {
      const blob = await exportVaultToEncryptedJson({
        secrets,
        masterKey: session.masterKey,
        password,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `zk-vault-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({
        title: "Exportación completa",
        description: "Tu bóveda se exportó cifrada con AES-256-GCM usando tu contraseña de exportación.",
      });
      setExportOpen(false);
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al exportar",
        description: err?.message ?? "Error desconocido",
      });
    } finally {
      setExportBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      {/* Toolbar */}
      <Card className="bg-card/60">
        <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg bg-primary/15">
              <ShieldCheck className="size-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-foreground" translate="no">
                  {session.email}
                </span>
                {session.name ? (
                  <span className="text-xs text-muted-foreground">· {session.name}</span>
                ) : null}
              </div>
              <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-muted-foreground">
                <KeyRound className="size-3" />
                Sesión autenticada con token HMAC · llave privada en memoria
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Módulo 2: búsqueda con acceso vía Cmd+K */}
            <div className="relative w-full sm:w-56">
              <Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                ref={searchRef}
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Buscar… (⌘K)"
                className="h-8 pl-7 text-xs"
                aria-label="Buscar en la bóveda"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                translate="no"
              />
            </div>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RefreshCw className={`mr-2 size-3.5 ${loading ? "animate-spin" : ""}`} />
              Refrescar
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 size-3.5" /> Nuevo secreto
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEnrollDeviceOpen(true)}
              title="Autorizar nuevo dispositivo"
            >
              <Smartphone className="mr-2 size-3.5" /> Dispositivo
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setRotateOpen(true)}
              title="Rotar contraseña maestra"
            >
              <RotateIcon className="mr-2 size-3.5" /> Rotar clave
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setRecoveryOpen(true)}
              title="Configurar backup de recuperación"
            >
              <RecoveryIcon className="mr-2 size-3.5" /> Recovery
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setAuditLogOpen(true)}
              title="Ver audit log"
            >
              <ScrollText className="mr-2 size-3.5" /> Audit
            </Button>
            {/* Módulo 4: exportación cifrada */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setExportOpen(true)}
              title="Exportar bóveda cifrada (JSON)"
              disabled={!session.masterKey}
            >
              <Download className="mr-2 size-3.5" /> Exportar
            </Button>
            <Button variant="ghost" size="sm" onClick={() => serverLogout()}>
              <LogOut className="mr-2 size-3.5" /> Salir
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Mis secretos */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Lock className="size-4 text-primary" /> Mis secretos
            <Badge variant="outline" className="text-[10px]">{mineFiltered.length}{search.trim() ? `/${mine.length}` : ""}</Badge>
          </h2>
        </div>
        <SecretGrid
          items={mineFiltered}
          loading={loading}
          onOpen={openView}
          onShare={openShare}
          onDelete={(s) => setDeleteTarget(s)}
          emptyHint={search.trim() ? "Sin resultados para tu búsqueda." : "Aún no tienes secretos. Crea el primero con «Nuevo secreto»."}
        />
      </div>

      {/* Compartidos conmigo */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Share2 className="size-4 text-primary" /> Compartidos conmigo
            <Badge variant="outline" className="text-[10px]">{sharedFiltered.length}{search.trim() ? `/${shared.length}` : ""}</Badge>
          </h2>
        </div>
        <SecretGrid
          items={sharedFiltered}
          loading={loading}
          onOpen={openView}
          onShare={() => {}}
          onLeave={(s) => setRevokeTarget(s)}
          shareable={false}
          emptyHint={search.trim() ? "Sin resultados para tu búsqueda." : "Nadie ha compartido secretos contigo todavía."}
        />
      </div>

      {/* Diálogos */}
      <CreateSecretDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={load} />
      <ViewSecretDialog open={viewOpen} onOpenChange={setViewOpen} secret={selected} />
      <ShareSecretDialog open={shareOpen} onOpenChange={setShareOpen} secret={selected} />
      <RotatePasswordDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        onRotated={() => {
          logout();
          toast({
            title: "Sesión cerrada",
            description: "Inicia sesión con tu nueva contraseña maestra.",
          });
        }}
      />
      <EnrollDeviceDialog open={enrollDeviceOpen} onOpenChange={setEnrollDeviceOpen} />
      <RecoverySetupDialog open={recoveryOpen} onOpenChange={setRecoveryOpen} />
      <AuditLogViewer open={auditLogOpen} onOpenChange={setAuditLogOpen} />

      {/* Módulo 4: diálogo de exportación cifrada */}
      <ExportDialog
        open={exportOpen}
        onOpenChange={setExportOpen}
        busy={exportBusy}
        onConfirm={handleExport}
      />

      {/* Confirmar borrado de secreto propio */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Trash2 className="size-4 text-destructive" /> ¿Borrar secreto?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs leading-relaxed">
              Esta acción es irreversible. Se borrarán el secreto cifrado y todas las
              <strong> shares </strong> compartidas con otros usuarios. Ellos perderán acceso a
              partir de este momento.
              <br /><br />
              <strong className="text-amber-500">Advertencia:</strong> copias que ya descifraron y
              guardaron localmente no pueden ser revocadas. Si crees que el secreto está
              comprometido, <strong>cámbialo antes de borrarlo</strong>.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busyAction}>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              disabled={busyAction}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {busyAction ? <Loader2 className="mr-2 size-4 animate-spin" /> : <Trash2 className="mr-2 size-4" />}
              Borrar definitivamente
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Confirmar salida de share (compartidos conmigo) */}
      <AlertDialog open={!!revokeTarget} onOpenChange={(o) => !o && setRevokeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <UserX className="size-4 text-destructive" /> ¿Salir de este secreto?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs leading-relaxed">
              Tu acceso a este secreto compartido será revocado en el servidor. Ya no aparecerá en
              tu bóveda ni podrás descifrarlo.
              <br /><br />
              El owner puede volver a compartírtelo en el futuro si es necesario.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busyAction}>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmRevoke}
              disabled={busyAction}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {busyAction ? <Loader2 className="mr-2 size-4 animate-spin" /> : <UserX className="mr-2 size-4" />}
              Salir del secreto
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SecretGrid({
  items,
  loading,
  onOpen,
  onShare,
  onDelete,
  onLeave,
  shareable = true,
  emptyHint,
}: {
  items: SecretListItem[];
  loading: boolean;
  onOpen: (s: SecretListItem) => void;
  onShare: (s: SecretListItem) => void;
  onDelete?: (s: SecretListItem) => void;
  onLeave?: (s: SecretListItem) => void;
  shareable?: boolean;
  emptyHint: string;
}) {
  if (loading) {
    return (
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="rounded-lg border border-border/40 bg-card/60 p-4 space-y-3">
            <div className="h-4 w-24 animate-pulse rounded bg-muted" />
            <div className="h-3 w-full animate-pulse rounded bg-muted" />
            <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
            <div className="flex gap-2 pt-2">
              <div className="h-7 w-20 animate-pulse rounded bg-muted" />
              <div className="h-7 w-20 animate-pulse rounded bg-muted" />
            </div>
          </div>
        ))}
      </div>
    );
  }
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/40 p-8 text-center">
        <Inbox className="size-6 text-muted-foreground/60" />
        <p className="text-xs text-muted-foreground">{emptyHint}</p>
      </div>
    );
  }
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((s) => (
        <Card key={s.id} className="bg-card/60 transition-colors hover:bg-card/80">
          <CardContent className="space-y-3 p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Lock className="size-3.5 text-primary" />
                <code className="font-mono">#{s.id.slice(-8)}</code>
              </div>
              {s.ownedByMe ? (
                <Badge variant="outline" className="border-primary/40 bg-primary/10 text-[10px] text-primary">
                  Propio
                </Badge>
              ) : (
                <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-500">
                  Compartido
                </Badge>
              )}
            </div>

            <div>
              <p className="text-xs text-muted-foreground">Título cifrado (no legible por el server):</p>
              <p className="mt-1 truncate font-mono text-[11px] text-foreground/70" title={s.encryptedTitle}>
                {s.encryptedTitle.slice(0, 48)}…
              </p>
            </div>

            <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
              <Clock className="size-3" />
              {new Date(s.createdAt).toLocaleString("es-ES", {
                day: "2-digit",
                month: "short",
                hour: "2-digit",
                minute: "2-digit",
              })}
            </div>

            <div className="flex gap-2 pt-1">
              <Button size="sm" variant="default" className="h-7 flex-1 text-xs" onClick={() => onOpen(s)}>
                <Eye className="mr-1.5 size-3" /> Descifrar
              </Button>
              {shareable ? (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 flex-1 text-xs"
                    onClick={() => onShare(s)}
                  >
                    <Share2 className="mr-1.5 size-3" /> Compartir
                  </Button>
                  {onDelete ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => onDelete(s)}
                      title="Borrar secreto"
                    >
                      <Trash2 className="size-3" />
                    </Button>
                  ) : null}
                </>
              ) : (
                <>
                  <div className="flex-1 truncate text-[10px] text-muted-foreground" title={s.ownerEmail} translate="no">
                    de {s.ownerEmail}
                  </div>
                  {onLeave ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => onLeave(s)}
                      title="Salir de este secreto"
                    >
                      <UserX className="size-3" />
                    </Button>
                  ) : null}
                </>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

/**
 * Módulo 4: diálogo para capturar la contraseña de exportación.
 * El usuario ingresa una contraseña (independiente de la master key)
 * que se usa para derivar una llave AES-256-GCM via PBKDF2 (600k iter)
 * y cifrar el JSON completo de la bóveda descifrada.
 *
 * El archivo resultante contiene:
 *   {
 *     "format": "zk-vault-export-v1",
 *     "kdf": { "algorithm": "pbkdf2", "iterations": 600000, "salt": "..." },
 *     "iv": "...",
 *     "ciphertext": "..."
 *   }
 *
 * Para importar de vuelta, el usuario ingresa la misma contraseña
 * y el cliente descifra el JSON. Esto permite migrar bóvedas entre
 * instancias sin exponer nunca el plaintext en disco.
 */
function ExportDialog({
  open,
  onOpenChange,
  busy,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  busy: boolean;
  onConfirm: (password: string) => void | Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [showPass, setShowPass] = useState(false);

  useEffect(() => {
    if (!open) {
      setPassword("");
      setPassword2("");
      setShowPass(false);
    }
  }, [open]);

  const canSubmit =
    password.length >= 8 && password === password2 && !busy;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="size-4 text-primary" />
            Exportar bóveda cifrada
          </DialogTitle>
          <DialogDescription className="text-xs">
            Tu bóveda se exportará como un archivo JSON cifrado con AES-256-GCM.
            La contraseña que ingreses aquí se usará para derivar una llave
            independiente de tu master key — no la olvides, sin ella el
            archivo es irrecuperable.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="exportPass" className="text-xs">
              Contraseña de exportación <span className="text-muted-foreground">(mín. 8)</span>
            </Label>
            <div className="relative">
              <Input
                id="exportPass"
                type={showPass ? "text" : "password"}
                autoComplete="new-password"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                translate="no"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPass((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                tabIndex={-1}
              >
                {showPass ? "🙈" : "👁"}
              </button>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="exportPass2" className="text-xs">Repetir contraseña</Label>
            <Input
              id="exportPass2"
              type={showPass ? "text" : "password"}
              autoComplete="new-password"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              translate="no"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              placeholder="••••••••••••"
            />
            {password && password2 && password !== password2 ? (
              <p className="text-[10px] text-destructive">Las contraseñas no coinciden</p>
            ) : null}
          </div>
          <p className="rounded-md bg-amber-500/10 p-2 text-[10px] text-amber-500">
            <strong>Advertencia:</strong> este archivo contiene tus secretos
            descifrados bajo una contraseña. Guárdalo en un lugar seguro y
            elimínalo cuando ya no lo necesites. Si lo pierdes o alguien
            obtiene la contraseña, todos tus secretos quedan expuestos.
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancelar
          </Button>
          <Button
            onClick={() => onConfirm(password)}
            disabled={!canSubmit}
          >
            {busy ? (
              <>
                <Loader2 className="mr-2 size-3.5 animate-spin" /> Cifrando…
              </>
            ) : (
              <>
                <Download className="mr-2 size-3.5" /> Exportar
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
