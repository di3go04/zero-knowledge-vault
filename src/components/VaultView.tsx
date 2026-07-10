"use client";

import { useCallback, useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { useApi } from "@/lib/api-client";
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
} from "lucide-react";
import { CreateSecretDialog } from "./CreateSecretDialog";
import { ViewSecretDialog, type SecretListItem } from "./ViewSecretDialog";
import { ShareSecretDialog } from "./ShareSecretDialog";
import { RotatePasswordDialog } from "./RotatePasswordDialog";

export function VaultView() {
  const { toast } = useToast();
  const session = useSession();
  const logout = useSession((s) => s.logout);
  const { apiFetch, serverLogout } = useApi();

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

  const mine = secrets.filter((s) => s.ownedByMe);
  const shared = secrets.filter((s) => !s.ownedByMe);

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
                <span className="text-sm font-semibold text-foreground">{session.email}</span>
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
          <div className="flex items-center gap-2">
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
              onClick={() => setRotateOpen(true)}
              title="Rotar contraseña maestra"
            >
              <RotateIcon className="mr-2 size-3.5" /> Rotar clave
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
            <Badge variant="outline" className="text-[10px]">{mine.length}</Badge>
          </h2>
        </div>
        <SecretGrid
          items={mine}
          loading={loading}
          onOpen={openView}
          onShare={openShare}
          onDelete={(s) => setDeleteTarget(s)}
          emptyHint="Aún no tienes secretos. Crea el primero con «Nuevo secreto»."
        />
      </div>

      {/* Compartidos conmigo */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Share2 className="size-4 text-primary" /> Compartidos conmigo
            <Badge variant="outline" className="text-[10px]">{shared.length}</Badge>
          </h2>
        </div>
        <SecretGrid
          items={shared}
          loading={loading}
          onOpen={openView}
          onShare={() => {}}
          onLeave={(s) => setRevokeTarget(s)}
          shareable={false}
          emptyHint="Nadie ha compartido secretos contigo todavía."
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
          // Tras rotar, la masterKey en memoria sigue siendo la vieja.
          // Forzamos logout para que el usuario re-login con la nueva.
          logout();
          toast({
            title: "Sesión cerrada",
            description: "Inicia sesión con tu nueva contraseña maestra.",
          });
        }}
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
      <div className="flex items-center justify-center gap-2 rounded-lg border border-dashed border-border/40 p-8 text-xs text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Cargando secretos…
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
                  <div className="flex-1 truncate text-[10px] text-muted-foreground" title={s.ownerEmail}>
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
