"use client";

import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import {
  importPublicKeyJwk,
  shareSecretWithRecipient,
} from "@/lib/crypto-client";
import { Loader2, Share2, Users } from "lucide-react";
import type { SecretListItem } from "./ViewSecretDialog";

interface ShareSecretDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  secret: SecretListItem | null;
}

interface PublicUser {
  id: string;
  email: string;
  name: string | null;
  publicKeyJwk?: JsonWebKey;
}

export function ShareSecretDialog({ open, onOpenChange, secret }: ShareSecretDialogProps) {
  const { toast } = useToast();
  const session = useSession();

  const [users, setUsers] = useState<PublicUser[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState(false);

  // Cargar lista de usuarios cuando se abre el diálogo
  useEffect(() => {
    if (!open) {
      setSelectedId("");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/users/list", {
          headers: { "x-user-id": session.userId },
        });
        const data = await res.json();
        if (cancelled) return;
        setUsers(data.users ?? []);
      } catch (err) {
        if (!cancelled) {
          toast({
            variant: "destructive",
            title: "No se pudo cargar la lista de usuarios",
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, session.userId, toast]);

  async function handleShare() {
    if (!secret || !selectedId || !session.privateKey) return;
    setBusy(true);
    try {
      // 1. Obtener la llave pública del destinatario
      const recipientRes = await fetch(
        `/api/users/lookup?email=${encodeURIComponent(
          users.find((u) => u.id === selectedId)?.email ?? "",
        )}`,
      );
      const recipient = await recipientRes.json();
      if (!recipientRes.ok) {
        throw new Error(recipient?.error ?? "Destinatario no encontrado");
      }

      // 2. Importar la publicKey del destinatario
      const recipientPublicKey = await importPublicKeyJwk(recipient.publicKeyJwk);

      // 3. Re-wrap: desenvolver con MI privateKey, envolver con SU publicKey
      const wrappedKeyForRecipient = await shareSecretWithRecipient(
        secret.wrappedKey,
        session.privateKey,
        recipientPublicKey,
      );

      // 4. Enviar al servidor la nueva wrappedKey (solo un blob)
      const res = await fetch("/api/shares", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-user-id": session.userId,
        },
        body: JSON.stringify({
          secretId: secret.id,
          recipientId: selectedId,
          wrappedSymmetricKey: wrappedKeyForRecipient,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al compartir");

      toast({
        title: "Secreto compartido",
        description: `La llave AES se re-envolvió con la llave pública de ${data.recipientEmail}. El servidor solo vio un nuevo blob.`,
      });
      onOpenChange(false);
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al compartir",
        description: err?.message ?? "Error desconocido",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="size-4 text-primary" /> Compartir secreto
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed">
            Tu llave privada desenvolverá la llave AES del secreto, y se re-envolverá con la llave
            pública del destinatario. El servidor nunca verá la llave AES en claro.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Secreto</Label>
            <div className="rounded-md border border-border/60 bg-background/60 p-2.5 text-xs font-mono text-muted-foreground">
              #{secret?.id?.slice(-8)} · wrappedKey del owner disponible localmente
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="recipient" className="text-xs">Destinatario</Label>
            {users.length === 0 ? (
              <div className="rounded-md border border-dashed border-border/60 p-3 text-center text-xs text-muted-foreground">
                No hay otros usuarios registrados todavía.
                <br />
                Regístrate con otro email en otra pestaña para probar el flujo de compartir.
              </div>
            ) : (
              <Select value={selectedId} onValueChange={setSelectedId}>
                <SelectTrigger id="recipient">
                  <SelectValue placeholder="Selecciona un miembro del equipo…" />
                </SelectTrigger>
                <SelectContent>
                  {users.map((u) => (
                    <SelectItem key={u.id} value={u.id}>
                      <span className="font-medium">{u.email}</span>
                      {u.name ? (
                        <span className="text-muted-foreground"> · {u.name}</span>
                      ) : null}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          <div className="rounded-md border border-primary/20 bg-primary/5 p-2.5">
            <div className="flex items-start gap-2">
              <Users className="mt-0.5 size-3.5 shrink-0 text-primary" />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                <strong className="text-foreground">Flujo criptográfico:</strong>{" "}
                <code className="rounded bg-muted/40 px-1">RSA-OAEP-DECRYPT(miPrivateKey, wrappedKey_owner)</code>{" "}
                →{" "}
                <code className="rounded bg-muted/40 px-1">RSA-OAEP-ENCRYPT(suPublicKey, rawAesKey)</code>.
                Solo el destinatario podrá revertirlo con su privateKey.
              </p>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancelar
          </Button>
          <Button
            type="button"
            onClick={handleShare}
            disabled={busy || !selectedId || users.length === 0}
          >
            {busy ? (
              <>
                <Loader2 className="mr-2 size-4 animate-spin" /> Re-envolviendo…
              </>
            ) : (
              <>
                <Share2 className="mr-2 size-4" /> Compartir
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
