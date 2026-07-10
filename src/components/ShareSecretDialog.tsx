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
  publicKeyFingerprint,
  shareSecretWithRecipient,
} from "@/lib/crypto-client";
import { Loader2, Share2, Users, Fingerprint, ShieldCheck } from "lucide-react";
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
  publicKeyFingerprint: string | null;
}

export function ShareSecretDialog({ open, onOpenChange, secret }: ShareSecretDialogProps) {
  const { toast } = useToast();
  const session = useSession();

  const [users, setUsers] = useState<PublicUser[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState(false);
  const [serverFingerprint, setServerFingerprint] = useState<string | null>(null);
  const [clientFingerprint, setClientFingerprint] = useState<string | null>(null);

  // Cargar lista de usuarios cuando se abre el diálogo
  useEffect(() => {
    if (!open) {
      setSelectedId("");
      setServerFingerprint(null);
      setClientFingerprint(null);
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

  // Cuando el usuario selecciona un destinatario, obtenemos su publicKey
  // vía /api/users/lookup para verificar TOFU: la fingerprint que el
  // servidor devuelve debe coincidir con la que el cliente computa
  // localmente a partir de la publicKeyJwk. Si no coinciden, el servidor
  // está sustituyendo llaves (ataque MITM activo).
  useEffect(() => {
    if (!selectedId) {
      setServerFingerprint(null);
      setClientFingerprint(null);
      return;
    }
    let cancelled = false;
    (async () => {
      const recipientEmail = users.find((u) => u.id === selectedId)?.email;
      if (!recipientEmail) return;
      try {
        const res = await fetch(
          `/api/users/lookup?email=${encodeURIComponent(recipientEmail)}`,
        );
        const data = await res.json();
        if (cancelled) return;
        if (!res.ok) {
          toast({
            variant: "destructive",
            title: "No se pudo obtener la llave del destinatario",
            description: data?.error,
          });
          return;
        }
        const serverFp = data.publicKeyFingerprint as string;
        const clientFp = await publicKeyFingerprint(data.publicKeyJwk);
        setServerFingerprint(serverFp);
        setClientFingerprint(clientFp);

        // TOFU check: si no coinciden, el servidor está mintiendo
        if (serverFp !== clientFp) {
          toast({
            variant: "destructive",
            title: "ALERTA TOFU: fingerprint inconsistente",
            description:
              "La fingerprint que el servidor devuelve NO coincide con la que el cliente computa. Posible sustitución de llave por el servidor. NO se compartirá el secreto.",
          });
        }
      } catch (err) {
        if (!cancelled) {
          toast({
            variant: "destructive",
            title: "Error al obtener datos del destinatario",
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedId, users, toast]);

  async function handleShare() {
    if (!secret || !selectedId || !session.privateKey) return;

    // TOFU gate: no continuar si las fingerprints no coinciden
    if (serverFingerprint !== clientFingerprint || !serverFingerprint) {
      toast({
        variant: "destructive",
        title: "Operación bloqueada",
        description:
          "Las fingerprints no coinciden o no se han verificado. No se compartirá el secreto.",
      });
      return;
    }

    setBusy(true);
    try {
      const recipientEmail = users.find((u) => u.id === selectedId)?.email;
      if (!recipientEmail) throw new Error("Destinatario no encontrado");

      // 1. Obtener la llave pública del destinatario
      const recipientRes = await fetch(
        `/api/users/lookup?email=${encodeURIComponent(recipientEmail)}`,
      );
      const recipient = await recipientRes.json();
      if (!recipientRes.ok) {
        throw new Error(recipient?.error ?? "Destinatario no encontrado");
      }

      // 2. Re-verificar TOFU antes de wrap
      const freshClientFp = await publicKeyFingerprint(recipient.publicKeyJwk);
      if (freshClientFp !== recipient.publicKeyFingerprint) {
        throw new Error(
          "TOFU inconsistente en el momento del wrap. Operación abortada.",
        );
      }

      // 3. Importar la publicKey del destinatario
      const recipientPublicKey = await importPublicKeyJwk(recipient.publicKeyJwk);

      // 4. Re-wrap: desenvolver con MI privateKey, envolver con SU publicKey
      const wrappedKeyForRecipient = await shareSecretWithRecipient(
        secret.wrappedKey,
        session.privateKey,
        recipientPublicKey,
      );

      // 5. Enviar al servidor la nueva wrappedKey (solo un blob)
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
        description: `La llave AES se re-envolvió con la llave pública de ${data.recipientEmail}. Fingerprint verificada (TOFU OK). El servidor solo vio un nuevo blob.`,
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

  const selectedUser = users.find((u) => u.id === selectedId);
  const tofuOk =
    serverFingerprint !== null &&
    clientFingerprint !== null &&
    serverFingerprint === clientFingerprint;

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

          {/* TOFU fingerprint verification */}
          {selectedUser && serverFingerprint && clientFingerprint ? (
            <div
              className={`rounded-md border p-2.5 ${
                tofuOk
                  ? "border-primary/30 bg-primary/5"
                  : "border-destructive/40 bg-destructive/5"
              }`}
            >
              <div className="flex items-start gap-2">
                <Fingerprint
                  className={`mt-0.5 size-3.5 shrink-0 ${
                    tofuOk ? "text-primary" : "text-destructive"
                  }`}
                />
                <div className="space-y-1.5">
                  <p className="text-[11px] font-semibold text-foreground">
                    Verificación TOFU de llave pública
                  </p>
                  <div className="space-y-1 text-[10px] text-muted-foreground">
                    <div>
                      <span className="font-medium">Servidor:</span>{" "}
                      <code className="font-mono break-all">{serverFingerprint.slice(0, 32)}…</code>
                    </div>
                    <div>
                      <span className="font-medium">Cliente:</span>{" "}
                      <code className="font-mono break-all">{clientFingerprint.slice(0, 32)}…</code>
                    </div>
                  </div>
                  {tofuOk ? (
                    <p className="flex items-center gap-1 text-[10px] font-medium text-primary">
                      <ShieldCheck className="size-3" /> Las fingerprints coinciden — llave
                      auténtica.
                    </p>
                  ) : (
                    <p className="text-[10px] font-medium text-destructive">
                      ¡ALERTA! Las fingerprints no coinciden — posible sustitución de llave por
                      el servidor. No se compartirá.
                    </p>
                  )}
                  <p className="text-[10px] leading-tight text-muted-foreground">
                    Verifica esta huella fuera de banda con el destinatario (ej. en persona o por
                    canal seguro) para máxima seguridad.
                  </p>
                </div>
              </div>
            </div>
          ) : null}

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
            disabled={busy || !selectedId || users.length === 0 || !tofuOk}
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
