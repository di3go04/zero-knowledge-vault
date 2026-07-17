"use client";

import { useEffect, useState, useRef } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { decryptSecret } from "@/lib/crypto";
import { zeroBuffer, clearCryptoKeyRef } from "@/lib/crypto/memory";
import { Loader2, Lock, Eye, EyeOff, Copy, Check } from "lucide-react";

interface ViewSecretDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  secret: SecretListItem | null;
}

export interface SecretListItem {
  id: string;
  ownerId: string;
  ownerEmail: string;
  ownerName: string | null;
  ownedByMe: boolean;
  encryptedTitle: string;
  titleIv: string;
  encryptedData: string;
  dataIv: string;
  wrappedKey: string;
  createdAt: string;
}

/**
 * ViewSecretDialog — descifra y muestra un secreto.
 *
 * MEJORA Módulo 1 (Memory Zeroing):
 *   - La AES key derivada del unwrap se guarda en un ref y se limpia
 *     (clearCryptoKeyRef) al cerrar el diálogo.
 *   - Los strings descifrados (title, content) se vacían al cerrar.
 *   - Aunque JS strings son inmutables y el GC los recolecta tarde,
 *     vaciar el state desreferencia las strings y las hace elegibles
 *     para GC inmediato.
 */
export function ViewSecretDialog({ open, onOpenChange, secret }: ViewSecretDialogProps) {
  const { toast } = useToast();
  const session = useSession();

  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [title, setTitle] = useState<string>("");
  const [content, setContent] = useState<string>("");
  const [copied, setCopied] = useState(false);

  // Refs para limpieza de memoria
  const aesKeyRef = useRef<CryptoKey | null>(null);

  useEffect(() => {
    if (!open || !secret) {
      // LIMPIEZA: vaciar state y refs criptográficas
      setTitle("");
      setContent("");
      setRevealed(false);
      setCopied(false);
      // Zeroing de la AES key (desreferenciar — Web Crypto no permite zeroing real)
      clearCryptoKeyRef(aesKeyRef);
      return;
    }
    let cancelled = false;
    (async () => {
      if (!session.privateKey) return;
      setBusy(true);
      try {
        const { title: t, content: c, aesKey } = await decryptSecret(
          secret.wrappedKey,
          secret.encryptedTitle,
          secret.titleIv,
          secret.encryptedData,
          secret.dataIv,
          session.privateKey,
          (session as any).mlKemPrivateKey ?? null,
        );
        if (cancelled) {
          // Si el diálogo se cerró mientras descifraba, limpiar inmediatamente
          clearCryptoKeyRef(aesKeyRef);
          return;
        }
        setTitle(t);
        setContent(c);
        aesKeyRef.current = aesKey;
      } catch (err: any) {
        toast({
          variant: "destructive",
          title: "No se pudo descifrar",
          description:
            err?.message ?? "Tu llave privada no pudo desenvolver la llave AES del secreto.",
        });
        onOpenChange(false);
      } finally {
        if (!cancelled) setBusy(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, secret, session.privateKey, toast, onOpenChange]);

  // Limpieza adicional al desmontar el componente
  useEffect(() => {
    return () => {
      clearCryptoKeyRef(aesKeyRef);
      setTitle("");
      setContent("");
    };
  }, []);

  function handleCopy() {
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true);
      toast({ title: "Copiado al portapapeles" });
      // Limpiar portapapeles tras 30s (best effort)
      setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 30_000);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="size-4 text-primary" /> Secreto descifrado
          </DialogTitle>
          <DialogDescription className="text-xs">
            Descifrado localmente con tu llave privada RSA. El servidor jamás vio este contenido.
          </DialogDescription>
        </DialogHeader>

        {busy ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" /> Desenvolviendo llave AES y descifrando…
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label className="text-xs text-muted-foreground">Título</Label>
                <Badge
                  variant="outline"
                  className={
                    secret?.ownedByMe
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-amber-500/40 bg-amber-500/10 text-amber-500"
                  }
                >
                  {secret?.ownedByMe ? "Propio" : `Compartido por ${secret?.ownerEmail}`}
                </Badge>
              </div>
              <div className="rounded-md border border-border/60 bg-background/60 p-3 text-sm font-medium">
                {title}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Contenido</Label>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border/60 bg-background/60 p-3 font-mono text-xs leading-relaxed">
                {revealed ? content : "••••••••••••••••••••••••••••••••••••••"}
              </pre>
            </div>
          </div>
        )}

        <DialogFooter className="gap-2">
          <Button
            type="button"
            variant="ghost"
            onClick={() => setRevealed((v) => !v)}
            disabled={busy || !content}
          >
            {revealed ? <EyeOff className="mr-2 size-4" /> : <Eye className="mr-2 size-4" />}
            {revealed ? "Ocultar" : "Revelar"}
          </Button>
          <Button
            type="button"
            variant="ghost"
            onClick={handleCopy}
            disabled={busy || !content || !revealed}
          >
            {copied ? <Check className="mr-2 size-4" /> : <Copy className="mr-2 size-4" />}
            Copiar
          </Button>
          <Button type="button" onClick={() => onOpenChange(false)}>
            Cerrar
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
