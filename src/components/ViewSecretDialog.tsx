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
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { decryptSecret } from "@/lib/crypto-client";
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

export function ViewSecretDialog({ open, onOpenChange, secret }: ViewSecretDialogProps) {
  const { toast } = useToast();
  const session = useSession();

  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [title, setTitle] = useState<string>("");
  const [content, setContent] = useState<string>("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open || !secret) {
      setTitle("");
      setContent("");
      setRevealed(false);
      setCopied(false);
      return;
    }
    let cancelled = false;
    (async () => {
      if (!session.privateKey) return;
      setBusy(true);
      try {
        const { title: t, content: c } = await decryptSecret(
          secret.wrappedKey,
          secret.encryptedTitle,
          secret.titleIv,
          secret.encryptedData,
          secret.dataIv,
          session.privateKey,
        );
        if (cancelled) return;
        setTitle(t);
        setContent(c);
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

  function handleCopy() {
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true);
      toast({ title: "Copiado al portapapeles" });
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
