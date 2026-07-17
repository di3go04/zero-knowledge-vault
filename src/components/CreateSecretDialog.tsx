"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { useApi } from "@/lib/api-client";
import { encryptNewSecret } from "@/lib/crypto";
import { PasswordGenerator } from "./PasswordGenerator";
import { Loader2, Lock, Plus } from "lucide-react";

interface CreateSecretDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: () => void;
}

export function CreateSecretDialog({ open, onOpenChange, onCreated }: CreateSecretDialogProps) {
  const { toast } = useToast();
  const session = useSession();
  const { apiFetch } = useApi();

  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      setTitle("");
      setContent("");
    }
  }, [open]);

  useEffect(() => {
    return () => {
      setTitle("");
      setContent("");
    };
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (busy || !session.publicKey) return;
    if (!title.trim() || !content.trim()) {
      toast({
        variant: "destructive",
        title: "Faltan datos",
        description: "Título y contenido son obligatorios.",
      });
      return;
    }

    setBusy(true);
    try {
      const artifacts = await encryptNewSecret(title, content, session.publicKey);

      const res = await apiFetch("/api/secrets", {
        method: "POST",
        body: JSON.stringify({
          encryptedTitle: artifacts.encryptedTitle,
          titleIv: artifacts.titleIv,
          encryptedData: artifacts.encryptedData,
          dataIv: artifacts.dataIv,
          wrappedKeyForOwner: artifacts.wrappedKeyForOwner,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al crear secreto");

      toast({
        title: "Secreto creado",
        description: "El título y el contenido se cifraron en tu navegador. El servidor solo vio blobs base64.",
      });

      setTitle("");
      setContent("");
      onOpenChange(false);
      onCreated();
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error",
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
            <Plus className="size-4 text-primary" /> Nuevo secreto
          </DialogTitle>
          <DialogDescription className="text-xs">
            Se generará una llave AES-256 aleatoria para cifrar el título y el contenido. La llave
            AES se envuelve con tu llave pública RSA-OAEP antes de enviarse al servidor.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleCreate} className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="secretTitle" className="text-xs">Título</Label>
            <Input
              id="secretTitle"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Credenciales BD producción"
              maxLength={120}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="secretContent" className="text-xs">Contenido del secreto</Label>
            <Textarea
              id="secretContent"
              required
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={"user: admin\npassword: s3cr3t!\nhost: db.interno"}
              rows={6}
              className="resize-none font-mono text-xs"
            />
          </div>
          <PasswordGenerator onGenerate={(pw) => setContent(pw)} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancelar
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? (
                <>
                  <Loader2 className="mr-2 size-4 animate-spin" /> Cifrando…
                </>
              ) : (
                <>
                  <Lock className="mr-2 size-4" /> Cifrar y guardar
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
