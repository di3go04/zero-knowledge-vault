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
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { useApi } from "@/lib/api-client";
import { performPasswordRotation } from "@/lib/crypto";
import { Loader2, KeyRound, ShieldCheck, AlertTriangle } from "lucide-react";

interface RotatePasswordDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onRotated: () => void;
}

export function RotatePasswordDialog({ open, onOpenChange, onRotated }: RotatePasswordDialogProps) {
  const { toast } = useToast();
  const session = useSession();
  const { apiFetch } = useApi();

  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [newPass2, setNewPass2] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [busy, setBusy] = useState(false);

  // MEJORA: Memory zeroing — limpiar contraseñas al cerrar y desmontar
  useEffect(() => {
    if (!open) {
      setOldPass("");
      setNewPass("");
      setNewPass2("");
    }
  }, [open]);

  useEffect(() => {
    return () => {
      setOldPass("");
      setNewPass("");
      setNewPass2("");
    };
  }, []);

  async function handleRotate(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;

    if (oldPass.length < 10) {
      toast({
        variant: "destructive",
        title: "Contraseña actual incorrecta",
        description: "La contraseña actual debe tener al menos 10 caracteres.",
      });
      return;
    }
    if (newPass.length < 10) {
      toast({
        variant: "destructive",
        title: "Nueva contraseña débil",
        description: "La nueva contraseña maestra debe tener al menos 10 caracteres.",
      });
      return;
    }
    if (newPass !== newPass2) {
      toast({
        variant: "destructive",
        title: "Las contraseñas no coinciden",
      });
      return;
    }
    if (oldPass === newPass) {
      toast({
        variant: "destructive",
        title: "La nueva contraseña debe ser distinta de la actual",
      });
      return;
    }

    setBusy(true);
    try {
      // 1. El cliente necesita el material criptográfico actual del servidor.
      //    Aunque tengamos masterKey en memoria, necesitamos el salt + IV
      //    + encryptedPrivateKey para pasar a performPasswordRotation.
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: session.email }),
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) {
        throw new Error(loginData?.error ?? "No se pudo obtener material actual");
      }

      // 2. Ejecutar rotación en el cliente
      const artifacts = await performPasswordRotation({
        oldPassword: oldPass,
        newPassword: newPass,
        email: session.email,
        currentKdfAlgorithm: loginData.kdfAlgorithm,
        currentKdfSaltB64: loginData.kdfSalt,
        currentKdfIterations: loginData.kdfIterations,
        currentKdfMemoryKiB: loginData.kdfMemoryKiB,
        currentKdfParallelism: loginData.kdfParallelism,
        currentEncryptedPrivateKeyJwkB64: loginData.encryptedPrivateKeyJwk,
        currentPrivateKeyIvB64: loginData.privateKeyIv,
      });

      // 3. Enviar al servidor
      const res = await apiFetch("/api/auth/rotate", {
        method: "POST",
        body: JSON.stringify({
          newKdfAlgorithm: artifacts.newKdfAlgorithm,
          newKdfSalt: artifacts.newKdfSalt,
          newKdfIterations: artifacts.newKdfIterations,
          newKdfMemoryKiB: artifacts.newKdfMemoryKiB,
          newKdfParallelism: artifacts.newKdfParallelism,
          newEncryptedPrivateKeyJwk: artifacts.newEncryptedPrivateKey.encryptedJwk,
          newPrivateKeyIv: artifacts.newEncryptedPrivateKey.iv,
          newPopSignature: artifacts.newPopSignature,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error ?? "Error al rotar contraseña");
      }

      toast({
        title: "Contraseña maestra rotada",
        description:
          "La privateKey RSA no cambió — solo su candado (masterKey). Todas las wrappedKeys y shares existentes siguen funcionando.",
      });

      setOldPass("");
      setNewPass("");
      setNewPass2("");
      onOpenChange(false);
      onRotated();
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al rotar",
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
            <KeyRound className="size-4 text-primary" /> Rotar contraseña maestra
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed">
            Cambia la contraseña que protege tu llave privada. Se generará un nuevo salt y se
            re-cifrará la MISMA llave privada con la nueva masterKey derivada (PBKDF2).
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleRotate} className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="oldPass" className="text-xs">Contraseña maestra actual</Label>
            <div className="relative">
              <Input
                id="oldPass"
                type={showPass ? "text" : "password"}
                autoComplete="current-password"
                required
                value={oldPass}
                onChange={(e) => setOldPass(e.target.value)}
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
            <Label htmlFor="newPass" className="text-xs">
              Nueva contraseña maestra <span className="text-muted-foreground">(mín. 10)</span>
            </Label>
            <Input
              id="newPass"
              type={showPass ? "text" : "password"}
              autoComplete="new-password"
              required
              value={newPass}
              onChange={(e) => setNewPass(e.target.value)}
              placeholder="••••••••••••"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="newPass2" className="text-xs">Repetir nueva contraseña</Label>
            <Input
              id="newPass2"
              type={showPass ? "text" : "password"}
              autoComplete="new-password"
              required
              value={newPass2}
              onChange={(e) => setNewPass2(e.target.value)}
              placeholder="••••••••••••"
            />
          </div>

          <div className="rounded-md border border-primary/20 bg-primary/5 p-2.5">
            <div className="flex items-start gap-2">
              <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                <strong className="text-foreground">Qué cambia:</strong> el salt, la masterKey
                derivada y el ciphertext de tu privateKey.
                <strong className="text-foreground"> Qué NO cambia:</strong> la privateKey RSA
                (mismo par), la publicKey, las wrappedKeys existentes y los shares activos.
              </p>
            </div>
          </div>

          <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-500" />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                <strong className="text-amber-500">Importante:</strong> si crees que tu contraseña
                actual está comprometida, también deberías revisar los secretos críticos y
                rotarlos individualmente (crear nuevos y borrar los viejos).
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              Cancelar
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? (
                <>
                  <Loader2 className="mr-2 size-4 animate-spin" /> Rotando…
                </>
              ) : (
                <>
                  <KeyRound className="mr-2 size-4" /> Rotar contraseña
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
