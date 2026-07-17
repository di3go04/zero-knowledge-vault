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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useApi } from "@/lib/api-client";
import {
  generateRecoveryMnemonic,
  validateRecoveryMnemonic,
  deriveRecoveryKey,
  encryptPrivateKeyForRecovery,
  exportPrivateKeyJwk,
  randomBytes,
  bufToBase64,
  RECOVERY_ITERATIONS,
} from "@/lib/crypto";
import { clearCryptoKeyRef, zeroBuffer } from "@/lib/crypto/memory";
import { useSession } from "@/lib/session-store";
import {
  Loader2,
  KeyRound,
  Copy,
  Check,
  ShieldCheck,
  AlertTriangle,
  Download,
  Eye,
  EyeOff,
} from "lucide-react";

interface RecoverySetupDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

/**
 * Diálogo "Recovery Setup" — genera una frase BIP-39 de 24 palabras,
 * la muestra al usuario con advertencias fuertes, y cifra la privateKey
 * RSA con la recovery key derivada de la frase.
 *
 * LIMPIEZA DE MEMORIA: al cerrar, todas las refs a CryptoKey y la
 * frase en claro se setean a null/vacío. La frase solo vive en memoria
 * mientras el diálogo está abierto.
 */
export function RecoverySetupDialog({ open, onOpenChange }: RecoverySetupDialogProps) {
  const { toast } = useToast();
  const session = useSession();
  const { apiFetch } = useApi();

  const [step, setStep] = useState<"intro" | "mnemonic" | "confirm" | "done">("intro");
  const [mnemonic, setMnemonic] = useState<string>("");
  const [showMnemonic, setShowMnemonic] = useState(true);
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // Refs para limpieza de memoria
  const recoveryKeyRef = useRef<CryptoKey | null>(null);

  // Cleanup al cerrar — zeroing de mnemonic y recovery key
  useEffect(() => {
    if (!open) {
      setStep("intro");
      setMnemonic("");
      setConfirmText("");
      setShowMnemonic(true);
      setCopied(false);
      // LIMPIEZA DE MEMORIA: desreferenciar recovery key
      clearCryptoKeyRef(recoveryKeyRef);
    }
  }, [open]);

  // Limpieza al desmontar
  useEffect(() => {
    return () => {
      setMnemonic("");
      clearCryptoKeyRef(recoveryKeyRef);
    };
  }, []);

  async function generateMnemonic() {
    setBusy(true);
    try {
      const { mnemonic: m } = await generateRecoveryMnemonic();
      setMnemonic(m);
      setStep("mnemonic");
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error al generar frase",
        description: err?.message,
      });
    } finally {
      setBusy(false);
    }
  }

  function copyMnemonic() {
    navigator.clipboard.writeText(mnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast({
      title: "Frase copiada",
      description: "Pégala en un gestor de contraseñas offline o imprímela. NO la guardes en texto plano digital.",
    });
  }

  function downloadMnemonic() {
    const blob = new Blob(
      [
        `Zero-Knowledge Vault — Recovery Key\n\n` +
          `Generada: ${new Date().toISOString()}\n` +
          `Usuario: ${session.email}\n\n` +
          `FRASE DE RECUPERACIÓN (24 palabras):\n\n${mnemonic}\n\n` +
          `ADVERTENCIA: Cualquiera con esta frase puede acceder a tu cuenta.\n` +
          `Guárdala en un lugar seguro (caja fuerte, papel offline).\n` +
          `El servidor NUNCA la tiene.\n`,
      ],
      { type: "text/plain" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `zk-vault-recovery-${session.email}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function confirmAndSetup() {
    if (confirmText !== "HE GUARDADO MI FRASE") {
      toast({
        variant: "destructive",
        title: "Confirmación requerida",
        description: 'Escribe exactamente: HE GUARDADO MI FRASE',
      });
      return;
    }

    if (!session.privateKey || !session.masterKey) {
      toast({
        variant: "destructive",
        title: "Sesión incompleta",
        description: "Falta masterKey o privateKey en sesión.",
      });
      return;
    }

    setBusy(true);
    try {
      // 1. Validar mnemonic
      const valid = await validateRecoveryMnemonic(mnemonic);
      if (!valid) {
        throw new Error("Frase BIP-39 inválida (checksum falló)");
      }

      // 2. Generar salt aleatorio para recovery key
      const recoverySalt = randomBytes(16);

      // 3. Derivar recovery key (PBKDF2 alto — no bloquea UI porque solo se usa aquí)
      const recoveryKey = await deriveRecoveryKey(mnemonic, recoverySalt, RECOVERY_ITERATIONS);
      recoveryKeyRef.current = recoveryKey;

      // 4. Exportar privateKey RSA como JWK
      let privateKeyJwkStr: string;
      try {
        const jwk = await exportPrivateKeyJwk(session.privateKey);
        privateKeyJwkStr = JSON.stringify(jwk);
      } catch {
        throw new Error(
          "La privateKey en sesión no es extraíble. Re-inicia sesión para habilitar Recovery Setup.",
        );
      }

      // 5. Cifrar la privateKey con la recovery key
      const { ciphertext, iv } = await encryptPrivateKeyForRecovery(
        privateKeyJwkStr,
        recoveryKey,
      );

      // 6. Enviar al servidor
      const res = await apiFetch("/api/auth/recovery/setup", {
        method: "POST",
        body: JSON.stringify({
          recoverySalt: bufToBase64(recoverySalt),
          recoveryIterations: RECOVERY_ITERATIONS,
          encryptedPrivateKeyForRecovery: ciphertext,
          recoveryIv: iv,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data?.error ?? "Error al configurar recovery");

      setStep("done");
      toast({
        title: "Backup de recuperación configurado",
        description: "Tu privateKey RSA ahora tiene un backup cifrado con tu frase BIP-39.",
      });
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error",
        description: err?.message,
      });
    } finally {
      setBusy(false);
    }
  }

  const words = mnemonic ? mnemonic.split(" ") : [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="size-4 text-primary" /> Backup de recuperación
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed">
            Genera una frase de 24 palabras (BIP-39) que permite recuperar tu cuenta si olvidas
            tu contraseña maestra. El servidor nunca ve esta frase.
          </DialogDescription>
        </DialogHeader>

        {step === "intro" && (
          <div className="space-y-3">
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-500" />
                <div className="space-y-2 text-[11px] leading-relaxed text-muted-foreground">
                  <p className="font-semibold text-amber-500">Antes de continuar, entiende:</p>
                  <ul className="list-disc pl-4 space-y-1">
                    <li>La frase de 24 palabras da <strong>acceso completo</strong> a tu cuenta.</li>
                    <li>El servidor <strong>nunca</strong> la recibe ni almacena.</li>
                    <li>Si la pierdes, <strong>no hay forma de recuperar tu cuenta</strong>.</li>
                    <li>Guárdala offline: papel en caja fuerte, gestor offline, metal.</li>
                    <li><strong>NUNCA</strong> la guardes en texto plano digital ( Drive, notas, email).</li>
                  </ul>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancelar
              </Button>
              <Button type="button" onClick={generateMnemonic} disabled={busy}>
                {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : <KeyRound className="mr-2 size-4" />}
                Generar frase
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "mnemonic" && (
          <div className="space-y-3">
            <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-semibold text-foreground">
                  Tu frase de recuperación (24 palabras)
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2"
                  onClick={() => setShowMnemonic((v) => !v)}
                >
                  {showMnemonic ? <EyeOff className="size-3" /> : <Eye className="size-3" />}
                </Button>
              </div>
              {showMnemonic ? (
                <div className="grid grid-cols-3 gap-1.5">
                  {words.map((w, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-1.5 rounded bg-background/60 px-2 py-1 text-[11px]"
                    >
                      <span className="text-muted-foreground">{i + 1}.</span>
                      <span className="font-mono font-medium">{w}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-6 text-center text-xs text-muted-foreground">
                  ••••• ••••• ••••• ••••• ••••• ••••• ••••• •••••
                  <br />
                  ••••• ••••• ••••• ••••• ••••• ••••• ••••• •••••
                  <br />
                  ••••• ••••• ••••• ••••• ••••• ••••• ••••• •••••
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" onClick={copyMnemonic} className="flex-1">
                {copied ? <Check className="mr-1.5 size-3" /> : <Copy className="mr-1.5 size-3" />}
                Copiar
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={downloadMnemonic} className="flex-1">
                <Download className="mr-1.5 size-3" />
                Descargar
              </Button>
            </div>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancelar
              </Button>
              <Button type="button" onClick={() => setStep("confirm")}>
                He guardado mi frase
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "confirm" && (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="confirmText" className="text-xs">
                Para confirmar, escribe exactamente: <code className="font-mono">HE GUARDADO MI FRASE</code>
              </Label>
              <Input
                id="confirmText"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="HE GUARDADO MI FRASE"
                className="font-mono text-xs"
              />
            </div>
            <div className="rounded-md border border-border/60 bg-background/60 p-2.5 text-[11px] text-muted-foreground">
              Al confirmar, cifraremos tu privateKey RSA con la recovery key derivada de tu frase
              y la enviaremos al servidor como blob cifrado. El servidor nunca verá ni la frase ni
              la privateKey en claro.
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setStep("mnemonic")}
                disabled={busy}
              >
                Atrás
              </Button>
              <Button
                type="button"
                onClick={confirmAndSetup}
                disabled={busy || confirmText !== "HE GUARDADO MI FRASE"}
              >
                {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : <ShieldCheck className="mr-2 size-4" />}
                Configurar backup
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "done" && (
          <div className="space-y-3 py-4 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-primary/15">
              <ShieldCheck className="size-6 text-primary" />
            </div>
            <p className="text-sm font-medium">Backup configurado</p>
            <p className="text-[11px] text-muted-foreground">
              Si olvidas tu contraseña maestra, podrás usar tu frase de 24 palabras para recuperar
              acceso a tu cuenta sin perder tus secretos.
            </p>
            <Badge variant="outline" className="border-primary/40 bg-primary/10 text-[10px] text-primary">
              Recovery habilitado
            </Badge>
            <DialogFooter>
              <Button type="button" onClick={() => onOpenChange(false)} className="w-full">
                Cerrar
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
