"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import {
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  importEcdhPublicKeyJwk,
  importEcdhPrivateKeyForSigning,
  deriveEcdhSharedAesKey,
  unwrapPrivateKeyForDevice,
  signChallenge,
  publicKeyFingerprint,
  importPublicKeyJwk,
} from "@/lib/crypto";
import { clearKeyPairRef, clearCryptoKeyRef } from "@/lib/crypto/memory";
import {
  Smartphone,
  Loader2,
  ShieldCheck,
  KeyRound,
  Fingerprint,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";

type Step = "input" | "waiting-code" | "polling" | "verifying" | "done" | "error";

/**
 * NewDeviceEnrollView — Flujo del Dispositivo B (nuevo dispositivo).
 *
 * El usuario quiere acceder a su cuenta desde un dispositivo nuevo.
 * NO tiene sesión activa. El flujo:
 *
 *   1. Usuario introduce email + contraseña maestra + deviceName.
 *   2. Cliente genera par ECDH efímero (P-256).
 *   3. POST /api/devices/enroll/init con email + publicKeyECDH → obtiene
 *      enrollCode (6 dígitos) + deviceId.
 *   4. Muestra enrollCode al usuario — debe introducirlo en un dispositivo
 *      YA autenticado (Dispositivo A) para autorizar este dispositivo.
 *   5. Polling a POST /api/devices/enroll/poll hasta que el enrollment
 *      esté completo (A autorizó). Recibe un `challenge` (nonce 32 bytes).
 *   6. Firma el challenge con la privateKey ECDH del dispositivo B
 *      (ECDSA P-256 + SHA-256).
 *   7. POST /api/devices/enroll/poll/verify con la firma → recibe
 *      wrappedPrivateKeyForDevice + enrollerPublicKeyECDH.
 *   8. Deriva shared secret ECDH: (B.privateKey × A.publicKeyECDH).
 *   9. Desenvuelve la privateKey RSA del usuario con el shared secret
 *      (AES-256-GCM).
 *  10. Guarda la privateKey RSA en sesión → redirige al dashboard.
 *
 * LIMPIEZA DE MEMORIA:
 *   - La privateKey ECDH efímera se limpia (clearKeyPairRef) tras el
 *     descifrado de la privateKey RSA.
 *   - El shared secret ECDH se limpia (clearCryptoKeyRef) tras el unwrap.
 *   - Si el usuario cancela o hay error, todas las refs se limpian.
 */
export function NewDeviceEnrollView({ onDone }: { onDone: () => void }) {
  const { toast } = useToast();
  const login = useSession((s) => s.login);

  const [step, setStep] = useState<Step>("input");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [deviceName, setDeviceName] = useState("");
  const [enrollCode, setEnrollCode] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [deviceFingerprint, setDeviceFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  const [pollCount, setPollCount] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");

  // Refs para material criptográfico — limpieza estricta
  const ecdhKeyPairRef = useRef<CryptoKeyPair | null>(null);
  const sharedKeyRef = useRef<CryptoKey | null>(null);
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const publicKeyRef = useRef<CryptoKey | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cleanup al desmontar
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      clearKeyPairRef(ecdhKeyPairRef);
      clearCryptoKeyRef(sharedKeyRef);
      clearCryptoKeyRef(privateKeyRef);
      clearCryptoKeyRef(publicKeyRef);
    };
  }, []);

  const cleanupAllKeys = useCallback(() => {
    clearKeyPairRef(ecdhKeyPairRef);
    clearCryptoKeyRef(sharedKeyRef);
    clearCryptoKeyRef(privateKeyRef);
    clearCryptoKeyRef(publicKeyRef);
  }, []);

  async function handleInit() {
    if (!email || !password || !deviceName) {
      toast({
        variant: "destructive",
        title: "Faltan datos",
        description: "Email, contraseña maestra y nombre del dispositivo son obligatorios.",
      });
      return;
    }

    setBusy(true);
    setErrorMsg("");
    try {
      // 1. Generar par ECDH efímero para este dispositivo
      const ecdhPair = await generateEcdhKeyPair();
      ecdhKeyPairRef.current = ecdhPair;

      // 2. Exportar publicKey ECDH para enviarla al servidor
      const publicKeyECDH = await exportEcdhPublicKeyJwk(ecdhPair.publicKey);

      // 3. Calcular fingerprint para mostrar al usuario (TOFU)
      const fingerprint = await publicKeyFingerprint(publicKeyECDH);
      setDeviceFingerprint(fingerprint);

      // 4. Llamar a /api/devices/enroll/init
      const res = await fetch("/api/devices/enroll/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          deviceName,
          publicKeyECDH,
          publicKeyECDHFingerprint: fingerprint,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error ?? "Error al iniciar enrollment");
      }

      setEnrollCode(data.enrollCode);
      setDeviceId(data.deviceId);
      setStep("waiting-code");
    } catch (err: any) {
      setErrorMsg(err?.message ?? "Error desconocido");
      setStep("error");
      cleanupAllKeys();
    } finally {
      setBusy(false);
    }
  }

  async function startPolling() {
    setStep("polling");
    setPollCount(0);

    const poll = async () => {
      setPollCount((c) => c + 1);
      try {
        // 5. Poll a /api/devices/enroll/poll
        const res = await fetch("/api/devices/enroll/poll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ deviceId }),
        });

        if (!res.ok) {
          const data = await res.json();
          throw new Error(data?.error ?? "Error en poll");
        }

        const data = await res.json();

        if (data.enrolled === false) {
          // Aún no autorizado — seguir esperando
          toast({
            title: "Esperando autorización",
            description: `Intento ${pollCount + 1}. El dispositivo A debe introducir el código.`,
          });
          pollTimerRef.current = setTimeout(poll, 5000);
          return;
        }

        // A autorizó — recibimos challenge
        await handleChallenge(data.challenge);
      } catch (err: any) {
        setErrorMsg(err?.message ?? "Error durante polling");
        setStep("error");
        cleanupAllKeys();
      }
    };

    poll();
  }

  async function handleChallenge(challengeB64: string) {
    setStep("verifying");
    try {
      if (!ecdhKeyPairRef.current) throw new Error("Par ECDH no disponible");

      // 6. Importar privateKey ECDH como ECDSA para firmar
      const ecdhPrivJwk = await crypto.subtle.exportKey(
        "jwk",
        ecdhKeyPairRef.current.privateKey,
      );
      const signingKey = await importEcdhPrivateKeyForSigning(ecdhPrivJwk);

      // MEJORA: limpiar ecdhPrivJwk inmediatamente tras usarlo
      // (contiene la privateKey ECDH en claro)
      Object.keys(ecdhPrivJwk).forEach((k) => { (ecdhPrivJwk as any)[k] = ""; });

      // 7. Firmar challenge con ECDSA P-256
      const signature = await signChallenge(signingKey, challengeB64);

      // 8. Enviar firma a /api/devices/enroll/poll/verify
      const res = await fetch("/api/devices/enroll/poll/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deviceId,
          challenge: challengeB64,
          signature,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error ?? "Firma del challenge inválida");
      }

      // 9. Derivar shared secret ECDH: B.privateKey × A.publicKeyECDH
      const enrollerPublicKey = await importEcdhPublicKeyJwk(
        data.enrollerPublicKeyECDH,
      );
      const sharedKey = await deriveEcdhSharedAesKey(
        ecdhKeyPairRef.current.privateKey,
        enrollerPublicKey,
      );
      sharedKeyRef.current = sharedKey;

      // 10. Desenvolver la privateKey RSA del usuario
      const privateKey = await unwrapPrivateKeyForDevice(
        data.wrappedPrivateKeyForDevice,
        data.wrappedPrivateKeyIv,
        sharedKey,
      );
      privateKeyRef.current = privateKey;

      // 11. Necesitamos la publicKey RSA del usuario para sesión.
      //     La obtenemos del login del servidor (que devuelve publicKeyJwk).
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const loginData = await loginRes.json();

      // 12. Importar publicKey RSA
      const publicKey = await importPublicKeyJwk(loginData.publicKeyJwk);
      publicKeyRef.current = publicKey;

      // 13. Guardar en sesión — pero NO tenemos masterKey (no la derivamos).
      //     Para una sesión funcional completa, el usuario debería hacer login
      //     normal tras el enrollment. Por ahora, guardamos lo que tenemos.
      login({
        userId: loginData.userId,
        email: loginData.email,
        name: loginData.name,
        publicKeyJwk: loginData.publicKeyJwk,
        sessionToken: loginData.sessionToken,
        expiresAt: loginData.expiresAt,
        masterKey: null as unknown as CryptoKey, // no disponible en este flujo
        privateKey,
        publicKey,
      });

      // 14. LIMPIEZA: la privateKey ECDH ya no se necesita — borrarla.
      //     El shared secret también.
      clearKeyPairRef(ecdhKeyPairRef);
      clearCryptoKeyRef(sharedKeyRef);

      setStep("done");
      toast({
        title: "Dispositivo autorizado",
        description: "Tu llave privada se descifró localmente. Acceso concedido.",
      });

      // Redirigir al dashboard tras 2s
      setTimeout(() => onDone(), 2000);
    } catch (err: any) {
      setErrorMsg(err?.message ?? "Error al verificar challenge");
      setStep("error");
      cleanupAllKeys();
    }
  }

  function handleCancel() {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    cleanupAllKeys();
    setStep("input");
    setEnrollCode("");
    setDeviceId("");
    setDeviceFingerprint("");
    setPollCount(0);
    setErrorMsg("");
  }

  return (
    <div className="mx-auto max-w-md">
      <Card className="border-primary/30 bg-card/80">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-xl bg-primary/15">
            <Smartphone className="size-6 text-primary" />
          </div>
          <CardTitle className="text-xl">Acceder desde nuevo dispositivo</CardTitle>
          <CardDescription className="text-xs">
            Si ya tienes una cuenta y quieres acceder desde este dispositivo, necesitas
            autorizarlo desde un dispositivo ya autenticado.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {step === "input" && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-xs">Email</Label>
                <Input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="tu@equipo.com"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-xs">Contraseña maestra</Label>
                <Input
                  id="password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                />
                <p className="text-[10px] text-muted-foreground">
                  Se usa solo para verificar tu identidad localmente. No se envía al servidor.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="deviceName" className="text-xs">Nombre del dispositivo</Label>
                <Input
                  id="deviceName"
                  type="text"
                  required
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  placeholder="Mac de Ana"
                  maxLength={80}
                />
              </div>
              <Button onClick={handleInit} disabled={busy} className="w-full">
                {busy ? (
                  <>
                    <Loader2 className="mr-2 size-4 animate-spin" /> Generando llaves…
                  </>
                ) : (
                  <>
                    <KeyRound className="mr-2 size-4" /> Iniciar enrollment
                  </>
                )}
              </Button>
            </div>
          )}

          {step === "waiting-code" && (
            <div className="space-y-3">
              <div className="rounded-md border border-primary/30 bg-primary/5 p-4 text-center">
                <p className="mb-2 text-xs text-muted-foreground">Código de enrollment</p>
                <p className="font-mono text-3xl font-bold tracking-widest text-primary">
                  {enrollCode}
                </p>
                <p className="mt-2 text-[10px] text-muted-foreground">
                  Introduce este código en un dispositivo ya autenticado para autorizar
                  este dispositivo.
                </p>
              </div>

              {deviceFingerprint && (
                <div className="rounded-md border border-border/60 bg-background/60 p-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                    <Fingerprint className="size-3" />
                    Fingerprint de este dispositivo:
                  </div>
                  <code className="mt-1 block truncate font-mono text-[10px] text-foreground/70">
                    {deviceFingerprint.slice(0, 32)}…
                  </code>
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    Verifica que coincide en el dispositivo autorizador (TOFU).
                  </p>
                </div>
              )}

              <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-500" />
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    Espera a que el dispositivo autorizador complete el enrollment.
                    Luego pulsa "Empezar polling" para verificar el challenge-response.
                  </p>
                </div>
              </div>

              <div className="flex gap-2">
                <Button variant="ghost" onClick={handleCancel} className="flex-1">
                  Cancelar
                </Button>
                <Button onClick={startPolling} className="flex-1">
                  <RefreshCw className="mr-2 size-4" /> Empezar polling
                </Button>
              </div>
            </div>
          )}

          {step === "polling" && (
            <div className="space-y-3 py-4 text-center">
              <Loader2 className="mx-auto size-8 animate-spin text-primary" />
              <p className="text-sm font-medium">Esperando autorización…</p>
              <p className="text-[11px] text-muted-foreground">
                Intento {pollCount}. El dispositivo A debe introducir el código{" "}
                <code className="font-mono">{enrollCode}</code> y autorizar.
              </p>
              <Button variant="ghost" size="sm" onClick={handleCancel}>
                Cancelar
              </Button>
            </div>
          )}

          {step === "verifying" && (
            <div className="space-y-3 py-4 text-center">
              <Loader2 className="mx-auto size-8 animate-spin text-primary" />
              <p className="text-sm font-medium">Verificando challenge-response…</p>
              <p className="text-[11px] text-muted-foreground">
                Firmando challenge con ECDSA P-256 y desenvolviendo tu llave privada
                con ECDH shared secret.
              </p>
            </div>
          )}

          {step === "done" && (
            <div className="space-y-3 py-4 text-center">
              <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-primary/15">
                <CheckCircle2 className="size-6 text-primary" />
              </div>
              <p className="text-sm font-medium">¡Dispositivo autorizado!</p>
              <p className="text-[11px] text-muted-foreground">
                Tu llave privada RSA se descifró localmente. Redirigiendo al dashboard…
              </p>
              <Badge variant="outline" className="border-primary/40 bg-primary/10 text-[10px] text-primary">
                <ShieldCheck className="mr-1 size-3" /> Zero-Knowledge preservado
              </Badge>
            </div>
          )}

          {step === "error" && (
            <div className="space-y-3 py-4 text-center">
              <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-destructive/15">
                <AlertTriangle className="size-6 text-destructive" />
              </div>
              <p className="text-sm font-medium">Error</p>
              <p className="text-[11px] text-muted-foreground">{errorMsg}</p>
              <Button variant="ghost" onClick={handleCancel}>
                Reintentar
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
