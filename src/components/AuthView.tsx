"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useSession } from "@/lib/session-store";
import { performRegistration, performLogin, importPublicKeyJwk } from "@/lib/crypto-client";
import { Loader2, ShieldCheck, KeyRound, LogIn, UserPlus, Eye, EyeOff } from "lucide-react";

export function AuthView() {
  const { toast } = useToast();
  const login = useSession((s) => s.login);

  // ----- Registro -----
  const [regEmail, setRegEmail] = useState("");
  const [regName, setRegName] = useState("");
  const [regPass, setRegPass] = useState("");
  const [regPass2, setRegPass2] = useState("");
  const [regBusy, setRegBusy] = useState(false);

  // ----- Login -----
  const [logEmail, setLogEmail] = useState("");
  const [logPass, setLogPass] = useState("");
  const [logBusy, setLogBusy] = useState(false);

  const [showPass, setShowPass] = useState(false);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    if (regBusy) return;
    if (regPass.length < 10) {
      toast({
        variant: "destructive",
        title: "Contraseña débil",
        description: "Mínimo 10 caracteres para la contraseña maestra.",
      });
      return;
    }
    if (regPass !== regPass2) {
      toast({
        variant: "destructive",
        title: "Las contraseñas no coinciden",
      });
      return;
    }

    setRegBusy(true);
    try {
      // 1. Todo el trabajo criptográfico en el cliente
      const artifacts = await performRegistration(regEmail, regPass);

      // 2. Enviar SOLO blobs al servidor — incluyendo PoP + fingerprint
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: regEmail,
          name: regName || undefined,
          kdfSalt: artifacts.kdfSalt,
          kdfIterations: artifacts.kdfIterations,
          publicKeyJwk: artifacts.publicKeyJwk,
          publicKeyFingerprint: artifacts.publicKeyFingerprint,
          popSignature: artifacts.popSignature,
          encryptedPrivateKeyJwk: artifacts.encryptedPrivateKey.encryptedJwk,
          privateKeyIv: artifacts.encryptedPrivateKey.iv,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error ?? "Error al registrar");
      }

      // 3. Autosesión inmediata — pero necesitamos un sessionToken.
      //    El endpoint /register NO emite tokens (no recibe la contraseña
      //    para validación, solo blobs). Así que llamamos a /login para
      //    obtener el token. Ya tenemos masterKey + privateKey en memoria,
      //    así que el descifrado del login será instantáneo.
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: regEmail }),
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok || !loginData.sessionToken) {
        throw new Error("Registro OK pero no se pudo iniciar sesión automáticamente.");
      }

      // 4. Autosesión inmediata con token
      login({
        userId: data.userId,
        email: data.email,
        name: data.name,
        publicKeyJwk: artifacts.publicKeyJwk,
        sessionToken: loginData.sessionToken,
        expiresAt: loginData.expiresAt,
        masterKey: artifacts.masterKey,
        privateKey: artifacts.privateKey,
        publicKey: artifacts.publicKey,
      });

      toast({
        title: "Registro exitoso",
        description: "Llave privada cifrada con tu llave maestra (AES-256-GCM) + firma PoP verificada por el servidor (RSA-PSS). El servidor nunca vio ninguno de los dos en claro.",
      });

      setRegEmail("");
      setRegName("");
      setRegPass("");
      setRegPass2("");
    } catch (err: any) {
      toast({
        variant: "destructive",
        title: "Error de registro",
        description: err?.message ?? "Error desconocido",
      });
    } finally {
      setRegBusy(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (logBusy) return;
    setLogBusy(true);
    try {
      // 1. Pedir al servidor el material criptográfico PÚBLICO del usuario.
      //    Si el email NO existe, el servidor devuelve un DECOY con la misma
      //    estructura — el cliente no puede distinguirlo de un usuario real
      //    hasta que el descifrado AES-GCM falle con tag inválido.
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: logEmail }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error ?? "Error al iniciar sesión");
      }

      // 2. Derivar masterKey y descifrar la privateKey LOCALMENTE.
      //    Para un decoy, AES-GCM lanzará una excepción (tag inválido) —
      //    mismo comportamiento que contraseña incorrecta.
      const { masterKey, privateKey } = await performLogin(
        logPass,
        data.kdfSalt,
        data.kdfIterations,
        data.encryptedPrivateKeyJwk,
        data.privateKeyIv,
      );

      // 3. Importar la llave pública para tenerla lista en sesión
      const publicKey = await importPublicKeyJwk(data.publicKeyJwk);

      // 4. Guardar sessionToken emitido por el servidor (HMAC-signed)
      if (!data.sessionToken) {
        // Esto solo ocurre si el login era un decoy — pero el descifrado
        // ya debería haber fallado arriba. Por seguridad, abortamos.
        throw new Error("No se emitió token de sesión.");
      }

      login({
        userId: data.userId,
        email: data.email,
        name: data.name,
        publicKeyJwk: data.publicKeyJwk,
        sessionToken: data.sessionToken,
        expiresAt: data.expiresAt,
        masterKey,
        privateKey,
        publicKey,
      });

      toast({
        title: "Sesión iniciada",
        description: "Tu llave privada se descifró localmente. El servidor nunca recibió tu contraseña maestra.",
      });

      setLogEmail("");
      setLogPass("");
    } catch (err: any) {
      // Mensaje uniforme — no revelamos si el email existe o no
      toast({
        variant: "destructive",
        title: "No se pudo iniciar sesión",
        description:
          "Email o contraseña maestra incorrectos. Recuerda: el servidor nunca valida la contraseña, solo devuelve blobs — el descifrado ocurre en tu navegador.",
      });
    } finally {
      setLogBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md">
      <Card className="border-primary/30 bg-card/80">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-xl bg-primary/15">
            <ShieldCheck className="size-6 text-primary" />
          </div>
          <CardTitle className="text-xl">Acceso a la bóveda</CardTitle>
          <CardDescription className="text-xs">
            Todo el material criptográfico se procesa en tu navegador con Web Crypto API.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="login">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="login" className="text-xs">
                <LogIn className="mr-1.5 size-3.5" /> Iniciar sesión
              </TabsTrigger>
              <TabsTrigger value="register" className="text-xs">
                <UserPlus className="mr-1.5 size-3.5" /> Registrar
              </TabsTrigger>
            </TabsList>

            {/* LOGIN */}
            <TabsContent value="login" className="mt-4">
              <form onSubmit={handleLogin} className="space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor="logEmail" className="text-xs">Email</Label>
                  <Input
                    id="logEmail"
                    type="email"
                    autoComplete="email"
                    required
                    value={logEmail}
                    onChange={(e) => setLogEmail(e.target.value)}
                    placeholder="tu@equipo.com"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="logPass" className="text-xs">Contraseña maestra</Label>
                  <div className="relative">
                    <Input
                      id="logPass"
                      type={showPass ? "text" : "password"}
                      autoComplete="current-password"
                      required
                      value={logPass}
                      onChange={(e) => setLogPass(e.target.value)}
                      placeholder="••••••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass((v) => !v)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      tabIndex={-1}
                    >
                      {showPass ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                </div>
                <Button type="submit" disabled={logBusy} className="w-full">
                  {logBusy ? (
                    <>
                      <Loader2 className="mr-2 size-4 animate-spin" /> Derivando llave…
                    </>
                  ) : (
                    <>
                      <KeyRound className="mr-2 size-4" /> Desbloquear bóveda
                    </>
                  )}
                </Button>
                <p className="text-center text-[10px] text-muted-foreground">
                  Tu contraseña se usa para derivar (PBKDF2) una llave que descifra tu llave
                  privada localmente. Nunca se envía al servidor.
                </p>
              </form>
            </TabsContent>

            {/* REGISTER */}
            <TabsContent value="register" className="mt-4">
              <form onSubmit={handleRegister} className="space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor="regEmail" className="text-xs">Email</Label>
                  <Input
                    id="regEmail"
                    type="email"
                    autoComplete="email"
                    required
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="tu@equipo.com"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="regName" className="text-xs">Nombre (opcional)</Label>
                  <Input
                    id="regName"
                    type="text"
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="Ana García"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="regPass" className="text-xs">
                    Contraseña maestra <span className="text-muted-foreground">(mín. 10)</span>
                  </Label>
                  <div className="relative">
                    <Input
                      id="regPass"
                      type={showPass ? "text" : "password"}
                      autoComplete="new-password"
                      required
                      value={regPass}
                      onChange={(e) => setRegPass(e.target.value)}
                      placeholder="••••••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass((v) => !v)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      tabIndex={-1}
                    >
                      {showPass ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="regPass2" className="text-xs">Repetir contraseña maestra</Label>
                  <Input
                    id="regPass2"
                    type={showPass ? "text" : "password"}
                    autoComplete="new-password"
                    required
                    value={regPass2}
                    onChange={(e) => setRegPass2(e.target.value)}
                    placeholder="••••••••••••"
                  />
                </div>
                <Button type="submit" disabled={regBusy} className="w-full">
                  {regBusy ? (
                    <>
                      <Loader2 className="mr-2 size-4 animate-spin" /> Generando llaves RSA…
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="mr-2 size-4" /> Crear bóveda
                    </>
                  )}
                </Button>
                <p className="text-center text-[10px] text-muted-foreground">
                  Se generará un par RSA-OAEP 2048-bit. La llave privada se cifra con AES-256-GCM
                  usando tu llave maestra PBKDF2 antes de salir del navegador.
                </p>
              </form>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
