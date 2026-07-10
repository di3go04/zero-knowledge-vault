"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  ShieldCheck,
  KeyRound,
  Lock,
  Unlock,
  Users,
  ArrowRight,
  Server,
  Database,
  EyeOff,
  AlertTriangle,
} from "lucide-react";

const REGISTRATION_FLOW = `[CLIENTE]                                      [SERVIDOR (crypto-blind)]

1. Usuario ingresa email + master password
        │
        ▼
2. Generar salt aleatorio (16 bytes)
   salt = crypto.getRandomValues(…)
        │
        ▼
3. PBKDF2(password, salt, 600.000 iter, SHA-256)
   → masterKey (CryptoKey AES-256, NO extraíble)
   ⚠️ La masterKey NUNCA sale del navegador
        │
        ▼
4. Generar par RSA-OAEP 2048-bit
   { publicKey, privateKey } = crypto.subtle.generateKey(…)
        │
        ▼
5. Cifrar la privateKey con masterKey (AES-256-GCM)
   encryptedPrivKey = AES-GCM(masterKey, JWK(privKey), iv)
        │
        ▼
6. Exportar publicKey a JWK (texto plano — es pública)
        │
        ▼
7. POST /api/auth/register  ───────────────►  Valida que TODO sea blob
   Body: {                                    Almacena en BD:
     email,                                   • User(email, name)
     name,                                    • UserKeyMaterial(
     kdfSalt (base64),                            kdfSalt,
     kdfIterations: 600000,                       kdfIterations,
     publicKeyJwk (JSON),                         publicKeyJwk,
     encryptedPrivateKeyJwk (base64),             encryptedPrivateKeyJwk,
     privateKeyIv (base64)                        privateKeyIv)
   }                                          ◄── { userId }

❌ El servidor NUNCA recibe:
   • master password
   • masterKey derivada
   • privateKey en claro`;

const CREATE_SECRET_FLOW = `[CLIENTE]                                      [SERVIDOR]

1. Usuario autenticado (tiene masterKey + privateKey en memoria)
        │
        ▼
2. Generar AES-256 key aleatoria
   aesKey = crypto.subtle.generateKey("AES-GCM")
        │
        ▼
3. Generar IVs aleatorios (12 bytes c/u) para título y contenido
        │
        ▼
4. Cifrar título y contenido con AES-256-GCM
   encryptedTitle = AES-GCM(aesKey, title, titleIv)
   encryptedData  = AES-GCM(aesKey, content, dataIv)
        │
        ▼
5. Envolver (wrap) la aesKey con la publicKey del OWNER
   wrappedKey = RSA-OAEP(publicKey, raw(aesKey))
   ⚠️ Solo el owner puede desenvolverla con su privateKey
        │
        ▼
6. POST /api/secrets  ─────────────────────►  Valida que TODO sea base64
   Header: x-user-id: <ownerId>               Crea en transacción:
   Body: {                                    • Secret(ownerId,
     encryptedTitle,                              encryptedTitle,
     titleIv,                                      titleIv,
     encryptedData,                                encryptedData,
     dataIv,                                       dataIv)
     wrappedKeyForOwner                          )
   }                                          • SecretKeyShare(
                                                  secretId,
   ◄── { secretId }                                recipientId=ownerId,
                                                  wrappedSymmetricKey)

❌ El servidor NUNCA ve:
   • El contenido del secreto
   • El título del secreto
   • La llave AES en claro (solo envuelta con RSA)`;

const SHARE_SECRET_FLOW = `[OWNER]                                        [SERVIDOR]            [DESTINATARIO]

1. Owner quiere compartir el secreto S con el usuario B
        │
        ▼
2. GET /api/secrets  ◄──────────────────────  Devuelve lista con el
   (header: x-user-id = owner)                wrappedKey del owner
                                                para cada secreto
        │
        ▼
3. Owner desenvuelve SU wrappedKey usando SU privateKey
   aesKey = RSA-OAEP-DECRYPT(ownerPrivateKey, wrappedKey_owner)
   ⚠️ aesKey sale del proceso — owner la tiene en memoria
        │
        ▼
4. GET /api/users/lookup?email=B  ─────────►  Devuelve { userIdB, publicKeyJwkB }
        │
        ▼
5. Owner ENVUELVE la aesKey con la publicKey del destinatario B
   wrappedKeyB = RSA-OAEP(publicKeyB, raw(aesKey))
   ⚠️ Solo B puede desenvolverla con su privateKey
        │
        ▼
6. POST /api/shares  ──────────────────────►  Crea SecretKeyShare(
   Header: x-user-id = owner                     secretId=S,
   Body: {                                        recipientId=userIdB,
     secretId: S,                                 wrappedSymmetricKey=wrappedKeyB
     recipientId: userIdB,                     )
     wrappedSymmetricKey: wrappedKeyB
   }

                                                  ┌──────────────────┐
                                                  │  Cuando B inicie │
                                                  │  sesión y pida   │
                                                  │  GET /api/secrets│
                                                  │  recibirá SU     │
                                                  │  propia wrappedKeyB │
                                                  │  para el secreto S │
                                                  └──────────────────┘
                                                        │
                                                        ▼
                                                  7. B desenvuelve wrappedKeyB
                                                     con SU privateKey
                                                     aesKey = RSA-OAEP-DECRYPT(
                                                       B.privateKey, wrappedKeyB)

                                                        │
                                                        ▼
                                                  8. B descifra el contenido
                                                     content = AES-GCM-DECRYPT(
                                                       aesKey, encryptedData, dataIv)

❌ El servidor NUNCA ve la aesKey en ningún momento — solo wrappedKeys.
❌ Owner NUNCA envía su privateKey ni su wrappedKey al destinatario.
❌ Destinatario NUNCA necesita la privateKey del owner.

🔐 Propiedad matemática: RSA-OAEP solo puede ser revertido con la
   privateKey correspondiente a la publicKey usada en el wrapping.`;

const SECURITY_GUARANTEES = [
  {
    icon: EyeOff,
    title: "Cero Conocimiento del Servidor",
    desc: "El servidor nunca recibe master password, masterKey, llaves privadas en claro, ni llaves AES simétricas. Solo almacena blobs cifrados, sales públicas, IVs y llaves públicas RSA.",
  },
  {
    icon: ShieldCheck,
    title: "Resistencia a Brecha de BD",
    desc: "Si la BD se filtra, el atacante obtiene: salts (públicos), publicKeyJwk (público), encryptedPrivateKeyJwk (AES-256-GCM con masterKey que el atacante no tiene) y wrappedSymmetricKeys (RSA-OAEP que requieren privateKey que el atacante no tiene). Sin master password → sin PBKDF2 → sin descifrado.",
  },
  {
    icon: Users,
    title: "Compartir sin exponer claves",
    desc: "El owner desenvuelve su propia copia de la AES key (con su privateKey) y la re-envuelve con la publicKey del destinatario. La AES key nunca viaja en claro. El servidor solo ve una nueva wrappedKey.",
  },
  {
    icon: KeyRound,
    title: "Aislamiento de Llave Maestra",
    desc: "La masterKey se deriva con PBKDF2 (600.000 iter, SHA-256, salt único por usuario) y se marca como NO extraíble. Vive solo en memoria del navegador. Al cerrar/recargar la pestaña, se pierde y exige re-login.",
  },
  {
    icon: ShieldCheck,
    title: "Prueba de Posesión (PoP) en registro",
    desc: "El cliente firma {email, fingerprint, salt} con RSA-PSS antes de enviarlo. El servidor verifica la firma con la publicKey declarada antes de almacenar nada. Esto previene sustitución de publicKey: nadie puede registrar una cuenta usando la publicKey de otra persona.",
  },
  {
    icon: EyeOff,
    title: "Anti-enumeración de emails (login decoy)",
    desc: "Si el email NO existe, el servidor genera material criptográfico decoy determinista (HMAC-SHA-256 del email) con la misma estructura que un usuario real. El cliente ejecuta PBKDF2 + AES-GCM y falla con tag inválido — idéntico a contraseña incorrecta. El atacante no puede distinguir ambos casos.",
  },
  {
    icon: KeyRound,
    title: "TOFU con fingerprint de llaves públicas",
    desc: "Cada publicKey tiene una huella SHA-256 (hex). El cliente computa la huella localmente y la compara con la que el servidor devuelve. Si no coinciden, el servidor está sustituyendo llaves (MITM activo) y la operación se bloquea. La huella debe verificarse fuera de banda con el destinatario para máxima seguridad.",
  },
  {
    icon: ShieldCheck,
    title: "Validación server-side estricta de parámetros",
    desc: "kdfIterations ∈ [310.000, 1.000.000], salt ∈ [16, 64] bytes, IVs exactamente 12 bytes, blobs ≤ 64 KiB, JWKs ≤ 4 KiB, wrappedKeys exactamente 256 bytes (RSA-2048). Previene DoS y parámetros criptográficos degenerados.",
  },
  {
    icon: KeyRound,
    title: "Normalización Unicode NFC de contraseñas",
    desc: "Toda contraseña se normaliza a NFC antes de PBKDF2. Esto evita bloqueos accidentales cuando un usuario registra con caffè (NFC) y luego introduce café (NFD) — dos secuencias de bytes distintas para el mismo caracter visual.",
  },
];

const DB_SCHEMA = [
  {
    table: "User",
    rows: [
      { col: "id", type: "String (cuid)", clear: "—", note: "Identificador público" },
      { col: "email", type: "String", clear: "SÍ (en claro)", note: "Necesario para login y lookup" },
      { col: "name", type: "String?", clear: "SÍ (en claro)", note: "Display name opcional" },
      { col: "createdAt / updatedAt", type: "DateTime", clear: "SÍ", note: "Metadata" },
    ],
  },
  {
    table: "UserKeyMaterial",
    rows: [
      { col: "userId", type: "String (FK)", clear: "—", note: "Relación 1:1 con User" },
      { col: "kdfSalt", type: "String (base64, 16–64 B)", clear: "SÍ (público)", note: "Salt para PBKDF2 — no es secreto, validado server-side" },
      { col: "kdfIterations", type: "Int [310k–1M]", clear: "SÍ", note: "Validado server-side en rango OWASP — anti-DoS" },
      { col: "publicKeyJwk", type: "String (JSON ≤4 KB)", clear: "SÍ (público)", note: "Llave pública RSA-OAEP + RSA-PSS — pública por definición" },
      { col: "publicKeyFingerprint", type: "String (hex)", clear: "SÍ (público)", note: "SHA-256 del JWK canonizado — para TOFU y detección de sustitución" },
      { col: "popSignature", type: "String (base64)", clear: "SÍ (público)", note: "Firma RSA-PSS de {email, fingerprint, salt} — prueba que el cliente posee la privateKey" },
      { col: "popSignatureHash", type: "String", clear: "SÍ", note: "Algoritmo de hash usado para PoP — auditabilidad" },
      { col: "encryptedPrivateKeyJwk", type: "String (base64 ≤64 KB)", clear: "NO 🔒", note: "AES-256-GCM(masterKey, JWK(privKey)) — el servidor NO puede descifrar" },
      { col: "privateKeyIv", type: "String (base64, 12 B)", clear: "SÍ (público)", note: "IV de AES-GCM — público por diseño, validado server-side" },
    ],
  },
  {
    table: "Secret",
    rows: [
      { col: "id", type: "String (cuid)", clear: "—", note: "Identificador público" },
      { col: "ownerId", type: "String (FK)", clear: "SÍ", note: "Quién creó el secreto" },
      { col: "encryptedTitle", type: "String (base64)", clear: "NO 🔒", note: "AES-256-GCM(aesKey, title) — el servidor desconoce el título" },
      { col: "titleIv", type: "String (base64)", clear: "SÍ (público)", note: "IV público" },
      { col: "encryptedData", type: "String (base64)", clear: "NO 🔒", note: "AES-256-GCM(aesKey, content) — el servidor desconoce el contenido" },
      { col: "dataIv", type: "String (base64)", clear: "SÍ (público)", note: "IV público" },
      { col: "createdAt / updatedAt", type: "DateTime", clear: "SÍ", note: "Metadata" },
    ],
  },
  {
    table: "SecretKeyShare",
    rows: [
      { col: "id", type: "String (cuid)", clear: "—", note: "Identificador" },
      { col: "secretId", type: "String (FK)", clear: "—", note: "Secreto al que da acceso" },
      { col: "recipientId", type: "String (FK)", clear: "SÍ", note: "Usuario destinatario" },
      { col: "wrappedSymmetricKey", type: "String (base64)", clear: "NO 🔒", note: "RSA-OAEP(publicKey_recipient, raw(aesKey)) — solo el destinatario puede desenvolverla" },
      { col: "createdAt", type: "DateTime", clear: "SÍ", note: "Metadata" },
      { col: "UNIQUE(secretId, recipientId)", type: "Constraint", clear: "—", note: "Un usuario tiene una sola wrappedKey por secreto" },
    ],
  },
];

function FlowBlock({ title, content, icon: Icon }: { title: string; content: string; icon: any }) {
  return (
    <Card className="bg-card/60">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Icon className="size-5 text-primary" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <pre className="overflow-x-auto rounded-lg border border-border/60 bg-background/80 p-4 text-[11px] leading-relaxed text-foreground/90 font-mono">
          {content}
        </pre>
      </CardContent>
    </Card>
  );
}

export function ArchitectureView() {
  return (
    <div className="space-y-6">
      {/* Hero */}
      <Card className="border-primary/30 bg-gradient-to-br from-card/80 to-primary/5">
        <CardHeader>
          <div className="flex items-start gap-3">
            <div className="rounded-lg bg-primary/15 p-2.5">
              <ShieldCheck className="size-7 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl">
                Gestor de Contraseñas Zero-Knowledge para Equipos
              </CardTitle>
              <CardDescription className="mt-1.5 text-sm leading-relaxed">
                Arquitectura end-to-end donde el servidor es un{" "}
                <span className="font-semibold text-foreground">crypto-blind store</span>: solo
                guarda blobs cifrados. Todo el cifrado AES-256-GCM ocurre en el navegador con Web
                Crypto API. La llave maestra nunca sale del cliente, y los secretos se comparten
                mediante <span className="font-semibold text-foreground">key wrapping</span> RSA-OAEP
                sin que el servidor vea jamás la llave simétrica.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Stack criptográfico */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "KDF", value: "PBKDF2-SHA256", sub: "600.000 iteraciones", icon: KeyRound },
          { label: "Simétrico", value: "AES-256-GCM", sub: "IV 96-bit", icon: Lock },
          { label: "Asimétrico", value: "RSA-OAEP 2048", sub: "SHA-256", icon: Unlock },
          { label: "Wrapping", value: "RSA-OAEP wrap", sub: "de AES key raw", icon: Users },
        ].map((s) => (
          <Card key={s.label} className="bg-card/60">
            <CardContent className="flex flex-col gap-1 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  {s.label}
                </span>
                <s.icon className="size-4 text-primary" />
              </div>
              <span className="text-base font-semibold text-foreground">{s.value}</span>
              <span className="text-xs text-muted-foreground">{s.sub}</span>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Diagramas de flujo */}
      <div>
        <h2 className="mb-3 text-lg font-semibold text-foreground">Diagramas de flujo</h2>
        <div className="grid gap-4">
          <FlowBlock title="1. Registro de usuario" content={REGISTRATION_FLOW} icon={KeyRound} />
          <FlowBlock title="2. Creación de un secreto" content={CREATE_SECRET_FLOW} icon={Lock} />
          <FlowBlock
            title="3. Compartir un secreto con otro miembro del equipo"
            content={SHARE_SECRET_FLOW}
            icon={Users}
          />
        </div>
      </div>

      {/* Esquema BD */}
      <div>
        <h2 className="mb-3 flex items-center gap-2 text-lg font-semibold text-foreground">
          <Database className="size-5 text-primary" />
          Esquema de Base de Datos — qué se guarda en claro vs. cifrado
        </h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {DB_SCHEMA.map((t) => (
            <Card key={t.table} className="bg-card/60">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 font-mono text-base">
                  <Server className="size-4 text-primary" />
                  {t.table}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {t.rows.map((r) => (
                  <div
                    key={r.col}
                    className="flex flex-col gap-1 border-b border-border/40 pb-2 last:border-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="flex flex-col">
                      <code className="text-xs font-semibold text-foreground">{r.col}</code>
                      <span className="text-[10px] text-muted-foreground">{r.type}</span>
                    </div>
                    <div className="flex flex-col items-start gap-1 sm:items-end">
                      <Badge
                        variant="outline"
                        className={
                          r.clear.startsWith("NO")
                            ? "border-primary/40 bg-primary/10 text-primary"
                            : "border-muted-foreground/30 bg-muted/30 text-muted-foreground"
                        }
                      >
                        {r.clear.startsWith("NO") ? <Lock className="mr-1 size-3" /> : null}
                        {r.clear}
                      </Badge>
                      <span className="max-w-[260px] text-[10px] leading-tight text-muted-foreground">
                        {r.note}
                      </span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Garantías de seguridad */}
      <div>
        <h2 className="mb-3 text-lg font-semibold text-foreground">Garantías de seguridad</h2>
        <div className="grid gap-3 md:grid-cols-2">
          {SECURITY_GUARANTEES.map((g) => (
            <Card key={g.title} className="bg-card/60">
              <CardContent className="flex gap-3 p-4">
                <div className="rounded-lg bg-primary/15 p-2">
                  <g.icon className="size-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-foreground">{g.title}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{g.desc}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Advertencia */}
      <Card className="border-amber-500/40 bg-amber-500/5">
        <CardContent className="flex gap-3 p-4">
          <AlertTriangle className="size-5 shrink-0 text-amber-500" />
          <div className="text-xs leading-relaxed text-foreground/80">
            <strong className="text-amber-500">Nota sobre esta demo:</strong> para mantener la
            simulación simple, el identificador de usuario se pasa en el header{" "}
            <code className="rounded bg-muted/40 px-1 py-0.5">x-user-id</code> en lugar de un JWT
            firmado. En producción se debe usar NextAuth / JWT con expiración, rate-limiting en
            endpoints de login, y Argon2id (vía WASM) en lugar de PBKDF2 cuando el navegador lo
            permita. Adicionalmente, las claves en memoria se pierden al recargar la pestaña, lo
            cual es <em>correcto</em> desde el punto de vista de seguridad pero exige re-login.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
