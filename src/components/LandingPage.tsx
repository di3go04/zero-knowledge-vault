"use client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Lock, ShieldCheck, KeyRound, Smartphone, Database, Check } from "lucide-react";
import Link from "next/link";

const features = [
  { icon: Lock, title: "Cifrado AES-256-GCM", desc: "Todo ocurre en tu navegador. El servidor nunca ve tus secretos." },
  { icon: KeyRound, title: "Argon2id + BIP-39", desc: "KDF memory-hard resistente a GPU. Recovery con 24 palabras." },
  { icon: Smartphone, title: "Multi-Device ECDH", desc: "Autoriza nuevos dispositivos con challenge-response ECDSA P-256." },
  { icon: ShieldCheck, title: "Post-Quantum Ready", desc: "ML-KEM-768 implementado. Preparado para la era cuántica." },
  { icon: Database, title: "Audit Logs Cifrados", desc: "Hash chaining tamper-evident. Solo tú puedes descifrar tus logs." },
];

const plans = [
  { name: "Free", price: "$0", features: ["1 usuario", "50 secretos", "1 dispositivo"], cta: "Empezar gratis" },
  { name: "Team", price: "$4", features: ["50 usuarios", "Secretos ilimitados", "10 dispositivos", "Audit log"], cta: "Probar 14 días", popular: true },
  { name: "Business", price: "$8", features: ["500 usuarios", "SSO OIDC", "Roles admin", "50 dispositivos"], cta: "Contactar" },
];

export function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border/40">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-2">
            <Lock className="size-5 text-primary" />
            <span className="font-semibold">Zero-Knowledge Vault</span>
          </div>
          <Link href="/"><Button variant="ghost" size="sm">Iniciar sesión</Button></Link>
        </div>
      </header>

      <section className="mx-auto max-w-5xl px-4 py-16 text-center">
        <Badge variant="outline" className="mb-4 border-primary/40 bg-primary/10 text-primary">Zero-Knowledge Real</Badge>
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">Tu bóveda de secretos.<br/>Cifrada en tu navegador.</h1>
        <p className="mx-auto mt-4 max-w-2xl text-muted-foreground">El servidor es un crypto-blind store. Nunca recibe tu contraseña maestra, llaves privadas, ni el contenido de tus secretos. Resistente a brechas de BD.</p>
        <div className="mt-8 flex justify-center gap-3">
          <Link href="/"><Button size="lg">Crear bóveda gratis</Button></Link>
          <Link href="/?tab=arch"><Button size="lg" variant="outline">Ver arquitectura</Button></Link>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-12">
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <Card key={f.title} className="bg-card/60">
              <CardContent className="p-6">
                <f.icon className="mb-3 size-6 text-primary" />
                <h3 className="font-semibold">{f.title}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{f.desc}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-12">
        <h2 className="mb-8 text-center text-2xl font-bold">Planes</h2>
        <div className="grid gap-6 sm:grid-cols-3">
          {plans.map((p) => (
            <Card key={p.name} className={p.popular ? "border-primary" : ""}>
              <CardHeader><CardTitle className="flex items-center justify-between">{p.name}{p.popular ? <Badge className="text-[10px]">Popular</Badge> : null}</CardTitle></CardHeader>
              <CardContent>
                <p className="text-3xl font-bold">{p.price}<span className="text-sm font-normal text-muted-foreground">/mes</span></p>
                <ul className="mt-4 space-y-2 text-sm">
                  {p.features.map((f) => (<li key={f} className="flex items-center gap-2"><Check className="size-4 text-primary" />{f}</li>))}
                </ul>
                <Link href="/"><Button className="mt-6 w-full" variant={p.popular ? "default" : "outline"}>{p.cta}</Button></Link>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <footer className="border-t border-border/40 py-8 text-center text-xs text-muted-foreground">
        <p>Zero-Knowledge Vault · AES-256-GCM · Argon2id · ECDH P-256 · ML-KEM-768 · MIT License</p>
      </footer>
    </div>
  );
}
