"use client";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArchitectureView } from "@/components/ArchitectureView";
import { AuthView } from "@/components/AuthView";
import { VaultView } from "@/components/VaultView";
import { useSession, isAuthenticated } from "@/lib/session-store";
import { Lock, BookOpen, Database, ShieldCheck } from "lucide-react";

export default function Home() {
  const session = useSession();
  const authed = isAuthenticated(session);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-border/40 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary/15">
              <Lock className="size-5 text-primary" />
            </div>
            <div>
              <h1 className="text-sm font-semibold leading-tight sm:text-base">
                Zero-Knowledge Vault
              </h1>
              <p className="hidden text-[10px] text-muted-foreground sm:block">
                Gestor de contraseñas para equipos · cifrado end-to-end en el navegador
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-2.5 py-1 text-[10px] text-primary sm:flex">
              <Lock className="size-3" />
              AES-256-GCM · RSA-OAEP · PBKDF2
            </span>
            {authed ? (
              <span className="rounded-full border border-border/40 bg-card px-2.5 py-1 text-[10px] text-muted-foreground">
                {session.email}
              </span>
            ) : null}
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        <Tabs defaultValue="arch" className="w-full">
          <TabsList className="grid w-full grid-cols-2 sm:max-w-md">
            <TabsTrigger value="arch" className="text-xs sm:text-sm">
              <BookOpen className="mr-1.5 size-3.5 sm:size-4" />
              Arquitectura
            </TabsTrigger>
            <TabsTrigger value="vault" className="text-xs sm:text-sm">
              <Database className="mr-1.5 size-3.5 sm:size-4" />
              Demo Vault
            </TabsTrigger>
          </TabsList>

          <TabsContent value="arch" className="mt-6">
            <ArchitectureView />
          </TabsContent>

          <TabsContent value="vault" className="mt-6">
            {authed ? <VaultView /> : <AuthView />}
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-border/40 bg-background/50">
        <div className="mx-auto max-w-6xl px-4 py-4 text-center text-[10px] text-muted-foreground sm:px-6">
          <p>
            Implementación de referencia · Web Crypto API · El servidor nunca recibe llaves
            maestras, llaves privadas en claro, ni llaves simétricas.
          </p>
        </div>
      </footer>
    </div>
  );
}
