"use client";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Lock } from "lucide-react";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background px-4 text-center">
      <Lock className="size-12 text-muted-foreground/40" />
      <h1 className="text-6xl font-bold">404</h1>
      <p className="text-muted-foreground">Esta página no existe o fue cifrada.</p>
      <Link href="/"><Button>Volver al inicio</Button></Link>
    </div>
  );
}
