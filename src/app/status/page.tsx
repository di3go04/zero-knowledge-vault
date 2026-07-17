"use client";

import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface HealthCheck {
  status: string;
  version: string;
  timestamp: string;
  uptime: number;
  checks: {
    database: boolean;
    redis: boolean;
  };
}

export default function StatusPage() {
  const [health, setHealth] = useState<HealthCheck | null>(null);

  const fetchHealth = useCallback(() => {
    fetch("/api/health")
      .then((res) => res.json() as Promise<HealthCheck>)
      .then((data) => setHealth(data))
      .catch(() => {
        setHealth({
          status: "error",
          version: "unknown",
          timestamp: new Date().toISOString(),
          uptime: 0,
          checks: { database: false, redis: false },
        });
      });
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  if (!health) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-muted-foreground">Cargando estado...</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold tracking-tight">Estado del Sistema</h1>

      <Card>
        <CardHeader>
          <CardTitle>Vista General</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Estado</span>
            <span
              className={`font-medium ${
                health.status === "ok" ? "text-green-600" : "text-red-600"
              }`}
            >
              {health.status === "ok" ? "Operacional" : "Degradado"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Versión</span>
            <span className="font-mono text-sm">{health.version}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Uptime</span>
            <span className="font-mono text-sm">
              {Math.floor(health.uptime / 60)}m {Math.floor(health.uptime % 60)}s
            </span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Servicios</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <span>Base de datos</span>
            <span
              className={`size-2.5 rounded-full ${
                health.checks.database ? "bg-green-500" : "bg-red-500"
              }`}
            />
          </div>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <span>Redis</span>
            <span
              className={`size-2.5 rounded-full ${
                health.checks.redis ? "bg-green-500" : "bg-yellow-500"
              }`}
            />
          </div>
        </CardContent>
      </Card>

      <button
        onClick={fetchHealth}
        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
      >
        Refrescar
      </button>
    </div>
  );
}
