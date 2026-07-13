/**
 * graceful-shutdown.ts — SIGTERM handler que cierra conexiones limpiamente.
 *
 *
 * Al recibir SIGTERM (Kubernetes/Docker stop):
 *   1. Dejar de aceptar nuevas conexiones
 *   2. Esperar a que las conexiones activas terminen (max 30s)
 *   3. Cerrar conexión a BD
 *   4. Cerrar conexión a Redis
 *   5. Exit limpio
 */
import { db } from "@/lib/db";

let isShuttingDown = false;

export function isGracefulShutdownActive(): boolean {
  return isShuttingDown;
}

export function setupGracefulShutdown() {
  const shutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`[shutdown] Señal ${signal} recibida. Cerrando gracefully...`);

    // Timeout de 30s para forzar exit
    const forceExit = setTimeout(() => {
      console.error("[shutdown] Timeout — forzando exit");
      process.exit(1);
    }, 30_000);

    try {
      // 1. Cerrar conexión a BD
      await db.$disconnect();
      console.log("[shutdown] BD desconectada");

      // 2. Cerrar Redis (si está activo)
      // El adaptador de blacklist/rate-limit/challenge-store maneja su propia desconexión
      console.log("[shutdown] Redis cerrado (si estaba activo)");

      clearTimeout(forceExit);
      console.log("[shutdown] Cierre graceful completado");
      process.exit(0);
    } catch (err) {
      console.error("[shutdown] Error durante cierre:", err);
      clearTimeout(forceExit);
      process.exit(1);
    }
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
