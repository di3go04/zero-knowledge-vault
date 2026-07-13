"use client";

import { useEffect, useRef } from "react";
import { useSession } from "@/lib/session-store";
import { io as ioClient, type Socket } from "socket.io-client";

/**
 * Hook de WebSocket para sync multi-device real.
 *
 * en su bóveda (secreto compartido, borrado, dispositivo autorizado).
 *
 * El servidor SOLO envía { type, secretId } — nunca contenido.
 */
export function useWebSocketSync(onVaultUpdate?: (event: { type: string; secretId?: string }) => void) {
  const socketRef = useRef<Socket | null>(null);
  const sessionToken = useSession((s) => s.sessionToken);

  useEffect(() => {
    if (!sessionToken) return;

    let cancelled = false;

    (async () => {
      try {
        // 1. Obtener WS token
        const res = await fetch("/api/ws-token", {
          headers: { Authorization: `Bearer ${sessionToken}` },
        });
        const data = await res.json();
        if (!res.ok || !data.wsToken) return;

        if (cancelled) return;

        // 2. Conectar al WebSocket service
        const socket = ioClient(data.wsUrl, {
          auth: { token: data.wsToken },
          transports: ["websocket"],
          reconnection: true,
          reconnectionDelay: 2000,
          reconnectionAttempts: 5,
        });

        socketRef.current = socket;

        socket.on("connect", () => {
          console.log("[ws] Conectado para sync multi-device");
        });

        socket.on("vault:update", (event: { type: string; secretId?: string }) => {
          console.log("[ws] Notificación de actualización:", event.type);
          onVaultUpdate?.(event);
        });

        socket.on("disconnect", () => {
          console.log("[ws] Desconectado");
        });

        socket.on("connect_error", (err: Error) => {
          console.warn("[ws] Error de conexión:", err.message);
        });
      } catch (err) {
        // Silently fail — el WebSocket es opcional
      }
    })();

    return () => {
      cancelled = true;
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [sessionToken, onVaultUpdate]);
}
