/**
 * =====================================================================
 * ws-sync/index.ts — WebSocket service para sync multi-device real.
 * =====================================================================
 * MEJORA 1/50: WebSocket REAL con Socket.io.
 *
 * Flujo:
 *   1. Cliente pide token WS a /api/ws-token (autenticado)
 *   2. Cliente conecta a ws://localhost:3003/?XTransformPort=3003
 *   3. Servidor notifica al usuario cuando:
 *      - Un secreto es compartido con él
 *      - Un secreto propio es borrado
 *      - Un dispositivo es autorizado/revocado
 *
 * El servidor SOLO envía notificaciones de "algo cambió" — nunca
 * envía el contenido del secreto. El cliente debe hacer GET /api/secrets
 * para obtener los datos cifrados.
 * =====================================================================
 */
import { createServer } from "http";
import { Server } from "socket.io";
import { verifySessionToken } from "../../src/lib/session-token";

const PORT = 3003;

const httpServer = createServer();
const io = new Server(httpServer, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  path: "/",
});

// Map: userId -> Set<socket>
const userSockets = new Map<string, Set<string>>();

io.on("connection", (socket) => {
  const token = socket.handshake.auth?.token as string | undefined;
  if (!token) {
    socket.disconnect();
    return;
  }

  const payload = verifySessionToken(token);
  if (!payload) {
    socket.disconnect();
    return;
  }

  const userId = payload.uid;
  socket.data.userId = userId;

  // Registrar socket del usuario
  if (!userSockets.has(userId)) {
    userSockets.set(userId, new Set());
  }
  userSockets.get(userId)!.add(socket.id);

  socket.on("disconnect", () => {
    const sockets = userSockets.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        userSockets.delete(userId);
      }
    }
  });
});

/**
 * Notifica a un usuario que algo cambió en su bóveda.
 * Llamado por los endpoints POST/DELETE de secrets y shares.
 *
 * IMPORTANTE: solo envía { type, secretId } — NUNCA contenido.
 */
export function notifyUser(userId: string, event: { type: string; secretId?: string }) {
  const sockets = userSockets.get(userId);
  if (!sockets || sockets.size === 0) return;

  for (const socketId of sockets) {
    io.to(socketId).emit("vault:update", event);
  }
}

// Exportar io para que los API routes puedan llamar notifyUser
export { io };

httpServer.listen(PORT, () => {
  console.log(`[ws-sync] WebSocket server en puerto ${PORT}`);
});
