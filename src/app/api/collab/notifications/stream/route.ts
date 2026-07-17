import { db } from "@/lib/db";
import { extractUserIdFromAuth } from "@/lib/session-token";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  const authHeader = req.headers.get("authorization");
  const userId = await extractUserIdFromAuth(authHeader);
  if (!userId) {
    return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }

  let lastChecked = new Date();

  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();

      const sendEvent = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };

      sendEvent("connected", { message: "Conectado al stream de notificaciones" });

      const poll = async () => {
        try {
          const notifications = await db.notification.findMany({
            where: { userId, read: false, createdAt: { gt: lastChecked } },
            orderBy: { createdAt: "asc" },
            take: 50,
          });

          if (notifications.length > 0) {
            lastChecked = notifications[notifications.length - 1].createdAt;
            for (const n of notifications) {
              sendEvent("notification", n);
            }
          }
        } catch {
          // Connection might be closed
        }
      };

      const interval = setInterval(poll, 5000);

      req.signal.addEventListener("abort", () => {
        clearInterval(interval);
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
