import { NextResponse } from "next/server";

interface SSEClient {
  id: string;
  controller: ReadableStreamDefaultController;
}

const clients = new Map<string, SSEClient>();
const encoder = new TextEncoder();

export function GET(req: Request) {
  const userId = req.headers.get("x-user-id") || "anonymous";

  const stream = new ReadableStream({
    start(controller) {
      const client: SSEClient = { id: userId + "-" + Date.now(), controller };
      clients.set(client.id, client);

      controller.enqueue(
        encoder.encode(`data: ${JSON.stringify({ type: "connected", message: "Conectado" })}\n\n`)
      );

      req.signal.addEventListener("abort", () => {
        clients.delete(client.id);
      });
    },
  });

  return new NextResponse(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

export function broadcastNotification(userId: string, event: { type: string; message: string }) {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  for (const [, client] of clients) {
    if (client.id.startsWith(userId)) {
      try {
        client.controller.enqueue(encoder.encode(data));
      } catch {
        clients.delete(client.id);
      }
    }
  }
}

export async function POST(req: Request) {
  const body = (await req.json()) as { userId?: string; type?: string; message?: string };
  broadcastNotification(body.userId || "anonymous", {
    type: body.type || "notification",
    message: body.message || "",
  });
  return NextResponse.json({ sent: true });
}
