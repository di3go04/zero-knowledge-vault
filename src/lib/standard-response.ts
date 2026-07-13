/**
 * standard-response.ts — Estandariza respuestas de error y éxito.
 */
import { NextResponse } from "next/server";

export function errorResponse(error: string, status: number = 400, requestId?: string): NextResponse {
  const response = NextResponse.json({ error, requestId }, { status });
  if (requestId) response.headers.set("X-Request-ID", requestId);
  return response;
}

export function successResponse(data: Record<string, unknown>, status: number = 200, requestId?: string): NextResponse {
  const response = NextResponse.json({ ...data, requestId }, { status });
  if (requestId) response.headers.set("X-Request-ID", requestId);
  return response;
}

export function rateLimitResponse(retryAfter: number): NextResponse {
  return NextResponse.json(
    { error: "Too many requests", retryAfter },
    {
      status: 429,
      headers: {
        "Retry-After": String(retryAfter),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": String(retryAfter),
      },
    },
  );
}
