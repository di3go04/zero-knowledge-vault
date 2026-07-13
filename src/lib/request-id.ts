/**
 * request-id.ts — Genera un ID único por petición para tracing.
 */
import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";

export function generateRequestId(): string {
  return randomUUID();
}

export function addRequestId(response: NextResponse, requestId: string): NextResponse {
  response.headers.set("X-Request-ID", requestId);
  return response;
}
