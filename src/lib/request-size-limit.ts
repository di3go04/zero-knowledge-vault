/**
 * request-size-limit.ts — Middleware para limitar tamaño de peticiones.
 */
import { NextRequest, NextResponse } from "next/server";

const MAX_BODY_SIZE = 256 * 1024; // 256 KiB

export function checkRequestSize(req: NextRequest): NextResponse | null {
  const contentLength = req.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    return NextResponse.json(
      { error: `Request body too large (max ${MAX_BODY_SIZE} bytes)` },
      { status: 413 },
    );
  }
  return null;
}
