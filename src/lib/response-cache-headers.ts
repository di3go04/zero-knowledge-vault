/**
 * response-cache-headers.ts — Cache-Control headers para endpoints.
 */
import { NextResponse } from "next/server";

export function setCacheHeaders(
  response: NextResponse,
  type: "public" | "private" | "no-store",
  maxAgeSeconds: number = 30,
): NextResponse {
  switch (type) {
    case "public":
      response.headers.set("Cache-Control", `public, max-age=${maxAgeSeconds}, s-maxage=${maxAgeSeconds * 2}`);
      break;
    case "private":
      response.headers.set("Cache-Control", `private, max-age=${maxAgeSeconds}`);
      break;
    case "no-store":
      response.headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
      break;
  }
  return response;
}
