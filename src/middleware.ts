import { NextRequest, NextResponse } from "next/server";
import { extractUserIdFromAuth } from "@/lib/session-token";

const publicPaths = [
  "/api/auth/login",
  "/api/auth/register",
  "/api/auth/recovery/recover",
  "/api/devices/enroll/init",
  "/api/devices/enroll/poll",
  "/api/devices/enroll/poll/verify",
  "/api/users/lookup",
  "/api",
];

const publicExactPaths = new Set([
  "/api",
]);

const publicPrefixes = [
  "/api/auth/login",
  "/api/auth/register",
  "/api/auth/recovery/recover",
  "/api/devices/enroll/init",
  "/api/devices/enroll/poll",
  "/api/devices/enroll/poll/verify",
  "/api/users/lookup",
];

function isPublicPath(pathname: string): boolean {
  if (publicExactPaths.has(pathname)) return true;
  return publicPrefixes.some((prefix) => pathname.startsWith(prefix));
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  const userId = await extractUserIdFromAuth(req.headers.get("authorization"));
  if (!userId) {
    return NextResponse.json(
      { error: "No autenticado. Proporciona un Authorization: Bearer <token> válido." },
      { status: 401 },
    );
  }

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-authenticated-user-id", userId);

  return NextResponse.next({
    request: { headers: requestHeaders },
  });
}

export const config = {
  matcher: "/api/:path*",
};
