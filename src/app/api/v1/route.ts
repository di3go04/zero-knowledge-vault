import { NextResponse } from "next/server";

export function GET() {
  return NextResponse.json({
    version: "v1",
    message: "Zero-Knowledge Vault API v1",
    docs: "/docs/API_REFERENCE.md",
  });
}
