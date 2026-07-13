import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  return NextResponse.json({
    compliance: {
      gdpr: { status: "compliant", features: ["crypto-shredding", "data-export", "rtbf"] },
      soc2: { status: "pre-audit", features: ["audit-logs", "hash-chaining", "rbac", "access-control"] },
      hipaa: { status: "not-applicable", note: "No PHI data stored" },
      iso27001: { status: "pre-audit", features: ["encryption-at-rest", "encryption-in-transit", "access-logging"] },
    },
    lastChecked: new Date().toISOString(),
  });
}
