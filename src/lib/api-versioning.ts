/**
 * api-versioning.ts — Headers de versionado de API.
 */
import { NextResponse } from "next/server";

const API_VERSION = "v1";
const SDK_VERSION = "zk-vault-sdk/1.0.0";

export function addVersionHeaders(response: NextResponse): NextResponse {
  response.headers.set("X-API-Version", API_VERSION);
  response.headers.set("X-SDK-Version", SDK_VERSION);
  return response;
}

export function addDeprecationWarning(response: NextResponse, sunsetDate: string): NextResponse {
  response.headers.set("Deprecation", "true");
  response.headers.set("Sunset", sunsetDate);
  return response;
}
