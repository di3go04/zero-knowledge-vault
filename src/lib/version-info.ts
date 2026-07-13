/**
 * version-info.ts — Información de versión del build.
 */
import { execSync } from "node:child_process";
import packageJson from "../../package.json";

let gitHash: string | null = null;
try {
  gitHash = execSync("git rev-parse --short HEAD", { encoding: "utf-8" }).trim();
} catch {
  gitHash = null;
}

export const VERSION_INFO = {
  version: packageJson.version,
  gitHash,
  buildTime: process.env.BUILD_TIME || new Date().toISOString(),
  nodeVersion: process.version,
  environment: process.env.NODE_ENV || "development",
};

export function getVersionInfo() {
  return VERSION_INFO;
}
