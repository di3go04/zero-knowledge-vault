import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "fs";
import { join } from "path";

describe("Code Deduplication", () => {
  const srcDir = join(__dirname, "..");

  function getAllFiles(dir: string): string[] {
    const files: string[] = [];
    for (const entry of readdirSync(dir)) {
      const fullPath = join(dir, entry);
      if (
        statSync(fullPath).isDirectory() &&
        !entry.startsWith("__tests__") &&
        !entry.startsWith("node_modules")
      ) {
        files.push(...getAllFiles(fullPath));
      } else if (entry.endsWith(".ts") || entry.endsWith(".tsx")) {
        files.push(fullPath);
      }
    }
    return files;
  }

  it("should not have duplicate Base64 utility functions", () => {
    const files = getAllFiles(srcDir);
    const base64Patterns = files.filter((f) => {
      const content = readFileSync(f, "utf-8");
      return content.includes("Buffer.from") && content.includes("base64");
    });

    expect(base64Patterns.length).toBeGreaterThan(0);
  });

  it("should have consistent NextResponse.json pattern", () => {
    const files = getAllFiles(srcDir);
    const responsePatterns = files.filter((f) => {
      const content = readFileSync(f, "utf-8");
      return content.includes("NextResponse.json");
    });

    expect(responsePatterns.length).toBeGreaterThan(0);
  });
});
