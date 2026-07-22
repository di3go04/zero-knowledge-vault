import { execSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

if (!process.env.DATABASE_URL) {
  const tmpDbDir = mkdtempSync(join(tmpdir(), "zkv-test-"));
  const dbPath = join(tmpDbDir, "test.db");
  process.env.DATABASE_URL = `file:${dbPath}`;
  process.env.REDIS_URL = "";
  process.env.SESSION_SECRET = process.env.SESSION_SECRET ?? "test-secret-min-32-chars-do-not-use-in-prod!";

  execSync("npx prisma db push --skip-generate --accept-data-loss 2>&1", {
    env: { ...process.env, DATABASE_URL: `file:${dbPath}` },
    stdio: "pipe",
  });
} else {
  process.env.REDIS_URL = process.env.REDIS_URL ?? "";
  process.env.SESSION_SECRET = process.env.SESSION_SECRET ?? "test-secret-min-32-chars-do-not-use-in-prod!";
}
