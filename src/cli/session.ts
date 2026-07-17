import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";

const CONFIG_DIR = join(process.env.HOME ?? process.env.USERPROFILE ?? ".", ".zk-vault");
const SESSION_FILE = join(CONFIG_DIR, "session.json");

interface SessionData {
  token: string;
  userId: string;
  createdAt: string;
}

function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export const session = {
  save(token: string, userId: string): void {
    ensureConfigDir();
    const data: SessionData = { token, userId, createdAt: new Date().toISOString() };
    writeFileSync(SESSION_FILE, JSON.stringify(data, null, 2), "utf-8");
    // Restrict permissions on Unix-like systems
    if (process.platform !== "win32") {
      try {
        const { chmodSync } = require("fs");
        chmodSync(SESSION_FILE, 0o600);
      } catch { /* ignore */ }
    }
  },

  load(): string | null {
    try {
      if (!existsSync(SESSION_FILE)) return null;
      const raw = readFileSync(SESSION_FILE, "utf-8");
      const data = JSON.parse(raw) as SessionData;
      return data.token;
    } catch {
      return null;
    }
  },

  clear(): void {
    try {
      if (existsSync(SESSION_FILE)) {
        unlinkSync(SESSION_FILE);
      }
    } catch { /* ignore */ }
  },
};
