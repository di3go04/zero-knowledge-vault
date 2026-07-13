/**
 * hash-chain-logs.ts — Hash chaining para audit logs tamper-evident.
 *
 */
import { createHash } from "node:crypto";

export function computeLogHash(
  prevHash: string | null,
  encryptedEvent: string,
  createdAt: string,
): string {
  const data = `${prevHash ?? ""}|${encryptedEvent}|${createdAt}`;
  return createHash("sha256").update(data).digest("hex");
}

export function verifyLogChain(logs: { prevHash: string | null; logHash: string; encryptedEvent: string; createdAt: string }[]): {
  valid: boolean;
  brokenAtIndex: number | null;
} {
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    const expectedHash = computeLogHash(log.prevHash, log.encryptedEvent, log.createdAt);
    if (expectedHash !== log.logHash) {
      return { valid: false, brokenAtIndex: i };
    }
  }
  return { valid: true, brokenAtIndex: null };
}
