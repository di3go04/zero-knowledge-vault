/**
 * Hash chain utilities for tamper-evident audit logs.
 *
 * Each audit log entry stores:
 *   - prevHash: SHA-256 hash of the previous entry (or null for the first)
 *   - logHash:  SHA-256 of (prevHash || encryptedEvent || eventIv || createdAt)
 *
 * Verification walks the chain and recomputes each hash; if any hash
 * does not match, the chain has been tampered with.
 */

/**
 * Compute the SHA-256 hash of a string and return it as hex.
 */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bufferToHex(digest);
}

/**
 * Compute the next hash in the chain given the previous hash and the
 * current entry's fields.
 */
export async function computeLogHash(params: {
  prevHash: string | null;
  encryptedEvent: string;
  eventIv: string;
  createdAt: string;
}): Promise<string> {
  const concat = `${params.prevHash ?? ""}|${params.encryptedEvent}|${params.eventIv}|${params.createdAt}`;
  return sha256Hex(concat);
}

/**
 * Verify a chain of audit log entries. Returns the index of the first
 * broken entry, or null if the entire chain is valid.
 */
export async function verifyChain(
  entries: Array<{
    prevHash: string | null;
    logHash: string | null;
    encryptedEvent: string;
    eventIv: string;
    createdAt: string;
  }>
): Promise<{ ok: boolean; firstBrokenIndex: number | null }> {
  let prevHash: string | null = null;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    // Verify linkage
    if (entry.prevHash !== prevHash) {
      return { ok: false, firstBrokenIndex: i };
    }
    // Verify hash
    const expected = await computeLogHash({
      prevHash: entry.prevHash,
      encryptedEvent: entry.encryptedEvent,
      eventIv: entry.eventIv,
      createdAt: entry.createdAt,
    });
    if (entry.logHash !== expected) {
      return { ok: false, firstBrokenIndex: i };
    }
    prevHash = entry.logHash;
  }
  return { ok: true, firstBrokenIndex: null };
}

function bufferToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}
