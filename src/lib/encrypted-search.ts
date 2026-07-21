/**
 * Client-side encrypted search.
 *
 * The server never sees plaintext secret titles. To search, the client
 * must first decrypt titles locally, then filter. This module provides:
 *
 * 1. decryptAndSearch — decrypts all titles with masterKey, filters by query
 * 2. buildSearchIndex — pre-builds an in-memory index for fast repeated queries
 * 3. SearchIndex class — maintains a decrypted index that can be queried
 *
 * Security: all decryption happens client-side. The server only sends
 * encrypted blobs; the search query never leaves the browser.
 */
import { aesDecrypt, type KdfParams } from "@/lib/crypto";

export interface EncryptedSecretMeta {
  id: string;
  encryptedTitle: string;
  titleIv: string;
  ownerId: string;
  createdAt: string;
}

export interface SearchResult {
  id: string;
  title: string;
  createdAt: string;
  score: number; // 0 = exact match, higher = worse
}

/**
 * Decrypt all titles and filter by query. Returns results sorted by
 * relevance (exact match first, then startsWith, then includes).
 *
 * @param secrets - Encrypted secret metadata from /api/secrets
 * @param masterKey - User's master CryptoKey
 * @param query - Search query (case-insensitive)
 */
export async function decryptAndSearch(
  secrets: EncryptedSecretMeta[],
  masterKey: CryptoKey,
  query: string,
): Promise<SearchResult[]> {
  if (!query.trim()) {
    // No query: decrypt all and return with score 0
    const results: SearchResult[] = [];
    for (const s of secrets) {
      try {
        const title = await aesDecrypt(masterKey, s.encryptedTitle, s.titleIv);
        results.push({ id: s.id, title, createdAt: s.createdAt, score: 0 });
      } catch {
        // Skip secrets we can't decrypt (shared but no wrappedKey)
      }
    }
    return results;
  }

  const q = query.toLowerCase().trim();
  const results: SearchResult[] = [];

  for (const s of secrets) {
    try {
      const title = await aesDecrypt(masterKey, s.encryptedTitle, s.titleIv);
      const lowerTitle = title.toLowerCase();

      let score = -1;
      if (lowerTitle === q) score = 0; // exact match
      else if (lowerTitle.startsWith(q)) score = 1; // starts with
      else if (lowerTitle.includes(q)) score = 2; // includes
      else {
        // Fuzzy: check if all query chars appear in order
        if (fuzzyMatch(lowerTitle, q)) score = 3;
      }

      if (score >= 0) {
        results.push({ id: s.id, title, createdAt: s.createdAt, score });
      }
    } catch {
      // Skip undecryptable secrets
    }
  }

  // Sort by score (best first), then alphabetically
  results.sort((a, b) => {
    if (a.score !== b.score) return a.score - b.score;
    return a.title.localeCompare(b.title);
  });

  return results;
}

/**
 * Fuzzy match: check if all characters of query appear in order in text.
 * Not a full fuzzy search, but catches typos and partial matches.
 */
function fuzzyMatch(text: string, query: string): boolean {
  let qi = 0;
  for (let ti = 0; ti < text.length && qi < query.length; ti++) {
    if (text[ti] === query[qi]) qi++;
  }
  return qi === query.length;
}

/**
 * Pre-build an in-memory search index for fast repeated queries.
 * The index stores decrypted titles; queries are instant after build.
 */
export class SearchIndex {
  private entries: Array<{ id: string; title: string; lowerTitle: string; createdAt: string }> = [];

  /**
   * Build the index by decrypting all titles.
   * Call this once after login or when secrets change.
   */
  async build(secrets: EncryptedSecretMeta[], masterKey: CryptoKey): Promise<void> {
    this.entries = [];
    for (const s of secrets) {
      try {
        const title = await aesDecrypt(masterKey, s.encryptedTitle, s.titleIv);
        this.entries.push({
          id: s.id,
          title,
          lowerTitle: title.toLowerCase(),
          createdAt: s.createdAt,
        });
      } catch {
        // Skip undecryptable
      }
    }
  }

  search(query: string): SearchResult[] {
    if (!query.trim()) {
      return this.entries.map((e) => ({ id: e.id, title: e.title, createdAt: e.createdAt, score: 0 }));
    }

    const q = query.toLowerCase().trim();
    const results: SearchResult[] = [];

    for (const e of this.entries) {
      let score = -1;
      if (e.lowerTitle === q) score = 0;
      else if (e.lowerTitle.startsWith(q)) score = 1;
      else if (e.lowerTitle.includes(q)) score = 2;
      else if (fuzzyMatch(e.lowerTitle, q)) score = 3;

      if (score >= 0) {
        results.push({ id: e.id, title: e.title, createdAt: e.createdAt, score });
      }
    }

    results.sort((a, b) => {
      if (a.score !== b.score) return a.score - b.score;
      return a.title.localeCompare(b.title);
    });

    return results;
  }

  get size(): number {
    return this.entries.length;
  }

  clear(): void {
    this.entries = [];
  }
}
