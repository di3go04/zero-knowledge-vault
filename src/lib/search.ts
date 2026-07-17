/**
 * search.ts — Full-text search across encrypted titles (client-side).
 *
 * Since titles are encrypted with AES-256-GCM, we cannot use SQL LIKE
 * or database full-text search. Instead, we maintain an in-memory index
 * of encrypted titles and search client-side.
 *
 * Approach:
 *   1. On decrypt, extract keywords from the plaintext title
 *   2. Store a search-index blob alongside each secret (word → normalized tokens)
 *   3. Client-side search iterates over the loaded secret list, filtering
 *      by matching the query against each secret's stored index
 *
 * This is NOT a security leak: the search index is encrypted with the same
 * AES key as the title. The server never sees plaintext.
 */

export interface SearchIndex {
  /** Normalized lowercased tokens from the plaintext title */
  tokens: string[];
  /** The original title (plaintext, only in memory) */
  title?: string;
}

/**
 * Builds a search index from a plaintext title.
 * Tokens are: lowercased, split on non-alphanumeric, stem-free (full words).
 */
export function buildSearchIndex(title: string): SearchIndex {
  const normalized = title
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // Remove diacritics
    .replace(/[^a-z0-9\s]/g, " ")
    .trim();

  const tokens = [...new Set(normalized.split(/\s+/).filter(Boolean))];

  // Add substring tokens for prefix matching
  const subTokens = new Set<string>();
  for (const token of tokens) {
    for (let i = 1; i <= token.length; i++) {
      subTokens.add(token.slice(0, i));
    }
  }

  return { tokens: [...new Set([...tokens, ...subTokens])], title };
}

/**
 * Scores a document against a search query.
 * Returns a number between 0 (no match) and 1 (exact match).
 */
export function scoreDocument(query: string, index: SearchIndex): number {
  const queryTokens = query
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9\s]/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (queryTokens.length === 0) return 0;

  let matches = 0;
  for (const qToken of queryTokens) {
    if (index.tokens.includes(qToken)) {
      matches++;
    }
  }

  return matches / queryTokens.length;
}

/**
 * Searches across multiple search indexes.
 * Returns results sorted by relevance score (descending).
 */
export function searchIndexes(
  query: string,
  indexes: Array<{ id: string; index: SearchIndex }>,
  threshold = 0.3,
): Array<{ id: string; score: number }> {
  if (!query.trim()) return [];

  const results: Array<{ id: string; score: number }> = [];

  for (const entry of indexes) {
    const score = scoreDocument(query, entry.index);
    if (score >= threshold) {
      results.push({ id: entry.id, score });
    }
  }

  return results.sort((a, b) => b.score - a.score);
}

/**
 * Checks if a single title matches a search query (boolean).
 * Useful for filtering in React components without needing stored indexes.
 */
export function titleMatches(title: string, query: string): boolean {
  const index = buildSearchIndex(title);
  return scoreDocument(query, index) >= 0.3;
}
