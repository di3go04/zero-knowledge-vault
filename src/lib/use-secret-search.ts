"use client";

import { useState, useMemo } from "react";

/**
 * Hook de búsqueda local de secretos por título descifrado.
 *
 */
export function useSecretSearch<T extends { id: string }>(
  secrets: T[],
  searchTextFn: (s: T) => string,
) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return secrets;
    const q = query.toLowerCase();
    return secrets.filter((s) => searchTextFn(s).toLowerCase().includes(q));
  }, [secrets, query, searchTextFn]);

  return { query, setQuery, filtered };
}
