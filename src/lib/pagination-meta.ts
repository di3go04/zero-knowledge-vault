/**
 * pagination-meta.ts — Metadata de paginación para respuestas.
 */
export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasMore: boolean;
  nextCursor: string | null;
}

export function buildPaginationMeta(
  itemsLength: number,
  limit: number,
  nextCursor: string | null,
  total?: number,
): PaginationMeta {
  const hasMore = itemsLength >= limit;
  return {
    page: 1, // cursor-based, no pages
    limit,
    total: total ?? itemsLength,
    totalPages: total ? Math.ceil(total / limit) : 1,
    hasMore,
    nextCursor,
  };
}
