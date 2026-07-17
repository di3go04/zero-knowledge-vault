# Bundle Analysis

## Prerequisites

```bash
bun add -d @next/bundle-analyzer
```

## Running

```bash
ANALYZE=true bun run build
```

This generates interactive treemaps in `.next/analyze/` showing the
composition of your JavaScript bundles.

## What to look for

- Large dependencies that could be lazy-loaded
- Duplicate code across chunks
- Opportunities for code splitting at route boundaries
