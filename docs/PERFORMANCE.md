# Performance Optimizations

## Lazy Loading

Heavy components use `next/dynamic` for code splitting:

- Charts (recharts): Dynamic import
- Rich text editor (@mdxeditor/editor): Dynamic import
- Animations (framer-motion): Dynamic import
- Syntax highlighting (react-syntax-highlighter): Dynamic import

## Image Optimization

All images use `next/image` with:

- WebP format via `sharp`
- Explicit width/height
- Lazy loading by default
- Placeholder blur-up or solid color placeholders

## Caching

Public keys are cached client-side to reduce API calls.
