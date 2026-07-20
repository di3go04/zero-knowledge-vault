import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  reactStrictMode: false,
  // Use webpack instead of Turbopack for `next build` to avoid
  // native ESM module resolution issues with lightningcss.
  // (Turbopack is still used by `next dev`.)
  // --- BLOQUE 2: Security headers nativos via Next.js ---
  // Estos headers se inyectan a nivel de servidor HTTP, no dependen
  // de meta tags. Son la fuente de verdad — el meta tag CSP en
  // layout.tsx es solo refuerzo.
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob:",
              "font-src 'self' data:",
              "connect-src 'self' https://api.github.com",
              "frame-ancestors 'none'",
              "form-action 'self'",
              "base-uri 'self'",
              "object-src 'none'",
              "manifest-src 'self'",
              "worker-src 'self' blob:",
            ].join("; "),
          },
          {
            key: "Cross-Origin-Opener-Policy",
            value: "same-origin",
          },
          {
            key: "Cross-Origin-Embedder-Policy",
            value: "require-corp",
          },
          {
            key: "Cross-Origin-Resource-Policy",
            value: "same-origin",
          },
        ],
      },
      {
        // Los Web Workers de Argon2 necesitan blob: worker-src
        source: "/_next/static/chunks/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: "worker-src 'self' blob:;" },
        ],
      },
    ];
  },
};

export default nextConfig;
