import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: true,
  // Use webpack instead of Turbopack for `next build` to avoid
  // native ESM module resolution issues with lightningcss.
  // (Turbopack is still used by `next dev`.)
   // --- BLOQUE 2: Security headers via Next.js ---
   // Los headers HTTP complementan al middleware. CSP se maneja
   // exclusivamente en middleware.ts para soporte de nonces dinámicos.
   async headers() {
     return [
       {
         source: "/(.*)",
         headers: [
           {
             key: "Strict-Transport-Security",
             value: "max-age=63072000; includeSubDomains; preload",
           },
         ],
       },
     ];
   },
};

export default nextConfig;
