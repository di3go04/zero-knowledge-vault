import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["src/**/*.test.ts"],
    setupFiles: ["./vitest.setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/lib/crypto/**/*.ts"],
      exclude: [
        "**/*.test.ts",
        "**/*.d.ts",
        "src/lib/crypto/argon2-worker.ts", // Web Worker - exercised only at runtime
        "src/lib/crypto/pq-kem.ts",         // ML-KEM binary - tested separately
        "src/lib/crypto/index.ts",          // Pure re-exports
      ],
      thresholds: {
        statements: 60,
        branches: 80,
        functions: 80,
        lines: 60,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
