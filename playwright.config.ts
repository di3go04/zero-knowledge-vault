import { defineConfig, devices } from "@playwright/test";

/**
 * BLOQUE 3 — Configuración Playwright para tests E2E.
 *
 * Flujo cubierto: Registro → Login → Crear Secreto → Compartir →
 * Revocar Dispositivo. Ver `e2e/full-flow.spec.ts`.
 *
 * Requisitos:
 *   - `bun run dev` ejecutándose en http://localhost:3000
 *   - `bun run db:seed` ejecutado (crea Alice y Bob de demo)
 *
 * Ejecutar:
 *   bun add -d @playwright/test
 *   bunx playwright install --with-deps chromium
 *   bun run e2e
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // los tests comparten BD — serial
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // single worker para no contaminar BD entre tests
  reporter: process.env.CI ? "github" : "html",
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: process.env.PLAYWRIGHT_NO_SERVER
    ? undefined
    : {
        command: "bun run dev",
        url: "http://localhost:3000",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
