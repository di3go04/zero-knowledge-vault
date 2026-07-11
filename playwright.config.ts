/**
 * playwright.config.ts — Configuración de Playwright para tests E2E.
 *
 * Instalación:
 *   npm install -D @playwright/test
 *   npx playwright install
 *
 * Ejecución:
 *   npx playwright test
 *   npx playwright test scripts/e2e-multi-device.spec.ts
 *   npx playwright test --headed  # ver navegador
 *   npx playwright test --ui      # modo interactivo
 */
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./scripts",
  fullyParallel: false, // Los tests E2E comparten estado — no paralelizar
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Un solo worker para evitar conflictos de BD
  reporter: "html",
  timeout: 60_000, // 60s por test (Argon2id puede tardar)
  expect: {
    timeout: 15_000,
  },
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
  // No iniciar servidor automáticamente — el dev server debe estar corriendo
  // webServer: {
  //   command: "bun run dev",
  //   url: "http://localhost:3000",
  //   reuseExistingServer: true,
  //   timeout: 60_000,
  // },
});
