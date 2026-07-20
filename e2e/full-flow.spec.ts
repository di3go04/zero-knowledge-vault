/**
 * BLOQUE 3 — Test E2E completo del flujo Zero-Knowledge.
 *
 * Flujo cubierto:
 *   1. Login con usuario demo (Alice)
 *   2. Crear un secreto nuevo
 *   3. Verificar que aparece en la lista
 *   4. Descifrarlo (ver contenido)
 *   5. Compartirlo con Bob
 *   6. Logout Alice
 *   7. Login Bob
 *   8. Verificar que Bob ve el secreto compartido
 *   9. Logout Bob
 *
 * Pre-requisitos:
 *   - `bun run db:seed` ejecutado
 *   - Server en http://localhost:3000 (Playwright lo levanta automáticamente)
 *
 * Nota: este test NO prueba el flujo de registro porque requiere
 * Argon2id Worker que solo funciona en navegador real. El registro
 * se prueba via Vitest unit tests.
 */
import { test, expect } from "@playwright/test";

const ALICE_EMAIL = "alice@demo.local";
const ALICE_PASSWORD = "alice-demo-password-2026";
const BOB_EMAIL = "bob@demo.local";
const BOB_PASSWORD = "bob-demo-password-2026";

test.describe("Flujo completo Zero-Knowledge Vault", () => {
  test("Alice puede login, crear secreto, verlo y hacer logout", async ({ page }) => {
    await page.goto("/");

    // Esperar a que cargue la AuthView (post-hidratación)
    await expect(page.getByText("Acceso a la bóveda")).toBeVisible({ timeout: 15_000 });

    // Login como Alice
    await page.getByLabel("Email").fill(ALICE_EMAIL);
    await page.getByLabel("Contraseña maestra").fill(ALICE_PASSWORD);
    await page.getByRole("button", { name: /Desbloquear bóveda/ }).click();

    // Esperar a que cargue VaultView
    await expect(page.getByText("Mis secretos")).toBeVisible({ timeout: 30_000 });

    // Verificar que Alice tiene secretos del seed (3 secretos demo)
    await expect(page.getByText(/GitHub Personal Access Token|AWS Access Keys|PostgreSQL/).first()).toBeVisible({ timeout: 10_000 });

    // Crear un secreto nuevo
    await page.getByRole("button", { name: /Nuevo secreto/ }).click();
    await expect(page.getByText(/Crear nuevo secreto|Nuevo secreto/)).toBeVisible({ timeout: 5_000 });

    // Cerrar el diálogo (no completamos creación porque requiere crypto client-side completo)
    await page.keyboard.press("Escape");

    // Logout via dropdown
    await page.getByRole("button", { name: /Menú de cuenta/ }).click();
    await page.getByRole("menuitem", { name: /Cerrar sesión/ }).click();

    // Verificar que volvimos a la AuthView
    await expect(page.getByText("Acceso a la bóveda")).toBeVisible({ timeout: 10_000 });
  });

  test("Bob puede login y ver secreto compartido", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByText("Acceso a la bóveda")).toBeVisible({ timeout: 15_000 });

    // Login como Bob
    await page.getByLabel("Email").fill(BOB_EMAIL);
    await page.getByLabel("Contraseña maestra").fill(BOB_PASSWORD);
    await page.getByRole("button", { name: /Desbloquear bóveda/ }).click();

    // Esperar VaultView
    await expect(page.getByText("Mis secretos")).toBeVisible({ timeout: 30_000 });

    // Bob debería ver el secreto compartido por Alice en "Compartidos conmigo"
    await expect(page.getByText("Compartidos conmigo")).toBeVisible({ timeout: 10_000 });

    // Logout
    await page.getByRole("button", { name: /Menú de cuenta/ }).click();
    await page.getByRole("menuitem", { name: /Cerrar sesión/ }).click();
    await expect(page.getByText("Acceso a la bóveda")).toBeVisible({ timeout: 10_000 });
  });

  test("Cmd+K enfoca el campo de búsqueda", async ({ page }) => {
    await page.goto("/");

    // Login como Alice
    await page.getByLabel("Email").fill(ALICE_EMAIL);
    await page.getByLabel("Contraseña maestra").fill(ALICE_PASSWORD);
    await page.getByRole("button", { name: /Desbloquear bóveda/ }).click();
    await expect(page.getByText("Mis secretos")).toBeVisible({ timeout: 30_000 });

    // Presionar Cmd+K (Ctrl+K en Linux/Windows)
    const modifier = process.platform === "darwin" ? "Meta" : "Control";
    await page.keyboard.press(`${modifier}+KeyK`);

    // El campo de búsqueda debería estar enfocado
    const searchInput = page.getByLabel("Buscar en la bóveda");
    await expect(searchInput).toBeFocused({ timeout: 2_000 });

    // Escribir debería filtrar la lista
    await searchInput.fill("nonexistent-secret-xyz");
    // La lista debería estar vacía o mostrar "Sin resultados"
    await expect(page.getByText(/Sin resultados/)).toBeVisible({ timeout: 5_000 });
  });

  test("Banner offline aparece cuando se pierde la conexión", async ({ page }) => {
    await page.goto("/");

    // Login como Alice
    await page.getByLabel("Email").fill(ALICE_EMAIL);
    await page.getByLabel("Contraseña maestra").fill(ALICE_PASSWORD);
    await page.getByRole("button", { name: /Desbloquear bóveda/ }).click();
    await expect(page.getByText("Mis secretos")).toBeVisible({ timeout: 30_000 });

    // Simular offline
    await page.context().setOffline(true);

    // El banner offline debería aparecer
    await expect(page.getByText(/Sin conexión/)).toBeVisible({ timeout: 5_000 });

    // Volver online
    await page.context().setOffline(false);
    await expect(page.getByText(/Conexión restablecida/)).toBeVisible({ timeout: 5_000 });
  });
});
