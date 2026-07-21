/**
 * Test unitario para el rate-limit por email en login.
 *
 * Verifica que tras N intentos fallidos para un email, el intento N+1
 * es bloqueado (429) incluso si viene de una IP distinta.
 *
 * No mockeamos crypto ni DB — usamos el adaptador real de rate-limit
 * con Map in-memory (sin Redis).
 */
import { describe, it, expect, beforeEach } from "vitest";
import { checkRateLimit, resetRateLimit, RATE_LIMIT_POLICIES } from "@/lib/rate-limit";

describe("Rate-limit por email en login", () => {
  const EMAIL = "attacker@example.com";
  const emailKey = `login:email:${EMAIL}`;

  beforeEach(async () => {
    // Limpiar el rate-limit antes de cada test
    await resetRateLimit(emailKey);
  });

  it("permite hasta 5 intentos para el mismo email", async () => {
    const maxAttempts = RATE_LIMIT_POLICIES.login.maxAttempts; // 5

    for (let i = 0; i < maxAttempts; i++) {
      const result = await checkRateLimit(
        emailKey,
        maxAttempts,
        RATE_LIMIT_POLICIES.login.windowMs,
      );
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(maxAttempts - i - 1);
    }
  });

  it("bloquea el intento N+1 (6º intento) para el mismo email", async () => {
    const maxAttempts = RATE_LIMIT_POLICIES.login.maxAttempts; // 5

    // Consumir los 5 intentos permitidos
    for (let i = 0; i < maxAttempts; i++) {
      await checkRateLimit(emailKey, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
    }

    // El 6º intento debe ser bloqueado
    const result = await checkRateLimit(
      emailKey,
      maxAttempts,
      RATE_LIMIT_POLICIES.login.windowMs,
    );
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("el bloqueo por email es independiente de la IP", async () => {
    const maxAttempts = RATE_LIMIT_POLICIES.login.maxAttempts;

    // Consumir los 5 intentos desde IP-A
    const ipAKey = `login:ip:192.0.2.1`;
    for (let i = 0; i < maxAttempts; i++) {
      await checkRateLimit(emailKey, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
      await checkRateLimit(ipAKey, 20, 15 * 60 * 1000);
    }

    // Intentar desde IP-B (distinta IP, mismo email)
    const ipBKey = `login:ip:192.0.2.2`;
    const ipBResult = await checkRateLimit(ipBKey, 20, 15 * 60 * 1000);
    // La IP-B no está bloqueada (20 intentos permitidos, solo usó 0)
    expect(ipBResult.allowed).toBe(true);

    // Pero el email SÍ está bloqueado, así que el login falla
    const emailResult = await checkRateLimit(
      emailKey,
      maxAttempts,
      RATE_LIMIT_POLICIES.login.windowMs,
    );
    expect(emailResult.allowed).toBe(false);
  });

  it("resetRateLimit limpia el contador tras login exitoso", async () => {
    const maxAttempts = RATE_LIMIT_POLICIES.login.maxAttempts;

    // Consumir 3 intentos
    for (let i = 0; i < 3; i++) {
      await checkRateLimit(emailKey, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
    }

    // Reset (simula login exitoso)
    await resetRateLimit(emailKey);

    // Después del reset, el contador debe estar a 0 de nuevo
    const result = await checkRateLimit(
      emailKey,
      maxAttempts,
      RATE_LIMIT_POLICIES.login.windowMs,
    );
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(maxAttempts - 1); // 4 restantes
  });

  it("emails distintos tienen contadores independientes", async () => {
    const maxAttempts = RATE_LIMIT_POLICIES.login.maxAttempts;
    const email1Key = `login:email:user1@example.com`;
    const email2Key = `login:email:user2@example.com`;

    // Consumir todos los intentos para user1
    for (let i = 0; i < maxAttempts; i++) {
      await checkRateLimit(email1Key, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
    }

    // user1 está bloqueado
    const r1 = await checkRateLimit(email1Key, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
    expect(r1.allowed).toBe(false);

    // user2 NO está bloqueado (contador independiente)
    const r2 = await checkRateLimit(email2Key, maxAttempts, RATE_LIMIT_POLICIES.login.windowMs);
    expect(r2.allowed).toBe(true);

    // Cleanup
    await resetRateLimit(email1Key);
    await resetRateLimit(email2Key);
  });
});
