/**
 * BLOQUE 3 — Tests del Argon2id Web Worker simulando entorno de navegador.
 *
 * Estos tests validan que el worker de Argon2id funciona correctamente
 * cuando se le pasan entradas válidas e inválidas. Como vitest corre en
 * Node.js (no en navegador), usamos `hash-wasm` directamente para
 * validar la lógica que el worker ejecutaría.
 *
 * Para una prueba real en navegador headless, ver `e2e/argon2-worker.spec.ts`
 * que usa Playwright + Chromium real.
 */
import { describe, it, expect } from "vitest";
import { argon2id } from "hash-wasm";

const ARGON2_MEMORY_KIB = 65_536; // 64 MiB
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 4;

describe("Argon2id Worker — lógica de derivación", () => {
  it("produce un hash de 32 bytes (256 bits) para entradas válidas", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const hash = await argon2id({
      password: "test-password-123",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it("es determinista para los mismos parámetros", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const hash1 = await argon2id({
      password: "deterministic-test",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    const hash2 = await argon2id({
      password: "deterministic-test",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(Array.from(hash1)).toEqual(Array.from(hash2));
  });

  it("produce hashes distintos para contraseñas distintas", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const hash1 = await argon2id({
      password: "password-A",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    const hash2 = await argon2id({
      password: "password-B",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(Array.from(hash1)).not.toEqual(Array.from(hash2));
  });

  it("produce hashes distintos para salts distintos", async () => {
    const salt1 = new Uint8Array(16);
    const salt2 = new Uint8Array(16);
    crypto.getRandomValues(salt1);
    crypto.getRandomValues(salt2);

    const hash1 = await argon2id({
      password: "same-password",
      salt: salt1,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    const hash2 = await argon2id({
      password: "same-password",
      salt: salt2,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(Array.from(hash1)).not.toEqual(Array.from(hash2));
  });

  it("maneja entradas con caracteres unicode correctamente", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const hash = await argon2id({
      password: "contraseña-üñîçødé-日本語",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(hash.length).toBe(32);
    // No debe ser todo ceros
    const allZero = hash.every((b: number) => b === 0);
    expect(allZero).toBe(false);
  });

  it("maneja entrada muy corta (1 char) sin lanzar excepción", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    // hash-wasm requiere password no vacío. En la práctica, el formulario
    // de AuthView valida que la contraseña tenga mínimo 10 caracteres,
    // así que nunca llegamos a Argon2id con "".
    const hash = await argon2id({
      password: "x",
      salt,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      outputType: "binary",
    });

    expect(hash.length).toBe(32);
  });

  it("respeta el parámetro hashLength", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    for (const len of [16, 24, 32, 48, 64]) {
      const hash = await argon2id({
        password: "length-test",
        salt,
        iterations: ARGON2_ITERATIONS,
        memorySize: ARGON2_MEMORY_KIB,
        parallelism: ARGON2_PARALLELISM,
        hashLength: len,
        outputType: "binary",
      });
      expect(hash.length).toBe(len);
    }
  });

  it("lanza error si salt es muy corto (< 8 bytes)", async () => {
    const tinySalt = new Uint8Array(4);
    crypto.getRandomValues(tinySalt);

    await expect(
      argon2id({
        password: "test",
        salt: tinySalt,
        iterations: ARGON2_ITERATIONS,
        memorySize: ARGON2_MEMORY_KIB,
        parallelism: ARGON2_PARALLELISM,
        hashLength: 32,
        outputType: "binary",
      }),
    ).rejects.toThrow();
  });

  it("lanza error si memorySize es muy bajo", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    await expect(
      argon2id({
        password: "test",
        salt,
        iterations: ARGON2_ITERATIONS,
        memorySize: 8, // demasiado bajo, Argon2 requiere ≥ 8*p
        parallelism: ARGON2_PARALLELISM,
        hashLength: 32,
        outputType: "binary",
      }),
    ).rejects.toThrow();
  });

  it("lanza error si iterations es 0", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    await expect(
      argon2id({
        password: "test",
        salt,
        iterations: 0,
        memorySize: ARGON2_MEMORY_KIB,
        parallelism: ARGON2_PARALLELISM,
        hashLength: 32,
        outputType: "binary",
      }),
    ).rejects.toThrow();
  });
});
