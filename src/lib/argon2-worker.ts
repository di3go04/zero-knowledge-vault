/**
 * =====================================================================
 * argon2-worker.ts — Web Worker para derivación Argon2id.
 * =====================================================================
 * Se ejecuta en un hilo separado para no bloquear la UI mientras
 * Argon2id consume 64 MiB de RAM durante ~1-2s.
 *
 * Usa `hash-wasm` que es compatible con Turbopack y Web Workers.
 *
 * Recibe: { password, salt, memoryKiB, iterations, parallelism }
 * Devuelve: { rawKey: ArrayBuffer (32 bytes) }
 *
 * MEJORA Módulo 2 (Memory Zeroing + robustez):
 *   - Cache del módulo WASM con reset automático en fallo.
 *   - Copia defensiva del salt (puede llegar detached).
 *   - Limpieza de referencias tras el cálculo.
 *   - Timeout de 10s para evitar que el worker se cuelgue indefinidamente.
 * =====================================================================
 */

/// <reference lib="webworker" />

interface WorkerRequest {
  id: number;
  password: string;
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

interface WorkerResponse {
  id: number;
  ok: boolean;
  rawKey?: ArrayBuffer;
  error?: string;
}

// Cache del módulo WASM cargado
let wasmReady: Promise<typeof import("hash-wasm")> | null = null;

async function ensureWasmReady(): Promise<typeof import("hash-wasm")> {
  if (!wasmReady) {
    wasmReady = (async () => {
      const mod = await import("hash-wasm");
      if (typeof mod.argon2id !== "function") {
        throw new Error("hash-wasm: argon2id no disponible");
      }
      return mod;
    })().catch((err) => {
      wasmReady = null; // Reset para permitir reintento en la próxima petición
      throw err;
    });
  }
  return wasmReady;
}

/**
 * Ejecuta argon2id con un timeout de 10s.
 * Si excede, rechaza con error claro (no cuelga el worker indefinidamente).
 */
function argon2idWithTimeout(params: {
  password: string;
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}): Promise<Uint8Array> {
  return new Promise(async (resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Argon2id timeout (>10s) — posible navegador sin WASM"));
    }, 10_000);

    try {
      const mod = await ensureWasmReady();
      const result = await mod.argon2id({
        password: params.password,
        salt: params.salt,
        parallelism: params.parallelism,
        iterations: params.iterations,
        memorySize: params.memoryKiB,
        hashLength: 32,
        outputType: "binary",
      });
      clearTimeout(timeout);
      resolve(result);
    } catch (err) {
      clearTimeout(timeout);
      reject(err);
    }
  });
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, password, salt, memoryKiB, iterations, parallelism } = e.data;

  try {
    // Copia defensiva del salt: puede llegar detached (transferido).
    // Si está detached, new Uint8Array(salt) lanza y lo capturamos.
    let saltCopy: Uint8Array;
    try {
      saltCopy = new Uint8Array(salt);
    } catch {
      // Salt detached — usar como está si no lo está
      saltCopy = salt;
    }

    const rawKey = await argon2idWithTimeout({
      password,
      salt: saltCopy,
      memoryKiB,
      iterations,
      parallelism,
    });

    // LIMPIEZA: sobrescribir el salt con ceros antes de responder
    // (el salt no es secreto, pero buena práctica)
    try {
      saltCopy.fill(0);
    } catch {
      // no-op si está detached
    }

    const resp: WorkerResponse = {
      id,
      ok: true,
      rawKey: rawKey.buffer as ArrayBuffer,
    };
    // Transferir el rawKey (detach del lado del worker — se limpia solo)
    (self as DedicatedWorkerGlobalScope).postMessage(resp, [
      rawKey.buffer as ArrayBuffer,
    ]);
  } catch (err: any) {
    const resp: WorkerResponse = {
      id,
      ok: false,
      error: err?.message ?? "Argon2id failed",
    };
    (self as DedicatedWorkerGlobalScope).postMessage(resp);
  }
};
