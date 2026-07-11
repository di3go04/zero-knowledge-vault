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
 * MEJORA Fase 3: manejo robusto de errores y reinicialización del
 * módulo WASM. Si el módulo falla al cargar, el worker se auto-reinicia
 * en la siguiente petición.
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
let wasmReady: Promise<void> | null = null;

async function ensureWasmReady(): Promise<void> {
  if (!wasmReady) {
    wasmReady = (async () => {
      // hash-wasm carga el WASM internamente en la primera llamada
      // No necesitamos init explícito, pero hacemos una llamada de prueba
      const { argon2id } = await import("hash-wasm");
      // Verificar que la función existe
      if (typeof argon2id !== "function") {
        throw new Error("hash-wasm: argon2id no disponible");
      }
    })().catch((err) => {
      wasmReady = null; // Reset para permitir reintento
      throw err;
    });
  }
  return wasmReady;
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, password, salt, memoryKiB, iterations, parallelism } = e.data;
  try {
    await ensureWasmReady();
    const { argon2id } = await import("hash-wasm");

    const rawKey = await argon2id({
      password,
      // Copiar el salt porque puede ser transferido (detached)
      salt: new Uint8Array(salt),
      parallelism,
      iterations,
      memorySize: memoryKiB,
      hashLength: 32,
      outputType: "binary",
    });

    const resp: WorkerResponse = {
      id,
      ok: true,
      rawKey: rawKey.buffer as ArrayBuffer,
    };
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
