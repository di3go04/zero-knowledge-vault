/**
 * =====================================================================
 * argon2-worker.ts — Web Worker para derivación Argon2id.
 * =====================================================================
 * Se ejecuta en un hilo separado para no bloquear la UI mientras
 * Argon2id consume 64 MiB de RAM durante ~1-2s.
 *
 * Usa `hash-wasm` (compatiblad con Turbopack/Web Workers) en lugar de
 * `argon2-browser` (que tiene problemas con Turbopack).
 *
 * Recibe: { password, salt, memoryKiB, iterations, parallelism }
 * Devuelve: { rawKey: ArrayBuffer (32 bytes) }
 * =====================================================================
 */

/// <reference lib="webworker" />

import { argon2id } from "hash-wasm";

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

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, password, salt, memoryKiB, iterations, parallelism } = e.data;
  try {
    const rawKey = await argon2id({
      password,
      salt,
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
