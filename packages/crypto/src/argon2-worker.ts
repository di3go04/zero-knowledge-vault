/**
 * Web Worker that runs Argon2id using hash-wasm.
 *
 * The main thread posts a message with { id, password, salt, iterations,
 * memoryKiB, parallelism } and this worker responds with { id, hash }.
 *
 * If hash-wasm fails to load or Argon2id fails for any reason, the worker
 * posts back an error so the main thread can fall back to PBKDF2.
 */
import { argon2id } from "hash-wasm";

export interface Argon2Request {
  id: number;
  password: string;
  salt: Uint8Array;
  iterations: number;
  memoryKiB: number;
  parallelism: number;
}

export interface Argon2Response {
  id: number;
  hash?: Uint8Array;
  error?: string;
}

async function run(): Promise<void> {
  self.onmessage = (ev: MessageEvent<Argon2Request>) => {
    const { id, password, salt, iterations, memoryKiB, parallelism } = ev.data;
    try {
      const hash = argon2id({
        password,
        salt,
        iterations,
        memorySize: memoryKiB,
        parallelism,
        hashLength: 32,
        outputType: "binary",
      });
      const response: Argon2Response = { id, hash: hash as unknown as Uint8Array };
      (self as unknown as Worker).postMessage(response);
    } catch (e) {
      const response: Argon2Response = {
        id,
        error: e instanceof Error ? e.message : "argon2 failed",
      };
      (self as unknown as Worker).postMessage(response);
    }
  };
}

run();
