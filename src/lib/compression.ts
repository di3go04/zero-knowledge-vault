/**
 * compression.ts — Compresión zlib antes de cifrar para secretos >1KB.
 *
 *
 * Flujo:
 *   1. Si el plaintext > 1KB, comprimir con gzip
 *   2. Cifrar el compressed data con AES-256-GCM
 *   3. Añadir flag "compressed" en el primer byte del ciphertext
 *
 * Al descifrar:
 *   1. Descifrar con AES-256-GCM
 *   2. Si flag "compressed", descomprimir con DecompressionStream
 */

const COMPRESSION_THRESHOLD = 1024; // 1KB

export async function compressIfLarge(plaintext: string): Promise<{
  data: Uint8Array;
  compressed: boolean;
}> {
  const encoded = new TextEncoder().encode(plaintext) as unknown as Uint8Array;
  if (encoded.length < COMPRESSION_THRESHOLD) {
    return { data: encoded, compressed: false };
  }

  // Usar CompressionStream (gzip) — disponible en navegadores modernos
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(encoded as unknown as BufferSource);
  writer.close();

  const chunks: Uint8Array[] = [];
  const reader = cs.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const compressed = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
  let offset = 0;
  for (const c of chunks) {
    compressed.set(c, offset);
    offset += c.length;
  }

  return { data: compressed, compressed: true };
}

export async function decompressIfNeeded(data: Uint8Array, compressed: boolean): Promise<string> {
  if (!compressed) {
    return new TextDecoder().decode(data);
  }

  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(data as unknown as BufferSource);
  writer.close();

  const chunks: Uint8Array[] = [];
  const reader = ds.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const decompressed = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
  let offset = 0;
  for (const c of chunks) {
    decompressed.set(c, offset);
    offset += c.length;
  }

  return new TextDecoder().decode(decompressed);
}
