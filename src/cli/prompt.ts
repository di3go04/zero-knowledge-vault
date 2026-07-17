/**
 * Minimal interactive prompt for Bun CLI.
 */

export async function prompt(question: string, options?: { silent?: boolean }): Promise<string> {
  Bun.write(Bun.stdout, question);

  if (options?.silent) {
    // Read without echo (Bun.stdin mode: "pipe" with raw mode)
    Bun.stdin.setRaw?.(true);
    const chars: string[] = [];
    const decoder = new TextDecoder();

    while (true) {
      const chunk = await readNext(Bun.stdin);
      if (!chunk) break;
      const char = decoder.decode(chunk);
      if (char === "\r" || char === "\n") {
        break;
      }
      if (char === "\u0003") {
        process.exit(130);
      }
      chars.push(char);
    }
    Bun.stdin.setRaw?.(false);
    Bun.write(Bun.stdout, "\n");
    return chars.join("");
  }

  const input = await readLine(Bun.stdin);
  return input.trim();
}

async function readNext(stream: typeof Bun.stdin): Promise<Uint8Array | null> {
  const reader = stream.getReader();
  const result = await reader.read();
  reader.releaseLock();
  return result.done ? null : result.value;
}

async function readLine(stream: typeof Bun.stdin): Promise<string> {
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const chunk = await readNext(stream);
    if (!chunk) break;
    buffer += decoder.decode(chunk, { stream: true });
    if (buffer.includes("\n")) break;
  }

  return buffer;
}

/**
 * Reads all available stdin (for multi-line content input).
 */
export async function readStdin(): Promise<string> {
  const decoder = new TextDecoder();
  let buffer = "";
  const reader = Bun.stdin.getReader();

  while (true) {
    const result = await reader.read();
    if (result.done) break;
    buffer += decoder.decode(result.value, { stream: true });
  }

  reader.releaseLock();
  return buffer;
}
