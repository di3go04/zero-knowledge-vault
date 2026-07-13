/**
 * batch-decrypt.ts — Descifrar múltiples secretos en paralelo.
 *
 */
import { decryptSecret } from "./crypto-client";

export async function batchDecryptSecrets(
  secrets: Array<{
    wrappedKey: string;
    encryptedTitle: string;
    titleIv: string;
    encryptedData: string;
    dataIv: string;
  }>,
  privateKey: CryptoKey,
  concurrency: number = 5,
): Promise<Array<{ title: string; content: string } | { error: string }>> {
  const results: Array<{ title: string; content: string } | { error: string }> = [];
  
  // Procesar en lotes de N para no saturar la CPU
  for (let i = 0; i < secrets.length; i += concurrency) {
    const batch = secrets.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (s) => {
        try {
          const { title, content } = await decryptSecret(
            s.wrappedKey,
            s.encryptedTitle,
            s.titleIv,
            s.encryptedData,
            s.dataIv,
            privateKey,
          );
          return { title, content };
        } catch (err: any) {
          return { error: err?.message ?? "Error de descifrado" };
        }
      }),
    );
    results.push(...batchResults);
  }

  return results;
}
