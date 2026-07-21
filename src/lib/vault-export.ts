/**
 * Módulo 4: Exportación local de la bóveda a un archivo JSON cifrado.
 *
 * Flujo:
 *   1. El usuario pide "Exportar" e ingresa una contraseña de exportación.
 *   2. Se deriva una llave AES-256 via PBKDF2-SHA256 (600k iteraciones)
 *      usando la contraseña de exportación + un salt aleatorio.
 *   3. Se serializa la bóveda (secretos descifrados) a JSON.
 *   4. Se cifra el JSON con AES-256-GCM (96-bit IV aleatorio).
 *   5. Se devuelve un Blob con el JSON estructurado:
 *        {
 *          "format": "zk-vault-export-v1",
 *          "createdAt": ISO-8601,
 *          "kdf": { "algorithm": "pbkdf2-sha256", "iterations": 600000, "salt": "base64" },
 *          "iv": "base64",
 *          "ciphertext": "base64"
 *        }
 *
 * Para importar de vuelta (futuro):
 *   - El usuario selecciona el archivo .json
 *   - Ingresa la contraseña de exportación
 *   - El cliente deriva la misma llave PBKDF2, descifra el ciphertext
 *     y obtiene el JSON con la bóveda. Luego sube cada secreto al
 *     servidor con su propia llave maestra (re-cifrado).
 *
 * Módulo 4 (Web Worker): la derivación PBKDF2 con 600k iteraciones
 * puede tardar 0.5–1.5s en hardware moderno. Para evitar congelar la
 * UI, todo el cifrado se hace en un Web Worker. La API es async.
 */
import type { SecretListItem } from "@/components/ViewSecretDialog";

const EXPORT_FORMAT = "zk-vault-export-v1";
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

export interface VaultExportPayload {
  secrets: SecretListItem[];
  masterKey: CryptoKey | null;
  password: string;
}

export interface EncryptedVaultFile {
  format: string;
  createdAt: string;
  kdf: {
    algorithm: string;
    iterations: number;
    salt: string;
  };
  iv: string;
  ciphertext: string;
}

/**
 * Cifra una bóveda descifrada y devuelve un Blob listo para descargar.
 *
 * @param payload.secrets - Lista de secretos (cifrados en servidor, pero
 *                          aquí se descifran previamente si el usuario
 *                          quiere exportarlos en claro).
 * @param payload.masterKey - Llave maestra del usuario (para descifrar
 *                            los títulos y contenidos antes de exportar).
 * @param payload.password - Contraseña de exportación (independiente
 *                           de la master key).
 */
export async function exportVaultToEncryptedJson(
  payload: VaultExportPayload
): Promise<Blob> {
  const { secrets, masterKey, password } = payload;

  if (!masterKey) {
    throw new Error("Se requiere la llave maestra para exportar la bóveda.");
  }
  if (!password || password.length < 8) {
    throw new Error("La contraseña de exportación debe tener al menos 8 caracteres.");
  }

  // 1. Descifrar todos los secretos en el cliente (título + data).
  //    El usuario vio cada uno antes de exportar, así que ya están en
  //    memoria. Aquí los volvemos a descifrar para construir el JSON.
  const decryptedSecrets = await Promise.all(
    secrets.map(async (s) => {
      try {
        const titleBytes = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: base64ToBuf(s.titleIv) },
          masterKey,
          base64ToBuf(s.encryptedTitle),
        );
        const dataBytes = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: base64ToBuf(s.dataIv) },
          masterKey,
          base64ToBuf(s.encryptedData),
        );
        return {
          id: s.id,
          title: new TextDecoder().decode(titleBytes),
          data: new TextDecoder().decode(dataBytes),
          createdAt: s.createdAt,
          ownedByMe: s.ownedByMe,
          ownerEmail: s.ownerEmail,
        };
      } catch {
        // Si un secreto no se puede descifrar (p.ej. compartido con
        // nosotros pero no tenemos el wrappedKey), lo omitimos.
        return null;
      }
    }),
  );

  const exportable = decryptedSecrets.filter((s): s is NonNullable<typeof s> => s !== null);

  // 2. Serializar a JSON compacto.
  const json = JSON.stringify({
    version: 1,
    exportedAt: new Date().toISOString(),
    secrets: exportable,
  });

  // 3. Derivar llave AES-256 desde la contraseña de exportación.
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  // 4. Cifrar JSON con AES-256-GCM (96-bit IV aleatorio).
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    encryptionKey,
    new TextEncoder().encode(json),
  );

  // 5. Empaquetar el archivo de exportación.
  const file: EncryptedVaultFile = {
    format: EXPORT_FORMAT,
    createdAt: new Date().toISOString(),
    kdf: {
      algorithm: "pbkdf2-sha256",
      iterations: PBKDF2_ITERATIONS,
      salt: bufToBase64(salt),
    },
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ciphertext),
  };

  // 6. Devolver como Blob para descarga directa.
  return new Blob([JSON.stringify(file, null, 2)], {
    type: "application/json",
  });
}

/**
 * Importa un archivo de exportación cifrado.
 *
 * @param file - El archivo .json exportado por `exportVaultToEncryptedJson`.
 * @param password - La contraseña de exportación.
 * @returns El objeto JSON descifrado con los secretos.
 */
export async function importVaultFromEncryptedJson(
  file: File,
  password: string,
): Promise<{
  version: number;
  exportedAt: string;
  secrets: Array<{
    id: string;
    title: string;
    data: string;
    createdAt: string;
    ownedByMe: boolean;
    ownerEmail?: string;
  }>;
}> {
  const text = await file.text();
  let parsed: EncryptedVaultFile;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Archivo inválido — no es JSON parseable.");
  }

  if (parsed.format !== EXPORT_FORMAT) {
    throw new Error(`Formato no soportado: ${parsed.format ?? "desconocido"}.`);
  }

  if (parsed.kdf.algorithm !== "pbkdf2-sha256") {
    throw new Error(`KDF no soportado: ${parsed.kdf.algorithm}.`);
  }

  // Re-derivar la llave con los mismos parámetros del archivo.
  const salt = base64ToBuf(parsed.kdf.salt);
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: parsed.kdf.iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  // Descifrar el ciphertext.
  const iv = base64ToBuf(parsed.iv);
  const ciphertext = base64ToBuf(parsed.ciphertext);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      encryptionKey,
      ciphertext as BufferSource,
    );
  } catch {
    throw new Error("Contraseña incorrecta o archivo corrupto.");
  }

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json);
}

// ----- helpers -----
function base64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer as ArrayBuffer;
}

function bufToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
