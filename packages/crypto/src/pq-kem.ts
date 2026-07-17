import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const ML_KEM_CIPHERTEXT_LEN = 1088;
const AES_KEY_LEN = 32;
const GCM_IV_LEN = 12;
const GCM_TAG_LEN = 16;

export class MLKEM768KEM {
  generateKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const { secretKey, publicKey } = ml_kem768.keygen();
    return { publicKey, privateKey: secretKey };
  }

  encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    return { ciphertext: cipherText, sharedSecret };
  }

  decapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(privateKey, ciphertext);
  }

  async sharedSecretToAesKey(sharedSecret: Uint8Array): Promise<CryptoKey> {
    const hash = await crypto.subtle.digest("SHA-256", sharedSecret as BufferSource);
    return crypto.subtle.importKey("raw", hash, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  /**
   * Hybrid KEM wrap: ML-KEM encapsulate + AES-GCM encrypt the raw AES key.
   * Output: base64( kemCiphertext[1088] | iv[12] | aesCiphertext[32+16] )
   * Total: 1148 bytes → base64 ≈ 1531 chars
   */
  async wrapAesKey(rawAesKey: Uint8Array, recipientMlKemPublicKey: Uint8Array): Promise<string> {
    const { ciphertext: kemCt, sharedSecret } = this.encapsulate(recipientMlKemPublicKey);
    const aesKey = await this.sharedSecretToAesKey(sharedSecret);
    const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LEN));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      aesKey,
      rawAesKey as BufferSource,
    );
    const combined = new Uint8Array(kemCt.length + iv.length + encrypted.byteLength);
    combined.set(kemCt, 0);
    combined.set(iv, kemCt.length);
    combined.set(new Uint8Array(encrypted), kemCt.length + iv.length);
    return btoa(String.fromCharCode(...combined));
  }

  /**
   * Hybrid KEM unwrap: split → ML-KEM decapsulate → AES-GCM decrypt.
   */
  async unwrapAesKey(wrappedKeyB64: string, recipientMlKemPrivateKey: Uint8Array): Promise<Uint8Array> {
    const combined = Uint8Array.from(atob(wrappedKeyB64), (c) => c.charCodeAt(0));
    const kemCt = combined.slice(0, ML_KEM_CIPHERTEXT_LEN);
    const iv = combined.slice(ML_KEM_CIPHERTEXT_LEN, ML_KEM_CIPHERTEXT_LEN + GCM_IV_LEN);
    const aesCt = combined.slice(ML_KEM_CIPHERTEXT_LEN + GCM_IV_LEN);

    const sharedSecret = this.decapsulate(recipientMlKemPrivateKey, kemCt);
    const aesKey = await this.sharedSecretToAesKey(sharedSecret);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      aesKey,
      aesCt as BufferSource,
    );
    return new Uint8Array(decrypted);
  }
}

export function getActiveKEM(): MLKEM768KEM {
  return new MLKEM768KEM();
}

export function isKemWrappedKey(wrappedKeyB64: string): boolean {
  try {
    const decoded = Uint8Array.from(atob(wrappedKeyB64), (c) => c.charCodeAt(0));
    return decoded.length >= ML_KEM_CIPHERTEXT_LEN;
  } catch {
    return false;
  }
}

export { ML_KEM_CIPHERTEXT_LEN };
