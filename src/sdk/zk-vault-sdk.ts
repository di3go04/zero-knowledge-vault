/**
 * =====================================================================
 * zk-vault-sdk.ts — SDK TypeScript real para integrar con otras apps.
 *
 *
 * Uso:
 *   import { ZKVaultSDK } from './zk-vault-sdk';
 *   const sdk = new ZKVaultSDK({ baseUrl: 'http://localhost:3000' });
 *   await sdk.login('user@example.com', 'password');
 *   const secrets = await sdk.listSecrets();
 * =====================================================================
 */
import {
  performLogin,
  performRegistration,
  encryptNewSecret,
  decryptSecret,
  importPublicKeyJwk,
} from "../lib/crypto-client";

export interface ZKVaultConfig {
  baseUrl: string;
}

export interface ZKSecret {
  id: string;
  encryptedTitle: string;
  titleIv: string;
  encryptedData: string;
  dataIv: string;
  wrappedKey: string;
  ownedByMe: boolean;
  ownerEmail: string;
  createdAt: string;
}

export class ZKVaultSDK {
  private baseUrl: string;
  private sessionToken: string | null = null;
  private masterKey: CryptoKey | null = null;
  private privateKey: CryptoKey | null = null;
  private publicKey: CryptoKey | null = null;
  private email: string | null = null;

  constructor(config: ZKVaultConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
  }

  async register(email: string, password: string): Promise<void> {
    const artifacts = await performRegistration(email, password);
    const res = await fetch(`${this.baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        kdfAlgorithm: artifacts.kdfAlgorithm,
        kdfSalt: artifacts.kdfSalt,
        kdfIterations: artifacts.kdfIterations,
        kdfMemoryKiB: artifacts.kdfMemoryKiB,
        kdfParallelism: artifacts.kdfParallelism,
        publicKeyJwk: artifacts.publicKeyJwk,
        publicKeyFingerprint: artifacts.publicKeyFingerprint,
        popSignature: artifacts.popSignature,
        encryptedPrivateKeyJwk: artifacts.encryptedPrivateKey.encryptedJwk,
        privateKeyIv: artifacts.encryptedPrivateKey.iv,
      }),
    });
    if (!res.ok) throw new Error((await res.json()).error);

    this.masterKey = artifacts.masterKey;
    this.privateKey = artifacts.privateKey;
    this.publicKey = artifacts.publicKey;

    // Auto-login
    await this.login(email, password);
  }

  async login(email: string, password: string): Promise<void> {
    const loginRes = await fetch(`${this.baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error(loginData.error);

    const { masterKey, privateKey } = await performLogin({
      password,
      kdfAlgorithm: loginData.kdfAlgorithm,
      kdfSaltB64: loginData.kdfSalt,
      kdfIterations: loginData.kdfIterations,
      kdfMemoryKiB: loginData.kdfMemoryKiB,
      kdfParallelism: loginData.kdfParallelism,
      encryptedPrivateKeyJwkB64: loginData.encryptedPrivateKeyJwk,
      privateKeyIvB64: loginData.privateKeyIv,
    });

    this.sessionToken = loginData.sessionToken;
    this.masterKey = masterKey;
    this.privateKey = privateKey;
    this.publicKey = await importPublicKeyJwk(loginData.publicKeyJwk);
    this.email = email;
  }

  async listSecrets(): Promise<ZKSecret[]> {
    if (!this.sessionToken) throw new Error("No autenticado");
    const res = await fetch(`${this.baseUrl}/api/secrets`, {
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    return data.secrets;
  }

  async createSecret(title: string, content: string): Promise<string> {
    if (!this.sessionToken || !this.publicKey) throw new Error("No autenticado");
    const artifacts = await encryptNewSecret(title, content, this.publicKey);
    const res = await fetch(`${this.baseUrl}/api/secrets`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.sessionToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        encryptedTitle: artifacts.encryptedTitle,
        titleIv: artifacts.titleIv,
        encryptedData: artifacts.encryptedData,
        dataIv: artifacts.dataIv,
        wrappedKeyForOwner: artifacts.wrappedKeyForOwner,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    return data.secretId;
  }

  async decryptSecret(secret: ZKSecret): Promise<{ title: string; content: string }> {
    if (!this.privateKey) throw new Error("No autenticado");
    return decryptSecret(
      secret.wrappedKey,
      secret.encryptedTitle,
      secret.titleIv,
      secret.encryptedData,
      secret.dataIv,
      this.privateKey,
    );
  }

  async deleteSecret(secretId: string): Promise<void> {
    if (!this.sessionToken) throw new Error("No autenticado");
    const res = await fetch(`${this.baseUrl}/api/secrets/${secretId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    if (!res.ok) throw new Error((await res.json()).error);
  }

  async logout(): Promise<void> {
    if (!this.sessionToken) return;
    await fetch(`${this.baseUrl}/api/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    this.sessionToken = null;
    this.masterKey = null;
    this.privateKey = null;
    this.publicKey = null;
    this.email = null;
  }

  isAuthenticated(): boolean {
    return this.sessionToken !== null && this.privateKey !== null;
  }
}
