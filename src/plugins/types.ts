export interface VaultPlugin { name: string; version: string; onSecretCreated?(secretId: string, title: string): void; onSecretDecrypted?(secretId: string, content: string): void; onLogin?(email: string): void; }
export const pluginRegistry: VaultPlugin[] = [];
export function registerPlugin(p: VaultPlugin) { pluginRegistry.push(p); }
