/**
 * Simple plugin system for Zero-Knowledge Vault.
 * Plugins can hook into lifecycle events.
 */

export interface Plugin {
  name: string;
  version: string;
  description?: string;

  // Hooks
  onSecretCreated?: (params: { userId: string; secretId: string }) => Promise<void> | void;
  onSecretDeleted?: (params: { userId: string; secretId: string }) => Promise<void> | void;
  onSecretShared?: (params: { secretId: string; recipientId: string }) => Promise<void> | void;
  onUserRegistered?: (params: { userId: string; email: string }) => Promise<void> | void;
  onUserLogin?: (params: { userId: string; email: string }) => Promise<void> | void;
  onKeyRotated?: (params: { userId: string }) => Promise<void> | void;
}

const plugins: Plugin[] = [];

export function registerPlugin(plugin: Plugin): void {
  if (plugins.find((p) => p.name === plugin.name)) {
    console.warn(`Plugin "${plugin.name}" already registered`);
    return;
  }
  plugins.push(plugin);
  console.warn(`Plugin registered: ${plugin.name} v${plugin.version}`);
}

export function getPlugins(): Plugin[] {
  return [...plugins];
}

async function executeHook<T extends keyof Plugin>(
  hook: T,
  params: Parameters<Exclude<Plugin[T], undefined>>[0]
): Promise<void> {
  for (const plugin of plugins) {
    const handler = plugin[hook];
    if (typeof handler === "function") {
      try {
        await (handler as (args: typeof params) => Promise<void>)(params);
      } catch (error) {
        console.error(`Plugin "${plugin.name}" failed on hook "${hook}":`, error);
      }
    }
  }
}

export const hooks = {
  onSecretCreated: (params: { userId: string; secretId: string }) =>
    executeHook("onSecretCreated", params),
  onSecretDeleted: (params: { userId: string; secretId: string }) =>
    executeHook("onSecretDeleted", params),
  onSecretShared: (params: { secretId: string; recipientId: string }) =>
    executeHook("onSecretShared", params),
  onUserRegistered: (params: { userId: string; email: string }) =>
    executeHook("onUserRegistered", params),
  onUserLogin: (params: { userId: string; email: string }) => executeHook("onUserLogin", params),
  onKeyRotated: (params: { userId: string }) => executeHook("onKeyRotated", params),
};
