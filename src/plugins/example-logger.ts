import { registerPlugin, type VaultPlugin } from "./types";
export const loggerPlugin: VaultPlugin = {
  name: "audit-logger", version: "1.0.0",
  onSecretCreated: (id, title) => console.log(`[plugin] Secret created: ${id} "${title}"`),
  onSecretDecrypted: (id) => console.log(`[plugin] Secret decrypted: ${id}`),
  onLogin: (email) => console.log(`[plugin] User logged in: ${email}`),
};
registerPlugin(loggerPlugin);
