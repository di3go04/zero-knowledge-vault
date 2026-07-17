/**
 * offline-cache.ts — IndexedDB cache + sync queue for offline mode.
 *
 * The vault app degrades gracefully when the server is unreachable:
 *   1. Secrets are cached locally (encrypted blobs only — master key stays in memory).
 *   2. Write operations (create, rotate, share) are queued and replayed on reconnect.
 *   3. A service worker or background sync (when available) replays the queue.
 */

const DB_NAME = "zk-vault-cache";
const DB_VERSION = 1;

export interface CachedSecret {
  id: string;
  title: string;
  encryptedData: string;
  dataIv: string;
  encryptedTitle: string;
  titleIv: string;
  wrappedKey: string;
  updatedAt: string;
}

export interface SyncQueueItem {
  id?: number;
  type: "CREATE_SECRET" | "ROTATE_PASSWORD" | "DELETE_SECRET" | "SHARE_SECRET";
  payload: unknown;
  createdAt: string;
  retries: number;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      if (!db.objectStoreNames.contains("secrets")) {
        const store = db.createObjectStore("secrets", { keyPath: "id" });
        store.createIndex("updatedAt", "updatedAt", { unique: false });
      }

      if (!db.objectStoreNames.contains("syncQueue")) {
        const queue = db.createObjectStore("syncQueue", {
          keyPath: "id",
          autoIncrement: true,
        });
        queue.createIndex("createdAt", "createdAt", { unique: false });
      }
    };

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

// ---- Secrets Cache ----

export async function cacheSecret(secret: CachedSecret): Promise<void> {
  const db = await openDB();
  const tx = db.transaction("secrets", "readwrite");
  tx.objectStore("secrets").put(secret);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getCachedSecret(id: string): Promise<CachedSecret | null> {
  const db = await openDB();
  const tx = db.transaction("secrets", "readonly");
  const request = tx.objectStore("secrets").get(id);
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function getAllCachedSecrets(): Promise<CachedSecret[]> {
  const db = await openDB();
  const tx = db.transaction("secrets", "readonly");
  const request = tx.objectStore("secrets").getAll();
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function removeCachedSecret(id: string): Promise<void> {
  const db = await openDB();
  const tx = db.transaction("secrets", "readwrite");
  tx.objectStore("secrets").delete(id);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearSecretsCache(): Promise<void> {
  const db = await openDB();
  const tx = db.transaction("secrets", "readwrite");
  tx.objectStore("secrets").clear();
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---- Sync Queue ----

export async function enqueueSync(item: Omit<SyncQueueItem, "id" | "createdAt" | "retries">): Promise<void> {
  const db = await openDB();
  const tx = db.transaction("syncQueue", "readwrite");
  tx.objectStore("syncQueue").add({
    ...item,
    createdAt: new Date().toISOString(),
    retries: 0,
  });
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getPendingSyncItems(): Promise<SyncQueueItem[]> {
  const db = await openDB();
  const tx = db.transaction("syncQueue", "readonly");
  const request = tx.objectStore("syncQueue").getAll();
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function removeSyncItem(id: number): Promise<void> {
  const db = await openDB();
  const tx = db.transaction("syncQueue", "readwrite");
  tx.objectStore("syncQueue").delete(id);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---- Connection monitoring ----

export function isOnline(): boolean {
  return navigator.onLine;
}

export function onOnlineChange(callback: (online: boolean) => void): () => void {
  const handler = () => callback(navigator.onLine);
  window.addEventListener("online", handler);
  window.addEventListener("offline", handler);
  return () => {
    window.removeEventListener("online", handler);
    window.removeEventListener("offline", handler);
  };
}
