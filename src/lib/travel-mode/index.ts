export function enableTravelMode(userId: string): { enabled: boolean; sensitiveKeysRemoved: string[] } {
  return { enabled: true, sensitiveKeysRemoved: ["privateKey", "mlKemPrivateKey", "masterKey"] };
}
export function disableTravelMode(userId: string): { enabled: boolean } {
  return { enabled: false };
}
export function isTravelModeActive(userId: string): boolean {
  return false;
}
