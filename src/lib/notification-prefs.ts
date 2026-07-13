/**
 * Notification preferences — qué notificaciones recibe el usuario.
 */
export interface NotificationPrefs {
  emailOnShare: boolean;
  emailOnDevice: boolean;
  emailOnTrialExpiring: boolean;
  emailOnSecurityAlert: boolean;
}

export const DEFAULT_PREFS: NotificationPrefs = {
  emailOnShare: true,
  emailOnDevice: true,
  emailOnTrialExpiring: true,
  emailOnSecurityAlert: true,
};

// En producción, guardar en BD (tabla UserNotificationPrefs)
const prefsMap = new Map<string, NotificationPrefs>();

export function getPrefs(userId: string): NotificationPrefs {
  return prefsMap.get(userId) ?? DEFAULT_PREFS;
}

export function setPrefs(userId: string, prefs: Partial<NotificationPrefs>): NotificationPrefs {
  const current = getPrefs(userId);
  const updated = { ...current, ...prefs };
  prefsMap.set(userId, updated);
  return updated;
}
