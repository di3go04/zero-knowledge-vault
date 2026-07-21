/**
 * Dead man's switch for emergency access.
 * If user doesn't check in within N days, designated contact gets access.
 */
export interface DeadMansSwitchConfig { userId: string; checkInIntervalDays: number; emergencyContactEmail: string; lastCheckIn: Date; }
const switches = new Map<string, DeadMansSwitchConfig>();
export function configureDeadMansSwitch(config: DeadMansSwitchConfig): void { switches.set(config.userId, config); }
export function checkIn(userId: string): void {
  const sw = switches.get(userId);
  if (sw) sw.lastCheckIn = new Date();
}
export function shouldTriggerEmergency(userId: string): boolean {
  const sw = switches.get(userId);
  if (!sw) return false;
  const daysSince = (Date.now() - sw.lastCheckIn.getTime()) / (1000 * 60 * 60 * 24);
  return daysSince > sw.checkInIntervalDays;
}
export function getExpiredSwitches(): DeadMansSwitchConfig[] {
  return Array.from(switches.values()).filter(s => shouldTriggerEmergency(s.userId));
}
