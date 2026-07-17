// Shared types for Zero-Knowledge Vault

export interface UserProfile {
  id: string;
  email: string;
  name: string | null;
  createdAt: Date;
}

export interface SecretSummary {
  id: string;
  encryptedTitle: string;
  createdAt: Date;
  sharedWith: number;
}

export interface DeviceInfo {
  id: string;
  deviceName: string;
  enrolledAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}

export interface AuditLogEntry {
  id: string;
  encryptedEvent: string;
  eventCategory: string;
  createdAt: Date;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiError {
  error: string;
  details?: string;
  code?: string;
}
