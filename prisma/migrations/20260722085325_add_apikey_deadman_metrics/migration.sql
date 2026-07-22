-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "deviceName" TEXT NOT NULL,
    "publicKeyECDH" TEXT NOT NULL,
    "publicKeyECDHFingerprint" TEXT NOT NULL,
    "enrollerPublicKeyECDH" TEXT,
    "wrappedPrivateKeyForDevice" TEXT NOT NULL,
    "wrappedPrivateKeyIv" TEXT NOT NULL,
    "enrollCode" TEXT,
    "enrollCodeExpiresAt" DATETIME,
    "enrolledAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" DATETIME,
    CONSTRAINT "Device_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "UserKeyMaterial" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "kdfAlgorithm" TEXT NOT NULL DEFAULT 'argon2id',
    "kdfSalt" TEXT NOT NULL,
    "kdfIterations" INTEGER NOT NULL,
    "kdfMemoryKiB" INTEGER,
    "kdfParallelism" INTEGER,
    "publicKeyJwk" TEXT NOT NULL,
    "publicKeyFingerprint" TEXT NOT NULL,
    "popSignature" TEXT NOT NULL,
    "popSignatureHash" TEXT NOT NULL,
    "encryptedPrivateKeyJwk" TEXT NOT NULL,
    "privateKeyIv" TEXT NOT NULL,
    "mlKemPublicKey" TEXT,
    "encryptedMlKemPrivateKey" TEXT,
    "mlKemPrivateKeyIv" TEXT,
    "recoverySalt" TEXT,
    "recoveryIterations" INTEGER,
    "encryptedPrivateKeyForRecovery" TEXT,
    "recoveryIv" TEXT,
    "recoveryEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "UserKeyMaterial_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Secret" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "ownerId" TEXT NOT NULL,
    "encryptedTitle" TEXT NOT NULL,
    "titleIv" TEXT NOT NULL,
    "encryptedData" TEXT NOT NULL,
    "dataIv" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Secret_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "SecretKeyShare" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "secretId" TEXT NOT NULL,
    "recipientId" TEXT NOT NULL,
    "wrappedSymmetricKey" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'readonly',
    "seenAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SecretKeyShare_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "SecretKeyShare_recipientId_fkey" FOREIGN KEY ("recipientId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "encryptedEvent" TEXT NOT NULL,
    "eventIv" TEXT NOT NULL,
    "encryptedCategory" TEXT NOT NULL DEFAULT '',
    "categoryIv" TEXT NOT NULL DEFAULT '',
    "eventCategory" TEXT NOT NULL,
    "prevHash" TEXT,
    "logHash" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "ApiKey" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "scopes" TEXT NOT NULL,
    "expiresAt" DATETIME,
    "lastUsedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" DATETIME
);

-- CreateTable
CREATE TABLE "DeadManSwitch" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "gracePeriodMs" INTEGER NOT NULL DEFAULT 86400000,
    "lastPulseAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "notifyEmail" TEXT NOT NULL,
    "message" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "Metric" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "value" INTEGER NOT NULL DEFAULT 0
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "Device_userId_idx" ON "Device"("userId");

-- CreateIndex
CREATE INDEX "Device_enrollCode_idx" ON "Device"("enrollCode");

-- CreateIndex
CREATE UNIQUE INDEX "UserKeyMaterial_userId_key" ON "UserKeyMaterial"("userId");

-- CreateIndex
CREATE INDEX "UserKeyMaterial_publicKeyFingerprint_idx" ON "UserKeyMaterial"("publicKeyFingerprint");

-- CreateIndex
CREATE INDEX "Secret_ownerId_createdAt_idx" ON "Secret"("ownerId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SecretKeyShare_secretId_recipientId_key" ON "SecretKeyShare"("secretId", "recipientId");

-- CreateIndex
CREATE INDEX "AuditLog_userId_createdAt_idx" ON "AuditLog"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_eventCategory_idx" ON "AuditLog"("eventCategory");

-- CreateIndex
CREATE UNIQUE INDEX "ApiKey_keyHash_key" ON "ApiKey"("keyHash");

-- CreateIndex
CREATE INDEX "ApiKey_userId_idx" ON "ApiKey"("userId");

-- CreateIndex
CREATE INDEX "ApiKey_keyHash_idx" ON "ApiKey"("keyHash");

-- CreateIndex
CREATE UNIQUE INDEX "DeadManSwitch_userId_key" ON "DeadManSwitch"("userId");

-- CreateIndex
CREATE INDEX "DeadManSwitch_userId_idx" ON "DeadManSwitch"("userId");

-- CreateIndex
CREATE INDEX "DeadManSwitch_lastPulseAt_idx" ON "DeadManSwitch"("lastPulseAt");

-- CreateIndex
CREATE UNIQUE INDEX "Metric_name_key" ON "Metric"("name");

-- CreateIndex
CREATE INDEX "Metric_name_idx" ON "Metric"("name");


