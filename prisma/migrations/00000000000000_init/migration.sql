-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "UserKeyMaterial" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "kdfAlgorithm" TEXT NOT NULL,
    "kdfSalt" TEXT NOT NULL,
    "kdfIterations" INTEGER NOT NULL DEFAULT 600000,
    "kdfMemoryKiB" INTEGER,
    "kdfParallelism" INTEGER,
    "publicKeyJwk" TEXT NOT NULL,
    "publicKeyFingerprint" TEXT NOT NULL,
    "popSignature" TEXT NOT NULL,
    "encryptedPrivateKeyJwk" TEXT,
    "privateKeyIv" TEXT,
    "recoverySalt" TEXT,
    "recoveryIterations" INTEGER,
    "encryptedPrivateKeyForRecovery" TEXT,
    "recoveryIv" TEXT,
    "recoveryEnabled" BOOLEAN NOT NULL DEFAULT false,
    "passwordChangedAt" DATETIME,
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
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SecretKeyShare_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "SecretKeyShare_recipientId_fkey" FOREIGN KEY ("recipientId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "deviceName" TEXT NOT NULL,
    "publicKeyECDH" TEXT NOT NULL,
    "publicKeyECDHFingerprint" TEXT NOT NULL,
    "enrollerPublicKeyECDH" TEXT,
    "wrappedPrivateKeyForDevice" TEXT,
    "wrappedPrivateKeyIv" TEXT,
    "enrollCode" TEXT,
    "enrollCodeExpiresAt" DATETIME,
    "revokedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Device_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "encryptedEvent" TEXT NOT NULL,
    "eventIv" TEXT NOT NULL,
    "eventCategory" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "UserKeyMaterial_userId_key" ON "UserKeyMaterial"("userId");
CREATE INDEX "UserKeyMaterial_publicKeyFingerprint_idx" ON "UserKeyMaterial"("publicKeyFingerprint");
CREATE INDEX "Secret_ownerId_idx" ON "Secret"("ownerId");
CREATE UNIQUE INDEX "SecretKeyShare_secretId_recipientId_key" ON "SecretKeyShare"("secretId", "recipientId");
CREATE INDEX "Device_userId_idx" ON "Device"("userId");
CREATE INDEX "Device_enrollCode_idx" ON "Device"("enrollCode");
CREATE INDEX "AuditLog_userId_createdAt_idx" ON "AuditLog"("userId", "createdAt");
CREATE INDEX "AuditLog_eventCategory_idx" ON "AuditLog"("eventCategory");
