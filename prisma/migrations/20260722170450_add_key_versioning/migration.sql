-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_SecretKeyShare" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "secretId" TEXT NOT NULL,
    "recipientId" TEXT NOT NULL,
    "wrappedSymmetricKey" TEXT NOT NULL,
    "wrappingKeyVersion" INTEGER NOT NULL DEFAULT 1,
    "role" TEXT NOT NULL DEFAULT 'readonly',
    "seenAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "SecretKeyShare_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "SecretKeyShare_recipientId_fkey" FOREIGN KEY ("recipientId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_SecretKeyShare" ("createdAt", "id", "recipientId", "role", "secretId", "seenAt", "wrappedSymmetricKey") SELECT "createdAt", "id", "recipientId", "role", "secretId", "seenAt", "wrappedSymmetricKey" FROM "SecretKeyShare";
DROP TABLE "SecretKeyShare";
ALTER TABLE "new_SecretKeyShare" RENAME TO "SecretKeyShare";
CREATE UNIQUE INDEX "SecretKeyShare_secretId_recipientId_key" ON "SecretKeyShare"("secretId", "recipientId");
CREATE TABLE "new_UserKeyMaterial" (
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
    "cryptoVersion" INTEGER NOT NULL DEFAULT 1,
    "keyCompromisedAt" DATETIME,
    "recoverySalt" TEXT,
    "recoveryIterations" INTEGER,
    "encryptedPrivateKeyForRecovery" TEXT,
    "recoveryIv" TEXT,
    "recoveryEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "UserKeyMaterial_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_UserKeyMaterial" ("createdAt", "encryptedMlKemPrivateKey", "encryptedPrivateKeyForRecovery", "encryptedPrivateKeyJwk", "id", "kdfAlgorithm", "kdfIterations", "kdfMemoryKiB", "kdfParallelism", "kdfSalt", "mlKemPrivateKeyIv", "mlKemPublicKey", "popSignature", "popSignatureHash", "privateKeyIv", "publicKeyFingerprint", "publicKeyJwk", "recoveryEnabled", "recoveryIterations", "recoveryIv", "recoverySalt", "updatedAt", "userId") SELECT "createdAt", "encryptedMlKemPrivateKey", "encryptedPrivateKeyForRecovery", "encryptedPrivateKeyJwk", "id", "kdfAlgorithm", "kdfIterations", "kdfMemoryKiB", "kdfParallelism", "kdfSalt", "mlKemPrivateKeyIv", "mlKemPublicKey", "popSignature", "popSignatureHash", "privateKeyIv", "publicKeyFingerprint", "publicKeyJwk", "recoveryEnabled", "recoveryIterations", "recoveryIv", "recoverySalt", "updatedAt", "userId" FROM "UserKeyMaterial";
DROP TABLE "UserKeyMaterial";
ALTER TABLE "new_UserKeyMaterial" RENAME TO "UserKeyMaterial";
CREATE UNIQUE INDEX "UserKeyMaterial_userId_key" ON "UserKeyMaterial"("userId");
CREATE INDEX "UserKeyMaterial_publicKeyFingerprint_idx" ON "UserKeyMaterial"("publicKeyFingerprint");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
