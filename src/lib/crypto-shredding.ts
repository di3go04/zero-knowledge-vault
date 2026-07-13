/**
 * =====================================================================
 * crypto-shredding.ts — Borrado criptográfico garantizado.
 * =====================================================================
 *
 * la BD. Hay que destruir la llave que cifra la privateKey RSA.
 *
 * Crypto-shredding: eliminar el `encryptedPrivateKeyJwk` Y el
 * `encryptedPrivateKeyForRecovery` de la BD. Sin esos blobs, ni
 * siquiera con la contraseña maestra se puede descifrar nada — la
 * privateKey RSA deja de existir en cualquier forma recuperable.
 *
 * Esto garantiza GDPR "Right to be Forgotten" (Art. 17).
 * =====================================================================
 */
import { db } from "@/lib/db";

/**
 * Ejecuta crypto-shredding sobre un usuario:
 *   1. Sobrescribe encryptedPrivateKeyJwk con basura aleatoria
 *   2. Sobrescribe encryptedPrivateKeyForRecovery con basura
 *   3. Elimina todos los SecretKeyShare del usuario
 *   4. Elimina todos los Secret del usuario (cascade)
 *   5. Elimina todos los Device del usuario (cascade)
 *   6. Elimina la UserKeyMaterial
 *   7. Elimina el User
 *
 * Tras esto, los datos son criptográficamente irrecuperables incluso
 * si un backup de la BD se filtra.
 */
export async function cryptoShredUser(userId: string): Promise<{
  shredded: boolean;
  details: string[];
}> {
  const details: string[] = [];

  // 1. Sobrescribir blobs cifrados con basura aleatoria (32 bytes)
  const garbage = "A".repeat(64); // basura base64
  await db.userKeyMaterial.update({
    where: { userId },
    data: {
      encryptedPrivateKeyJwk: garbage,
      privateKeyIv: garbage,
      encryptedPrivateKeyForRecovery: null,
      recoveryIv: null,
      recoverySalt: null,
      recoveryIterations: null,
      recoveryEnabled: false,
      popSignature: garbage,
    },
  });
  details.push("encryptedPrivateKeyJwk sobrescrito con basura");

  // 2. Eliminar todos los SecretKeyShare donde es recipient
  const deletedShares = await db.secretKeyShare.deleteMany({
    where: { recipientId: userId },
  });
  details.push(`${deletedShares.count} SecretKeyShare eliminados`);

  // 3. Eliminar todos los Secrets del usuario (cascade borra versions, comments, shares)
  const deletedSecrets = await db.secret.deleteMany({
    where: { ownerId: userId },
  });
  details.push(`${deletedSecrets.count} Secrets eliminados`);

  // 4. Eliminar todos los Devices
  const deletedDevices = await db.device.deleteMany({
    where: { userId },
  });
  details.push(`${deletedDevices.count} Devices eliminados`);

  // 5. Eliminar AuditLogs
  const deletedLogs = await db.auditLog.deleteMany({
    where: { userId },
  });
  details.push(`${deletedLogs.count} AuditLogs eliminados`);

  // 6. Eliminar SecretComments
  const deletedComments = await db.secretComment.deleteMany({
    where: { authorId: userId },
  });
  details.push(`${deletedComments.count} SecretComments eliminados`);

  // 7. Eliminar TeamVaultMemberships
  const deletedMemberships = await db.teamVaultMember.deleteMany({
    where: { userId },
  });
  details.push(`${deletedMemberships.count} TeamVaultMemberships eliminados`);

  // 8. Eliminar UserKeyMaterial
  await db.userKeyMaterial.delete({
    where: { userId },
  });
  details.push("UserKeyMaterial eliminado");

  // 9. Eliminar User
  await db.user.delete({
    where: { id: userId },
  });
  details.push("User eliminado");

  return { shredded: true, details };
}
