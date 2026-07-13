/**
 * gdpr-export.ts — Exportación de datos personales cifrados.
 *
 *
 * El usuario puede exportar sus datos personales en JSON
 * con AES-256-GCM usando su masterKey. El servidor no puede
 * leer el contenido del export.
 */
import { db } from "@/lib/db";

export async function exportUserData(userId: string) {
  const user = await db.user.findUnique({
    where: { id: userId },
    include: {
      keyMaterial: true,
      ownedSecrets: { include: { keyShares: true, versions: true, comments: true } },
      secretKeyShares: { include: { secret: { include: { owner: { select: { email: true } } } } } },
      devices: true,
      auditLogs: { orderBy: { createdAt: "desc" }, take: 1000 },
    },
  });

  if (!user) throw new Error("Usuario no encontrado");

  // Devolver datos crudos — el cliente los cifrará antes de descargar
  return {
    user: { email: user.email, name: user.name, createdAt: user.createdAt },
    keyMaterial: user.keyMaterial,
    secrets: user.ownedSecrets.map((s) => ({
      id: s.id,
      encryptedTitle: s.encryptedTitle,
      titleIv: s.titleIv,
      encryptedData: s.encryptedData,
      dataIv: s.dataIv,
      createdAt: s.createdAt,
      shares: s.keyShares,
      versions: s.versions,
      comments: s.comments,
    })),
    sharedWithMe: user.secretKeyShares,
    devices: user.devices.map((d) => ({
      id: d.id,
      deviceName: d.deviceName,
      publicKeyECDHFingerprint: d.publicKeyECDHFingerprint,
      enrolledAt: d.enrolledAt,
    })),
    auditLogs: user.auditLogs,
    exportedAt: new Date().toISOString(),
  };
}
