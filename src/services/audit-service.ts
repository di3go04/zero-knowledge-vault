import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const auditService = {
  async log(params: {
    userId: string;
    encryptedEvent: string;
    eventIv: string;
    eventCategory: string;
  }) {
    return prisma.auditLog.create({ data: params });
  },

  async listByUser(userId: string, limit = 50, offset = 0) {
    const [data, total] = await Promise.all([
      prisma.auditLog.findMany({
        where: { userId },
        take: limit,
        skip: offset,
        orderBy: { createdAt: "desc" },
      }),
      prisma.auditLog.count({ where: { userId } }),
    ]);
    return { data, total, limit, offset };
  },
};
