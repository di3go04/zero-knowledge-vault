import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const secretService = {
  async findByOwner(ownerId: string, limit = 50, offset = 0) {
    const [data, total] = await Promise.all([
      prisma.secret.findMany({
        where: { ownerId },
        take: limit,
        skip: offset,
        orderBy: { createdAt: "desc" },
        include: {
          secretKeyShares: {
            select: { recipientId: true },
          },
        },
      }),
      prisma.secret.count({ where: { ownerId } }),
    ]);
    return { data, total, limit, offset };
  },

  async create(data: {
    ownerId: string;
    encryptedTitle: string;
    titleIv: string;
    encryptedData: string;
    dataIv: string;
  }) {
    return prisma.secret.create({ data });
  },

  async delete(id: string, ownerId: string) {
    const secret = await prisma.secret.findUnique({ where: { id } });
    if (!secret || secret.ownerId !== ownerId) {
      throw new Error("No autorizado");
    }
    return prisma.secret.delete({ where: { id } });
  },
};
