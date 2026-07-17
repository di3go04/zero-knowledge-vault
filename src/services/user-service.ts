import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const userService = {
  async findByEmail(email: string) {
    return prisma.user.findUnique({
      where: { email },
      include: { userKeyMaterial: true },
    });
  },

  async findById(id: string) {
    return prisma.user.findUnique({
      where: { id },
      include: { userKeyMaterial: true },
    });
  },

  async listUsers(limit = 50, offset = 0) {
    const [data, total] = await Promise.all([
      prisma.user.findMany({
        take: limit,
        skip: offset,
        orderBy: { createdAt: "desc" },
        select: { id: true, email: true, name: true, createdAt: true },
      }),
      prisma.user.count(),
    ]);
    return { data, total, limit, offset };
  },
};
