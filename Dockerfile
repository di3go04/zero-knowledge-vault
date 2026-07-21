FROM oven/bun:1 AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN bunx prisma generate
RUN bun run build

FROM oven/bun:1-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/.next/standalone ./
COPY --from=deps /app/.next/static ./.next/static
COPY --from=deps /app/public ./public
COPY --from=deps /app/prisma ./prisma
EXPOSE 3000
CMD ["bun", "server.js"]
