FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npx prisma generate && npm run build

FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/config ./config
# The pinned JSON-LD contexts. Canonicalization resolves these from disk rather than
# fetching them, so an image without them cannot issue ldp_vc credentials at all.
COPY --from=build /app/contexts ./contexts
COPY package*.json ./
EXPOSE 3000
CMD ["node", "dist/main.js"]
