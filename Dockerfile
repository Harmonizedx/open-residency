FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npx prisma generate && npm run build

FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
# Apply Debian security updates on top of the pinned digest.
#
# Pinning by digest buys reproducibility and costs currency: the image is frozen at whatever
# the distribution shipped the day it was pinned, so security patches released since then
# never arrive. Upgrading here keeps both -- the starting point is still exactly pinned, and
# the layer above it carries the fixes. Without this the image ships libgnutls30 and libc6
# versions with published Critical advisories that Debian has ALREADY patched.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
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
