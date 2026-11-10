FROM node:26-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# generate -> build -> prune -> generate.
#
# The first generate produces the client types tsc needs. The prune drops every
# devDependency, which is what stops build tooling (glob, cross-spawn, tar, minimatch and
# their trees) shipping in a production image and being reported against it forever. The
# second generate restores the generated client, which lives in an unlisted node_modules
# directory that prune treats as extraneous.
#
# prisma itself survives the prune because it is a real dependency of this artifact: the
# Kubernetes and Helm init containers run `npx prisma migrate deploy` from this very image.
RUN npx prisma generate \
    && npm run build \
    && npm prune --omit=dev \
    && npx prisma generate

FROM node:26-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68
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

# Remove npm from the runtime image.
#
# npm ships its own vendored dependency tree under /usr/local/lib/node_modules/npm --
# ip-address, brace-expansion and friends -- which pruning /app can never reach and which
# npm@latest still carries. It was only here to run `npx prisma migrate deploy`, and the
# Prisma CLI does not need npm: node_modules/.bin/prisma is a direct entry point. The
# manifests invoke it that way, so the package manager has no remaining job at runtime.
#
# A production image that cannot install packages is also a smaller thing to reason about:
# there is no npm for a compromised process to fetch with.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
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
