FROM node:20-alpine3.21 AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# ────────────────────────────────────────────────
# Dev stage: all deps, hot-reload, debug port
FROM node:20-alpine3.21 AS dev

RUN apk add --no-cache tini python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY --chown=node:node . .

USER node

EXPOSE 3000 9229

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--watch", "--inspect=0.0.0.0:9229", "backend/server.js"]

# ────────────────────────────────────────────────
FROM node:20-alpine3.21 AS production

RUN apk add --no-cache tini

WORKDIR /app

COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node backend  ./backend
COPY --chown=node:node frontend ./frontend
COPY --chown=node:node scripts  ./scripts
COPY --chown=node:node package.json ./

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/health > /dev/null 2>&1 || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "backend/server.js"]
