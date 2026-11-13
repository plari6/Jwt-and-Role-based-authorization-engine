FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY bin ./bin
COPY src ./src
# data/ (SQLite) and keys/ (signing keys) must be volumes so they survive redeploys
VOLUME ["/app/data", "/app/keys"]
EXPOSE 4000
USER node
HEALTHCHECK CMD wget -qO- http://127.0.0.1:4000/healthz || exit 1
CMD ["node", "bin/authz.js", "serve"]
