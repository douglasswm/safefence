FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY tsconfig.json ./
COPY src/ src/
RUN npx tsc

FROM node:22-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder --chown=app:app /app/dist dist/
COPY --from=builder --chown=app:app /app/node_modules node_modules/
COPY --chown=app:app package.json ./
USER app
EXPOSE 3100
CMD ["node", "dist/index.js"]
