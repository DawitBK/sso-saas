FROM node:22-alpine AS builder
WORKDIR /app/backend
COPY backend/package.json backend/package-lock.json backend/tsconfig.json ./
RUN npm install
COPY backend/src/ ./src/
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app/backend
ENV NODE_ENV=production
ENV PORT=7300
COPY backend/package.json backend/package-lock.json ./
RUN npm install --omit=dev
COPY --from=builder /app/backend/dist ./dist
COPY backend/migrations ./migrations
EXPOSE 7300
CMD ["node", "dist/main.js"]
