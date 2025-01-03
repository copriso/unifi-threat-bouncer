#Build stage
FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

#Production stage
FROM node:22-alpine AS production

WORKDIR /app

COPY package*.json ./
COPY --from=build /app/prisma ./prisma

RUN npm ci --only=production && npx prisma generate

COPY --from=build /app/dist ./dist

CMD ["node", "dist/index.js"]