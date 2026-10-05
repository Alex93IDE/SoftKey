FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY main.js ./
COPY lib ./lib
COPY routes ./routes
COPY public ./public

ENV NODE_ENV=production
EXPOSE 3333

CMD ["node", "main.js"]
