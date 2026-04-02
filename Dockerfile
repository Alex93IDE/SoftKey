FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY main.js index.html favicon.svg ./

EXPOSE 3333

CMD ["node", "main.js"]
