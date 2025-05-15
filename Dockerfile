FROM node:22-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install express node-fetch
COPY . .

ENV SERVER_PORT=3000
ENV PAGE_TITLE="IP信息查询"

EXPOSE ${SERVER_PORT}
CMD ["node", "server.js"]
