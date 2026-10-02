FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY policy ./policy

RUN mkdir -p /data && chown -R node:node /app /data

USER node

ENV PORT=8300
EXPOSE 8300

CMD ["node", "src/server.js"]
