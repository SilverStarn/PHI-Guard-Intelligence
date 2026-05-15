FROM node:22-alpine

WORKDIR /app

COPY package.json package.json
COPY apps/web/package.json apps/web/package.json
RUN npm install

COPY apps/web apps/web

EXPOSE 5173

CMD ["npm", "--workspace", "@phi-guard-intelligence/web", "run", "dev", "--", "--host", "0.0.0.0"]
