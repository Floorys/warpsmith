FROM node:22-alpine

WORKDIR /app

# No dependencies to install - package.json is copied for metadata only.
COPY package.json ./
COPY src ./src
COPY bin ./bin
COPY public ./public
COPY test ./test

ENV PORT=8787
ENV HOST=0.0.0.0
EXPOSE 8787

RUN addgroup -S awg && adduser -S awg -G awg && chown -R awg:awg /app
USER awg

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
	CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
