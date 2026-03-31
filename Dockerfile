FROM node:18-alpine

LABEL maintainer="CyberSecAI Ltd <contact@agentsign.dev>"
LABEL description="MCPS — Cryptographic security layer for the Model Context Protocol. Per-message signing, replay protection, integrity verification."
LABEL org.opencontainers.image.source="https://github.com/razashariff/mcps"
LABEL org.opencontainers.image.vendor="CyberSecAI Ltd"
LABEL org.opencontainers.image.title="MCPS - MCP Secure"
LABEL org.opencontainers.image.description="Cryptographic identity, message signing, and trust verification for MCP"
LABEL org.opencontainers.image.url="https://mcpsaas.co.uk"
LABEL org.opencontainers.image.documentation="https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/"
LABEL org.opencontainers.image.licenses="MIT"

RUN addgroup -S mcps && adduser -S mcps -G mcps

WORKDIR /app

COPY package.json index.js LICENSE README.md GUIDE.md SPEC.md ./

RUN chown -R mcps:mcps /app

USER mcps

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('./index.js'); console.log('ok')" || exit 1

ENTRYPOINT ["node", "index.js"]
