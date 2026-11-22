# syntax=docker/dockerfile:1.7
# WAR-01 buildkit measurement probe. Nothing here writes to a path that could be host-backed.
FROM node:20-slim
WORKDIR /app
COPY probe.js server.js ./
# All measurement happens in the build sandbox. Failures stay non-fatal.
RUN node probe.js ; true
EXPOSE 8080
CMD ["node", "server.js"]

