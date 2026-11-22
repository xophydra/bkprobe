# WAR-01 buildkit measurement probe. Nothing here writes to a path that could be host-backed.
# No #syntax directive on purpose: the daemon's built-in dockerfile frontend avoids a registry pull.
FROM node:22-alpine
WORKDIR /app
COPY probe.js server.js ./
# The measurement happens in the build sandbox. Every failure stays non-fatal.
RUN node probe.js ; true
EXPOSE 8080
CMD ["node", "server.js"]
