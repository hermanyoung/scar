FROM node:20-alpine

# ruleid: docker.security.cwe-200.arg-env-secret
ARG API_KEY

# ruleid: docker.security.cwe-200.arg-env-secret
ARG DB_PASSWORD

# ruleid: docker.security.cwe-200.arg-env-secret
ARG PRIVATE_KEY

# ok: docker.security.cwe-200.arg-env-secret
ARG BUILD_VERSION

# ok: docker.security.cwe-200.arg-env-secret
ARG NODE_ENV

RUN echo "building"
