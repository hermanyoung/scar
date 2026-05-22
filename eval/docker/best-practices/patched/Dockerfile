# Fixed: Follows Docker best practices.

# ok: pinned image with digest
FROM ubuntu:24.04@sha256:abc123

# ok: non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# ok: download verified with checksum
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    echo "expected_sha256  /tmp/install.sh" | sha256sum -c - && \
    bash /tmp/install.sh && \
    rm /tmp/install.sh

RUN apt-get update && apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app

USER appuser

HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["python3", "app.py"]
