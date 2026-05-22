# Vulnerable: Multiple Docker best-practice violations.

# ruleid: using-latest-tag
FROM ubuntu:latest

# ruleid: running-as-root (no USER directive in final image)

# ruleid: curl-piped-to-shell
RUN curl -fsSL https://example.com/install.sh | bash

RUN apt-get update && apt-get install -y python3

COPY . /app
WORKDIR /app

EXPOSE 8080 22

CMD ["python3", "app.py"]
