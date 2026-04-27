FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir hatchling

COPY pyproject.toml pyproject.toml
COPY src src
COPY README.md README.md

RUN pip install --no-cache-dir .

ENV PORT=8080
EXPOSE 8080

CMD ["python", "-m", "intervals_mcp_server.remote_server"]
