# Multi-stage Dockerfile for CloudSec & Container Audit CLI
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md /app/
COPY src/ /app/src/

RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install .

# Production runner image
FROM python:3.12-slim AS runner

WORKDIR /workspace

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

COPY --from=builder /opt/venv /opt/venv

# Run as non-root user for security best practices
RUN groupadd -g 10001 cloudsec && \
    useradd -u 10001 -g cloudsec -s /bin/bash cloudsec && \
    chown -R cloudsec:cloudsec /workspace

USER cloudsec

ENTRYPOINT ["cloudsec"]
CMD ["--help"]
