FROM python:3.14-slim

LABEL org.opencontainers.image.title="HTTP/2 Bomb - CVE-2026-49975"
LABEL org.opencontainers.image.description="HTTP/2 Stream Amplification PoC"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash bomber && \
    mkdir -p /app && chown -R bomber:bomber /app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

USER bomber

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/api/stats || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
