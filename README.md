# HTTP/2 Bomb — CVE-2026-49975

[![Docker Build & Publish](https://github.com/obrige/http2-bomb/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/obrige/http2-bomb/actions/workflows/docker-publish.yml)
[![GHCR](https://img.shields.io/badge/ghcr.io-obrige%2Fhttp2--bomb-blue)](https://github.com/obrige/http2-bomb/pkgs/container/http2-bomb)

HTTP/2 Stream Amplification PoC · Docker · Web Console

## Vulnerability

HTTP/2 allows multiplexing multiple streams over a single TCP connection. This PoC crafts specially formed HEADERS frames containing a large number of internal references, forcing the server to allocate massive amounts of memory to track them.

| Server | Amplification | Effect |
|--------|--------------|--------|
| Envoy 1.37.2 | ~5,700:1 | ~32 GB in ~10s |
| Apache httpd 2.4.67 | ~4,000:1 | ~32 GB in ~18s |
| Nginx | High | Rapid OOM |

Minimal traffic, maximum memory exhaustion.

## Quick Start

```bash
git clone https://github.com/obrige/http2-bomb.git
cd http2-bomb
docker compose up -d
```

Open http://localhost:8080

> Uses pre-built image from `ghcr.io/obrige/http2-bomb:latest`. No local build required.

### Manual

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Pull Image Directly

```bash
docker pull ghcr.io/obrige/http2-bomb:latest
docker run -d -p 8080:8080 ghcr.io/obrige/http2-bomb:latest
```

## Features

- Web console with real-time monitoring
- One-click HTTP/2 detection
- Configurable attack parameters
- SSE real-time log streaming
- Docker one-click deployment
- CI/CD auto-publish to GHCR

## Disclaimer

**For authorized security testing and educational research only.** Do not use against targets without explicit written permission. Users assume all legal responsibility.
