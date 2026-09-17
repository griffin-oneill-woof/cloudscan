"""HTTP API and web UI.   Run:  uvicorn cloudscan.api:app --port 8000"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .cache import Cache
from .collectors import REGISTRY
from .engine import scan

BATCH_CONCURRENCY = int(os.getenv("CLOUDSCAN_BATCH_CONCURRENCY", "4"))
API_KEY = os.getenv("CLOUDSCAN_API_KEY")   # set to require the X-Api-Key header (or ?key=) on requests


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not API_KEY:
        print("CloudScan: CLOUDSCAN_API_KEY is not set — /api/scan, /api/batch and /api/recent are "
              "open to anyone who can reach this server. Set it before deploying anywhere but your "
              "own machine.", file=sys.stderr)
    yield


app = FastAPI(title="CloudScan", version="1.0", lifespan=lifespan)

# Closed by default: the bundled web UI is served from this same origin and never needs CORS, and
# opening it to "*" would let any page on the internet drive scans (and API-key guesses) through a
# visitor's browser. Set CLOUDSCAN_CORS to a comma-separated origin list to allow a separate frontend.
_cors_origins = [o.strip() for o in os.getenv("CLOUDSCAN_CORS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_methods=["GET", "POST"], allow_headers=["*"])

cache = Cache()
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"


def _check_key(key: Optional[str], x_api_key: Optional[str] = None):
    if not API_KEY:
        return
    supplied = x_api_key or key
    # compare_digest over a plain != so checking the key can't be timed to guess it a byte at a time.
    if not supplied or not secrets.compare_digest(supplied, API_KEY):
        raise HTTPException(401, "Missing or wrong API key. Pass it as the X-Api-Key header (preferred) or ?key=.")


async def _cached_scan(q: str, fast: bool, fresh: bool) -> dict:
    ck = f"{q.strip().lower()}|{'fast' if fast else 'full'}"
    if not fresh:
        hit = cache.get(ck)
        if hit:
            hit["cached"] = True
            return hit
    body = await scan(q, fast=fast)
    if "error" not in body:
        cache.put(ck, body)
    body["cached"] = False
    return body


@app.get("/")
def index():
    return FileResponse(WEB)


@app.get("/api/health")
def health():
    return {"ok": True, "sources": [{"name": c.name, "description": c.description} for c in REGISTRY]}


@app.get("/api/scan")
async def scan_one(q: str = Query(..., min_length=2, max_length=200), fast: bool = False, fresh: bool = False,
                   key: Optional[str] = None, x_api_key: Optional[str] = Header(None, alias="X-Api-Key")):
    _check_key(key, x_api_key)
    body = await _cached_scan(q, fast, fresh)
    if body.get("error") == "not_found":
        raise HTTPException(404, body["message"])
    return body


class BatchIn(BaseModel):
    queries: list[str] = Field(..., min_length=1, max_length=500)
    fast: bool = True
    key: Optional[str] = None   # kept for backwards compatibility; the X-Api-Key header is preferred


@app.post("/api/batch")
async def scan_batch(req: BatchIn, x_api_key: Optional[str] = Header(None, alias="X-Api-Key")):
    _check_key(req.key, x_api_key)
    sem = asyncio.Semaphore(BATCH_CONCURRENCY)

    async def one(q):
        async with sem:
            try:
                b = await _cached_scan(q, req.fast, False)
            except Exception as exc:
                return {"query": q, "error": str(exc)}
            if "error" in b:
                return {"query": q, **b}
            return {"query": q, "domain": b["company"]["domain"], "primary": b["primary"], "summary": b["summary"],
                    "verdicts": b["verdicts"], "lead": b["lead"], "spend": b["spend"]}

    return {"results": await asyncio.gather(*(one(q) for q in req.queries))}


@app.get("/api/recent")
def recent(limit: int = 25, key: Optional[str] = None, x_api_key: Optional[str] = Header(None, alias="X-Api-Key")):
    _check_key(key, x_api_key)
    return {"results": [{"domain": r["company"]["domain"], "primary": r["primary"], "lead": r["lead"]["score"],
                         "scanned_at": r["scanned_at"]} for r in cache.recent(limit)]}
