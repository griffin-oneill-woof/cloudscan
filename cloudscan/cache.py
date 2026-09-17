"""Tiny SQLite cache so repeated lookups are instant and public sources aren't hammered."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

DEFAULT_TTL = int(os.getenv("CLOUDSCAN_CACHE_TTL", str(7 * 24 * 3600)))


class Cache:
    def __init__(self, path: str | None = None):
        path = path or os.getenv("CLOUDSCAN_DB", str(Path.home() / ".cache" / "cloudscan" / "reports.sqlite"))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS reports (key TEXT PRIMARY KEY, created REAL, body TEXT)")
        self.db.commit()

    def get(self, key: str, ttl: int = DEFAULT_TTL):
        with self.lock:
            row = self.db.execute("SELECT created, body FROM reports WHERE key=?", (key,)).fetchone()
        if not row or time.time() - row[0] > ttl:
            return None
        return json.loads(row[1])

    def put(self, key: str, body: dict):
        with self.lock:
            self.db.execute("REPLACE INTO reports VALUES (?,?,?)", (key, time.time(), json.dumps(body)))
            self.db.commit()

    def recent(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT body FROM reports ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]
