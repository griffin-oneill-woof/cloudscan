"""Reads response headers from the website and product endpoints (x-amz-cf-id, x-goog-*, x-azure-ref...)."""
from __future__ import annotations

import asyncio

import httpx

from .base import Collector
from ..models import Evidence
from .. import signatures as S

TARGETS = [("", "weak"), ("www", "weak"), ("app", "strong"), ("api", "strong"), ("console", "strong"), ("dashboard", "strong")]


def match_headers(headers: dict[str, str]):
    """Return (vendor or None, [(provider, header_string)])."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    vendor = next((label for name, label in S.VENDOR_HEADERS if name in h), None)
    hits = []
    for name, frag, prov in S.HEADER_SIGNATURES:
        if prov and name in h and (frag is None or frag in h[name]):
            hits.append((prov, f"{name}: {h[name][:60]}"))
    return vendor, hits


class HTTPFingerprint(Collector):
    name = "http_fingerprint"
    stage = 1
    timeout = 30
    description = "Inspects HTTP response headers from the site and product endpoints."

    async def collect(self, ctx, result):
        async def probe(sub, strength):
            host = f"{sub}.{ctx.domain}" if sub else ctx.domain
            try:
                r = await ctx.http.head(f"https://{host}/", follow_redirects=False)
                if r.status_code in (405, 501):
                    r = await ctx.http.get(f"https://{host}/", follow_redirects=False)
            except httpx.HTTPError:
                return
            vendor, hits = match_headers(dict(r.headers))
            if vendor:
                result.notes.append(f"https://{host} is served through {vendor}; its headers aren't attributed to the company.")
                return
            seen = set()
            for prov, header in hits:
                if prov in seen:
                    continue
                seen.add(prov)
                result.evidence.append(Evidence(prov, strength, self.name, f"https://{host} responded with {header}", f"https://{host}/"))

        await asyncio.gather(*(probe(s, st) for s, st in TARGETS))
