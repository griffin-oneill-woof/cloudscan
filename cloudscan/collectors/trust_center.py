"""Subprocessor lists and trust/security pages. Companies with SOC 2 or GDPR obligations publish the
infrastructure vendors that process customer data, which names the hosting cloud outright."""
from __future__ import annotations

import asyncio
import re

from .base import Collector
from ..models import Evidence
from ..net import get_text
from . import textscan as T

PATHS = ["/subprocessors", "/sub-processors", "/legal/subprocessors", "/legal/sub-processors", "/trust/subprocessors",
         "/privacy/subprocessors", "/security", "/trust", "/legal/dpa", "/dpa"]
HOSTS = ["", "trust.", "security."]
# Words that suggest the page actually lists hosting vendors (vs. a marketing page that says "AWS integration").
CONTEXT = re.compile(r"(sub-?processor|hosting|infrastructure|data (center|centre)|cloud (service )?provider|processes? (customer )?data)", re.I)


def analyze_page(text: str, url: str, source: str) -> list[Evidence]:
    body = T.plain(text)
    if not CONTEXT.search(body):
        return []
    out = []
    for prov, terms in T.providers_in(body, formal=True).items():
        term = terms[0]
        is_list = bool(re.search(r"sub-?processor", body, re.I))
        out.append(Evidence(prov, "strong" if is_list else "medium", source,
                            f"{'Subprocessor list' if is_list else 'Trust/security page'} names {term}: {T.snippet(body, term)}", url))
    return out


class TrustCenter(Collector):
    name = "trust_center"
    stage = 1
    timeout = 40
    description = "Reads public subprocessor lists and trust pages, which name the hosting provider."

    async def collect(self, ctx, result):
        urls = [f"https://{h}{ctx.domain}{p}" for h in HOSTS for p in (PATHS if h == "" else ["/", "/subprocessors"])]
        sem = asyncio.Semaphore(6)

        async def fetch(url):
            async with sem:
                return url, await get_text(ctx.http, url)

        seen = set()
        for url, text in await asyncio.gather(*(fetch(u) for u in urls)):
            if not text:
                continue
            for ev in analyze_page(text, url, self.name):
                if ev.provider not in seen:
                    seen.add(ev.provider)
                    result.evidence.append(ev)
        if not seen:
            result.notes.append("No public subprocessor or trust page naming a cloud provider was found.")
