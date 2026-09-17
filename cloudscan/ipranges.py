"""Match IP addresses against the address ranges each cloud provider publishes.

Catches hosts that point straight at an IP with no revealing reverse-DNS name.
Ranges are downloaded once and cached on disk for a day.
  AWS:   https://ip-ranges.amazonaws.com/ip-ranges.json
  GCP:   https://www.gstatic.com/ipranges/cloud.json
  Azure: the weekly "Service Tags" JSON. Microsoft reissues it under a new dated filename every
         week, but the download-confirmation page at AZURE_LANDING_URL is stable and embeds that
         week's direct link in its HTML — scrape it from there instead of requiring a human to
         find and set a new CLOUDSCAN_AZURE_RANGES_URL every week. CLOUDSCAN_AZURE_RANGES_URL /
         CLOUDSCAN_AZURE_RANGES_FILE still work and take priority, for a pinned mirror or an
         environment that can't reach microsoft.com.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from pathlib import Path

import httpx

CACHE_DIR = Path(os.getenv("CLOUDSCAN_CACHE_DIR", Path.home() / ".cache" / "cloudscan"))
TTL = 24 * 3600
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
AZURE_LANDING_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
AZURE_LINK_RE = re.compile(r"https://download\.microsoft\.com/download/[a-zA-Z0-9./-]+ServiceTags_Public_[0-9]+\.json")


class IPRanges:
    def __init__(self):
        self.nets: list[tuple[ipaddress.IPv4Network, str, str]] = []   # (network, provider, label)
        self.loaded = False

    # ---- loading -------------------------------------------------------
    async def load(self, client: httpx.AsyncClient):
        if self.loaded:
            return
        aws = await self._fetch(client, "aws.json", AWS_URL)
        if aws:
            for p in aws.get("prefixes", []):
                self._add(p.get("ip_prefix"), "aws", f"{p.get('service')} {p.get('region')}")
        gcp = await self._fetch(client, "gcp.json", GCP_URL)
        if gcp:
            for p in gcp.get("prefixes", []):
                self._add(p.get("ipv4Prefix"), "gcp", f"{p.get('service')} {p.get('scope')}")
        azure = None
        if os.getenv("CLOUDSCAN_AZURE_RANGES_FILE"):
            try:
                azure = json.loads(Path(os.environ["CLOUDSCAN_AZURE_RANGES_FILE"]).read_text())
            except (OSError, ValueError):
                azure = None
        else:
            azure_url = os.getenv("CLOUDSCAN_AZURE_RANGES_URL") or await self._resolve_azure_url(client)
            if azure_url:
                azure = await self._fetch(client, "azure.json", azure_url)
        if azure:
            for v in azure.get("values", []):
                name = v.get("name", "")
                if name in ("AzureCloud", "AzureFrontDoor.Frontend") or name.startswith("AzureCloud."):
                    for pfx in v.get("properties", {}).get("addressPrefixes", []):
                        self._add(pfx, "azure", name)
        # Most specific networks first so the best label wins.
        self.nets.sort(key=lambda n: n[0].prefixlen, reverse=True)
        self.loaded = True

    def load_dict(self, provider: str, prefixes: list[tuple[str, str]]):
        """Load ranges directly (used by tests and offline mode)."""
        for pfx, label in prefixes:
            self._add(pfx, provider, label)
        self.nets.sort(key=lambda n: n[0].prefixlen, reverse=True)
        self.loaded = True

    def _add(self, pfx, provider, label):
        if not pfx or ":" in pfx:
            return
        try:
            self.nets.append((ipaddress.ip_network(pfx, strict=False), provider, label))
        except ValueError:
            pass

    async def _fetch(self, client, fname, url):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = CACHE_DIR / fname
        if path.exists() and time.time() - path.stat().st_mtime < TTL:
            try:
                return json.loads(path.read_text())
            except ValueError:
                pass
        try:
            r = await client.get(url, timeout=30)
            if r.status_code == 200:
                path.write_text(r.text)
                return r.json()
        except (httpx.HTTPError, ValueError):
            pass
        if path.exists():  # stale beats nothing
            try:
                return json.loads(path.read_text())
            except ValueError:
                return None
        return None

    async def _resolve_azure_url(self, client) -> str | None:
        """Find this week's Service Tags JSON link on Microsoft's (stable) download page. Cached
        for a day like everything else here, so this costs one extra request per day, not per scan."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = CACHE_DIR / "azure_landing.html"
        html = None
        if path.exists() and time.time() - path.stat().st_mtime < TTL:
            try:
                html = path.read_text()
            except OSError:
                html = None
        if html is None:
            try:
                r = await client.get(AZURE_LANDING_URL, timeout=30)
                if r.status_code == 200:
                    html = r.text
                    path.write_text(html)
            except httpx.HTTPError:
                html = None
        if html is None and path.exists():  # stale beats nothing, same as _fetch
            try:
                html = path.read_text()
            except OSError:
                html = None
        m = AZURE_LINK_RE.search(html) if html else None
        return m.group(0) if m else None

    # ---- lookup --------------------------------------------------------
    def match(self, ip: str) -> tuple[str, str] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, provider, label in self.nets:
            if addr in net:
                return provider, label
        return None
