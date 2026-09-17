"""Network helpers: async DNS and a shared, polite HTTP client."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx

USER_AGENT = os.getenv("CLOUDSCAN_USER_AGENT", "cloudscan/1.0 (+public infrastructure research)")
DNS_TIMEOUT = float(os.getenv("CLOUDSCAN_DNS_TIMEOUT", "3"))
HTTP_TIMEOUT = float(os.getenv("CLOUDSCAN_HTTP_TIMEOUT", "8"))


@dataclass
class Resolution:
    host: str
    chain: list[str]     # CNAME targets in order, lowercased, no trailing dot
    ips: list[str]


class DNS:
    def __init__(self, nameservers: list[str] | None = None, concurrency: int = 30):
        self.r = dns.asyncresolver.Resolver()
        if nameservers:
            self.r.nameservers = nameservers
        elif os.getenv("CLOUDSCAN_NAMESERVERS"):
            self.r.nameservers = os.getenv("CLOUDSCAN_NAMESERVERS").split(",")
        self.r.timeout = DNS_TIMEOUT
        self.r.lifetime = DNS_TIMEOUT
        self.sem = asyncio.Semaphore(concurrency)

    async def _query(self, name, rdtype):
        async with self.sem:
            try:
                return await self.r.resolve(name, rdtype, raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError):
                return None

    async def resolve(self, host: str) -> Resolution | None:
        ans = await self._query(host, "A")
        if ans is None or ans.rrset is None:
            return None
        chain, ips = [], []
        for rrset in ans.response.answer:
            for item in rrset:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    chain.append(str(item.target).rstrip(".").lower())
                elif rrset.rdtype == dns.rdatatype.A:
                    ips.append(item.address)
        return Resolution(host, chain, ips)

    async def ptr(self, ip: str) -> list[str]:
        ans = await self._query(dns.reversename.from_address(ip), "PTR")
        if ans is None or ans.rrset is None:
            return []
        return [str(x).rstrip(".").lower() for x in ans]

    async def records(self, name: str, rdtype: str) -> list[str]:
        ans = await self._query(name, rdtype)
        if ans is None or ans.rrset is None:
            return []
        return [x.to_text().strip('"').lower() for x in ans]


def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html;q=0.9, */*;q=0.5"},
        timeout=HTTP_TIMEOUT,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


async def get_json_status(client: httpx.AsyncClient, url: str, **kw) -> tuple[dict | list | None, int | None]:
    """Like get_json, but also returns the HTTP status (None on a network-level failure) so a
    caller can tell "not found" apart from "rate limited" instead of treating both as silence."""
    try:
        r = await client.get(url, **kw)
    except httpx.HTTPError:
        return None, None
    if r.status_code != 200:
        return None, r.status_code
    try:
        return r.json(), 200
    except ValueError:
        return None, r.status_code


async def get_json(client: httpx.AsyncClient, url: str, **kw):
    data, _ = await get_json_status(client, url, **kw)
    return data


async def get_text(client: httpx.AsyncClient, url: str, max_bytes: int = 1_500_000, **kw):
    try:
        r = await client.get(url, **kw)
        if r.status_code != 200 or "text" not in r.headers.get("content-type", "text"):
            return None
        return r.text[:max_bytes]
    except httpx.HTTPError:
        return None
