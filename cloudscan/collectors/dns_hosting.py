"""Follows each host's CNAME chain, reverse-DNS names and published IP ranges to the hosting provider."""
from __future__ import annotations

import asyncio

from .base import Collector
from ..models import Evidence, Signal
from .. import signatures as S

ROLE_STRENGTH = {"product": "strong", "infra": "medium", "website": "weak"}
PRODUCT_HINTS = ("api", "app", "prod", "console", "dashboard", "portal", "auth", "login", "gateway", "backend")


def classify_chain(names: list[str], domain: str):
    """Return ('vendor', label) | ('provider', key, name) | ('ambiguous', name) | None for a list of hostnames."""
    foreign = [n for n in names if not n.endswith(domain)]
    for n in foreign:
        for frag, label in S.VENDOR_SIGNATURES:
            if frag in n:
                return ("vendor", label, n)
    for n in foreign:
        for frag in S.AMBIGUOUS_HOSTS:
            if frag in n:
                return ("ambiguous", n, n)
        for frag, prov in S.HOST_SIGNATURES:
            if frag in n:
                return ("provider", prov, n)
    return None


def role_for(host: str, domain: str) -> str:
    sub = host[: -len(domain)].rstrip(".")
    if sub in S.SUBDOMAINS:
        return S.SUBDOMAINS[sub]
    first = sub.split(".")[0] if sub else ""
    if any(h in first for h in PRODUCT_HINTS):
        return "product"
    return "infra"


class DNSHosting(Collector):
    name = "dns_hosting"
    stage = 1
    timeout = 90
    description = "Resolves product, infrastructure and website hosts to AWS, Google Cloud or Azure."

    async def collect(self, ctx, result):
        await ctx.ipranges.load(ctx.http)
        hosts = {(f"{s}.{ctx.domain}" if s else ctx.domain) for s in S.SUBDOMAINS} | set(ctx.hosts)
        vendors_seen = set()

        async def check(host):
            res = await ctx.dns.resolve(host)
            if not res:
                return
            role = role_for(host, ctx.domain)
            hit = classify_chain(res.chain, ctx.domain)
            target = res.chain[-1] if res.chain else (res.ips[0] if res.ips else "")
            if not hit:
                for ip in res.ips[:2]:
                    ptr = await ctx.dns.ptr(ip)
                    hit = classify_chain(ptr, ctx.domain)
                    if hit:
                        target = f"{ip} ({hit[2]})"
                        break
                    rng = ctx.ipranges.match(ip)
                    if rng:
                        hit = ("provider", rng[0], rng[1])
                        target = f"{ip} ({rng[0].upper()} {rng[1]})"
                        break
            if not hit:
                return
            if hit[0] == "vendor":
                vendors_seen.add(hit[1])
                result.notes.append(f"{host} is served by {hit[1]} (excluded)")
            elif hit[0] == "provider":
                result.evidence.append(Evidence(
                    provider=hit[1], strength=ROLE_STRENGTH[role], source=self.name,
                    detail=f"{host} → {target} [{role}]"))

        await asyncio.gather(*(check(h) for h in hosts))
        result.notes.append(f"{len(hosts)} hosts checked.")
        edge = vendors_seen & S.EDGE_VENDORS
        if edge:
            result.signals.append(Signal("edge_masked", f"Some hosts sit behind {', '.join(sorted(edge))}, which hides the origin cloud.", self.name, 0))
        ctx.options["hosts_checked"] = len(hosts)
