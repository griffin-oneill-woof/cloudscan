"""Certificate Transparency logs (crt.sh): every public TLS certificate lists the hostnames it covers,
so this reveals subdomains no wordlist would guess (api-prod-eu, grafana, customer-specific hosts...)."""
from __future__ import annotations

import re

from .base import Collector
from ..net import get_json_status

MAX_HOSTS = 120
NOISE = re.compile(r"(^\*\.|^mail\.|^autodiscover\.|^cpanel\.|^webmail\.|^www\d?\.)")


def parse_crtsh(rows, domain: str) -> set[str]:
    hosts = set()
    for row in rows or []:
        for name in str(row.get("name_value", "")).split("\n"):
            h = name.strip().lower().rstrip(".")
            if h.startswith("*."):
                h = h[2:]
            if not h.endswith(domain) or h == domain or NOISE.search(h) or " " in h or "@" in h:
                continue
            hosts.add(h)
    return hosts


def rank_hosts(hosts: set[str]) -> list[str]:
    """Prefer short, product-looking names; cap the list so scans stay fast."""
    keywords = ("api", "app", "prod", "console", "dashboard", "portal", "auth", "login", "gateway", "k8s", "eks", "gke", "aks")
    def score(h):
        return (0 if any(k in h for k in keywords) else 1, h.count("."), len(h))
    return sorted(hosts, key=score)[:MAX_HOSTS]


class CertificateLogs(Collector):
    name = "ct_logs"
    stage = 0
    # Stage 0 runs, and blocks, before every other collector starts (its discovered_hosts feed
    # them). crt.sh is a shared public resource that both runs slow (10-35s isn't unusual) and
    # rate-limits aggressively, so this stays well under the old 40s to bound how much one flaky
    # request can add to every single scan's latency, at the cost of occasionally missing the
    # extra subdomains it would have found — dns_hosting's fixed subdomain list still runs either way.
    timeout = 15
    description = "Discovers subdomains from public TLS certificate logs (crt.sh)."

    async def collect(self, ctx, result):
        rows, status = await get_json_status(ctx.http, "https://crt.sh/", params={"q": f"%.{ctx.domain}", "output": "json"}, timeout=12)
        if status == 429:
            result.notes.append("crt.sh rate-limited this request; continuing with the standard subdomain list.")
            return
        if rows is None:
            result.notes.append(f"crt.sh did not respond ({status or 'timeout'}); continuing with the standard subdomain list.")
            return
        hosts = rank_hosts(parse_crtsh(rows, ctx.domain))
        result.discovered_hosts.update(hosts)
        result.notes.append(f"{len(hosts)} subdomains discovered in certificate logs.")
