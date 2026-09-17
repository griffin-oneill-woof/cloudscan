"""Name servers, SPF/TXT and MX records: supporting signals about which cloud accounts a company holds."""
from __future__ import annotations

from .base import Collector
from ..models import Evidence, Signal
from .. import signatures as S


class DNSRecords(Collector):
    name = "dns_records"
    stage = 1
    timeout = 20
    description = "Checks name servers (Route 53, Cloud DNS, Azure DNS) and SPF records (Amazon SES)."

    async def collect(self, ctx, result):
        ns = await ctx.dns.records(ctx.domain, "NS")
        found = {}
        for rec in ns:
            for frag, prov in S.NS_SIGNATURES:
                if frag in rec and prov not in found:
                    found[prov] = rec
        for prov, rec in found.items():
            result.evidence.append(Evidence(prov, "weak", self.name, f"DNS hosted on {prov.upper()} name servers ({rec.rstrip('.')})"))
        txt = await ctx.dns.records(ctx.domain, "TXT")
        joined = " ".join(txt)
        if "amazonses.com" in joined:
            result.evidence.append(Evidence("aws", "weak", self.name, "SPF record authorizes Amazon SES to send mail"))
        mx = " ".join(await ctx.dns.records(ctx.domain, "MX"))
        if "google.com" in mx:
            result.notes.append("Email on Google Workspace (not counted as cloud hosting).")
        elif "outlook.com" in mx:
            result.notes.append("Email on Microsoft 365 (not counted as cloud hosting).")
        if "atlassian-domain-verification" in joined:
            result.notes.append("Uses Atlassian products.")
        if any(t.startswith("stripe-verification") for t in txt):
            result.signals.append(Signal("payments", "Stripe domain verification present.", self.name, 0))
