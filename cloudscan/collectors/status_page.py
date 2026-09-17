"""Public status pages. Statuspage-hosted pages expose a JSON API whose components and incident history
often name the provider or region ("AWS us-east-1", "Google Cloud outage")."""
from __future__ import annotations

from .base import Collector
from ..models import Evidence
from ..net import get_json
from . import textscan as T


def analyze_status(components, incidents, url, source):
    texts = [c.get("name", "") + " " + (c.get("description") or "") for c in (components or {}).get("components", [])]
    comp_text = " ".join(texts)
    inc_text = " ".join((i.get("name", "") + " " + " ".join(u.get("body", "") for u in i.get("incident_updates", [])))
                        for i in (incidents or {}).get("incidents", []))
    out = []
    for prov, terms in T.providers_in(comp_text).items():
        out.append(Evidence(prov, "strong", source, f"Status page components reference {', '.join(terms[:3])}", url))
    have = {e.provider for e in out}
    for prov, terms in T.providers_in(inc_text).items():
        if prov not in have:
            out.append(Evidence(prov, "medium", source, f"Status page incident history mentions {', '.join(terms[:3])}", url))
    return out


class StatusPage(Collector):
    name = "status_page"
    stage = 1
    timeout = 25
    description = "Reads public status page components and incident history."

    async def collect(self, ctx, result):
        for base in (f"https://status.{ctx.domain}", f"https://{ctx.domain.split('.')[0]}.statuspage.io"):
            comps = await get_json(ctx.http, f"{base}/api/v2/components.json")
            if not comps:
                continue
            incidents = await get_json(ctx.http, f"{base}/api/v2/incidents.json")
            evidence = analyze_status(comps, incidents, base, self.name)
            result.evidence += evidence
            result.notes.append(f"Status page found at {base} ({len(comps.get('components', []))} components).")
            return
        result.notes.append("No Statuspage-style JSON status page found.")
