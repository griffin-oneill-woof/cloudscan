"""Runs collectors in stages, merges their findings and produces a Report."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from .collectors import REGISTRY, FAST
from .collectors.base import ScanContext
from .ipranges import IPRanges
from .leads import score_lead
from .models import (PROVIDER_LABELS, STRENGTH_WEIGHT, CollectorResult, Company, Evidence, ProviderVerdict, Report)
from .net import DNS, http_client
from .resolver import resolve_company

PER_SOURCE_CAP = 8   # one source can't carry a verdict on its own through sheer volume

_ipranges = IPRanges()   # shared across scans; loaded once


def build_verdicts(evidence: list[Evidence]) -> list[ProviderVerdict]:
    per: dict[str, dict[str, int]] = {}
    strong: dict[str, bool] = {}
    counts: dict[str, int] = {}
    for e in evidence:
        per.setdefault(e.provider, {}).setdefault(e.source, 0)
        per[e.provider][e.source] = min(PER_SOURCE_CAP, per[e.provider][e.source] + STRENGTH_WEIGHT[e.strength])
        strong[e.provider] = strong.get(e.provider, False) or e.strength == "strong"
        counts[e.provider] = counts.get(e.provider, 0) + 1
    out = []
    for prov, sources in per.items():
        score = sum(sources.values())
        n_sources = len(sources)
        if strong[prov] or (score >= 7 and n_sources >= 2):
            conf = "confirmed"
        elif score >= 3:
            conf = "likely"
        else:
            conf = "possible"
        out.append(ProviderVerdict(prov, score, conf, counts[prov]))
    rank = {"confirmed": 0, "likely": 1, "possible": 2}
    return sorted(out, key=lambda v: (rank[v.confidence], -v.score))


def summarize(company: Company, verdicts: list[ProviderVerdict], signals) -> str:
    name = company.name or company.domain
    conf = [v for v in verdicts if v.confidence == "confirmed"]
    likely = [v for v in verdicts if v.confidence == "likely"]
    if conf:
        s = f"{name} runs on {' and '.join(PROVIDER_LABELS[v.provider] for v in conf)}."
        if likely:
            s += f" Also likely uses {', '.join(PROVIDER_LABELS[v.provider] for v in likely)}."
    elif likely:
        s = f"{name} likely uses {', '.join(PROVIDER_LABELS[v.provider] for v in likely)}, but no product host confirms it."
    elif verdicts:
        s = f"Only weak signs of {', '.join(PROVIDER_LABELS[v.provider] for v in verdicts)} for {name}."
    else:
        s = f"No public evidence of AWS, Google Cloud or Azure for {name}."
        if any(sig.kind == "edge_masked" for sig in signals):
            s += " Parts of the site sit behind a CDN that hides the origin."
    return s


async def _run(collector, ctx: ScanContext) -> CollectorResult:
    res = CollectorResult(name=collector.name)
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(collector.collect(ctx, res), timeout=collector.timeout)
    except asyncio.TimeoutError:
        res.error = f"timed out after {collector.timeout}s"
    except Exception as exc:  # a broken source must never break the scan
        res.error = f"{type(exc).__name__}: {exc}"
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res


async def scan_company(company: Company, fast: bool = False, only: set[str] | None = None,
                       dns: DNS | None = None, http=None, collectors=None) -> Report:
    dns = dns or DNS()
    own_http = http is None
    http = http or http_client()
    try:
        ctx = ScanContext(company=company, dns=dns, http=http, ipranges=_ipranges)
        classes = collectors or REGISTRY
        selected = [c() for c in classes if (not fast or c.name in FAST) and (not only or c.name in only)]
        results: list[CollectorResult] = []
        for stage in sorted({c.stage for c in selected}):
            batch = [c for c in selected if c.stage == stage]
            stage_results = await asyncio.gather(*(_run(c, ctx) for c in batch))
            for r in stage_results:
                ctx.hosts |= r.discovered_hosts
            results += stage_results
    finally:
        if own_http:
            await http.aclose()

    evidence = [e for r in results for e in r.evidence]
    # de-duplicate identical observations
    seen, uniq = set(), []
    for e in evidence:
        k = (e.provider, e.source, e.detail)
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    signals = [s for r in results for s in r.signals]
    verdicts = build_verdicts(uniq)
    primary = verdicts[0].provider if verdicts and verdicts[0].confidence != "possible" else None
    lead = score_lead(verdicts, uniq, signals, company.employees, company.country)
    order = {"strong": 0, "medium": 1, "weak": 2}
    return Report(
        company=company, verdicts=verdicts, primary=primary, summary=summarize(company, verdicts, signals),
        evidence=sorted(uniq, key=lambda e: (order[e.strength], e.provider, e.source)), signals=signals, lead=lead,
        collectors=[{"name": r.name, "evidence": len(r.evidence), "signals": len(r.signals), "notes": r.notes,
                     "error": r.error, "duration_ms": r.duration_ms} for r in results],
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hosts_checked=ctx.options.get("hosts_checked", 0),
    )


async def scan(query: str, fast: bool = False, only: set[str] | None = None) -> dict:
    """Resolve a domain/URL/company name and scan it. Returns a JSON-ready dict."""
    dns = DNS()
    async with http_client() as http:
        candidates = await resolve_company(query, dns, http)
        if not candidates:
            return {"error": "not_found", "message": f"Couldn't find a website for “{query}”. Try the company's domain instead."}
        report = await scan_company(candidates[0], fast=fast, only=only, dns=dns, http=http)
        body = report.to_dict()
        body["alternatives"] = [{"name": c.name, "domain": c.domain} for c in candidates[1:]]
        return body
