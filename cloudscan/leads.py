"""Scores how promising a company is as a cloud-cost prospect, from the evidence and public signals.

The weights are deliberately simple and live in one place; tune them to your ICP.
"""
from __future__ import annotations

import os
import re

from . import signatures as S
from .models import Evidence, LeadProfile, ProviderVerdict, Signal, SpendIntensity

ICP_MIN = int(os.getenv("CLOUDSCAN_ICP_MIN_EMPLOYEES", "50"))
ICP_MAX = int(os.getenv("CLOUDSCAN_ICP_MAX_EMPLOYEES", "500"))
ICP_COUNTRIES = {c.strip() for c in os.getenv("CLOUDSCAN_ICP_COUNTRIES", "United States,Canada").split(",")}

_REGION = re.compile(S.REGION_TEXT, re.I)
# Baseline host count with nothing discovered beyond the fixed subdomain probe list (see
# signatures.SUBDOMAINS) — thresholds below are calibrated above that floor so a big number means
# ct_logs actually found real extra infrastructure, not just the standard list.
SURFACE_HIGH = 90
SURFACE_ABOVE_AVERAGE = 60


def score_lead(verdicts: list[ProviderVerdict], evidence: list[Evidence], signals: list[Signal],
               employees: int | None = None, country: str | None = None) -> LeadProfile:
    score, factors = 0, []
    confirmed = [v for v in verdicts if v.confidence == "confirmed"]
    likely = [v for v in verdicts if v.confidence == "likely"]
    if confirmed:
        score += 35
        factors.append(f"+35 confirmed on {', '.join(v.provider.upper() for v in confirmed)}")
    elif likely:
        score += 20
        factors.append(f"+20 likely on {', '.join(v.provider.upper() for v in likely)}")
    if len(confirmed) + len(likely) >= 2:
        score += 10
        factors.append("+10 multi-cloud (more spend to optimize)")
    if any(e.source == "dns_hosting" and e.strength == "strong" for e in evidence):
        score += 10
        factors.append("+10 product runs directly on cloud infrastructure")

    by_kind: dict[str, list[Signal]] = {}
    for s in signals:
        by_kind.setdefault(s.kind, []).append(s)
    for kind, label, cap in [("hiring_cloud_role", "hiring infrastructure/DevOps", 15), ("hiring_finops_role", "hiring for FinOps / cloud cost", 20),
                             ("cost_focus", "job posts mention cloud cost work", 10), ("iac_public", "public infrastructure-as-code", 4),
                             ("hiring_volume", "actively hiring", 5)]:
        if kind in by_kind:
            pts = min(cap, max(s.weight for s in by_kind[kind]))
            if pts:
                score += pts
                factors.append(f"+{pts} {label}")

    if employees:
        if ICP_MIN <= employees <= ICP_MAX:
            score += 10
            factors.append(f"+10 {employees} employees (in ICP range)")
        else:
            score -= 10
            factors.append(f"−10 {employees} employees (outside {ICP_MIN}–{ICP_MAX})")
    if country:
        if country in ICP_COUNTRIES:
            score += 5
            factors.append(f"+5 based in {country}")
        else:
            score -= 5
            factors.append(f"−5 based in {country}")
    if "edge_masked" in by_kind and not confirmed:
        factors.append("note: hosts behind a CDN may hide the real provider")

    score = max(0, min(100, score))
    grade = "A" if score >= 70 else "B" if score >= 50 else "C" if score >= 30 else "D"
    return LeadProfile(score=score, grade=grade, factors=factors)


def estimate_spend_intensity(verdicts: list[ProviderVerdict], evidence: list[Evidence], signals: list[Signal],
                             hosts_checked: int = 0) -> SpendIntensity:
    """Employee count and traffic are decent baseline predictors of cloud spend, but they miss the
    biggest swings: a 60-person company running GPU training clusters can outspend a 500-person
    CRUD SaaS shop. This looks for the workload shapes that actually drive the bill — container
    orchestration, data/ML infrastructure, multi-region deployment, multi-cloud, and unusually
    large public infrastructure surface — none of which need a new data source, since every one of
    them is already visible in evidence/signals other collectors produced for the cloud verdict."""
    score, factors = 0, []
    by_kind: dict[str, list[Signal]] = {}
    for s in signals:
        by_kind.setdefault(s.kind, []).append(s)

    if "container_infra" in by_kind:
        score += 25
        factors.append("+25 container/Kubernetes infrastructure (EKS/GKE/AKS-scale workloads run well above typical VM costs)")
    if "data_ml_infra" in by_kind:
        score += 25
        factors.append("+25 data/ML infrastructure (data warehouses, streaming or model training are consistently the priciest line items on a cloud bill)")

    live_providers = {v.provider for v in verdicts if v.confidence in ("confirmed", "likely")}
    if len(live_providers) >= 2:
        score += 15
        factors.append("+15 multi-cloud (redundant infrastructure, typically more total spend)")

    regions = {m.group(0).lower() for e in evidence if e.source == "dns_hosting" for m in _REGION.finditer(e.detail)}
    if len(regions) >= 2:
        score += 20
        factors.append(f"+20 multi-region deployment ({', '.join(sorted(regions))})")

    if hosts_checked >= SURFACE_HIGH:
        score += 20
        factors.append(f"+20 large public infrastructure surface ({hosts_checked} hosts discovered)")
    elif hosts_checked >= SURFACE_ABOVE_AVERAGE:
        score += 10
        factors.append(f"+10 above-average infrastructure surface ({hosts_checked} hosts discovered)")

    score = max(0, min(100, score))
    level = "very high" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    if not factors:
        factors.append("no workload-intensity signals found publicly — spend is likely close to what headcount alone would suggest")
    return SpendIntensity(level=level, score=score, factors=factors)
