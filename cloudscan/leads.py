"""Scores how promising a company is as a cloud-cost prospect, from the evidence and public signals.

The weights are deliberately simple and live in one place; tune them to your ICP.
"""
from __future__ import annotations

import os

from .models import Evidence, LeadProfile, ProviderVerdict, Signal

ICP_MIN = int(os.getenv("CLOUDSCAN_ICP_MIN_EMPLOYEES", "50"))
ICP_MAX = int(os.getenv("CLOUDSCAN_ICP_MAX_EMPLOYEES", "500"))
ICP_COUNTRIES = {c.strip() for c in os.getenv("CLOUDSCAN_ICP_COUNTRIES", "United States,Canada").split(",")}


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
