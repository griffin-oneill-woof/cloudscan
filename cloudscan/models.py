"""Core data types shared by every collector, the engine and the API."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

PROVIDERS = ("aws", "gcp", "azure")
PROVIDER_LABELS = {"aws": "AWS", "gcp": "Google Cloud", "azure": "Azure"}

# How much a single piece of evidence counts toward a provider verdict.
STRENGTH_WEIGHT = {"strong": 5, "medium": 2, "weak": 1}


@dataclass
class Evidence:
    """One observation that a company uses a cloud provider."""
    provider: str            # aws | gcp | azure
    strength: str            # strong | medium | weak
    source: str              # collector name, e.g. "dns_hosting"
    detail: str              # human-readable explanation
    url: Optional[str] = None


@dataclass
class Signal:
    """A lead/buying signal that isn't itself proof of a provider."""
    kind: str                # hiring_cloud_role | multi_cloud | cost_focus | ...
    detail: str
    source: str
    weight: int = 1
    url: Optional[str] = None


@dataclass
class CollectorResult:
    name: str
    evidence: list[Evidence] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    discovered_hosts: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: int = 0


@dataclass
class Company:
    query: str
    domain: str
    name: Optional[str] = None
    resolved_by: str = "input"        # input | apollo | guess
    employees: Optional[int] = None
    country: Optional[str] = None


@dataclass
class ProviderVerdict:
    provider: str
    score: int
    confidence: str                  # confirmed | likely | possible
    evidence_count: int


@dataclass
class LeadProfile:
    score: int                       # 0-100
    grade: str                       # A | B | C | D
    factors: list[str]


@dataclass
class SpendIntensity:
    """How much higher this company's cloud bill likely runs than headcount alone would suggest.
    A separate axis from LeadProfile on purpose: ICP-fit and infra-cost-intensity are different
    questions — a 60-person ML company can be a weaker ICP fit (too small) yet a bigger bill than a
    500-person SaaS company with light infra, and a rep should see both, not one blended number."""
    level: str                       # low | medium | high | very high
    score: int                       # 0-100, informational — not merged into LeadProfile.score
    factors: list[str]


@dataclass
class Report:
    company: Company
    verdicts: list[ProviderVerdict]
    primary: Optional[str]
    summary: str
    evidence: list[Evidence]
    signals: list[Signal]
    lead: LeadProfile
    spend: SpendIntensity
    collectors: list[dict]
    scanned_at: str
    hosts_checked: int = 0

    def to_dict(self) -> dict:
        return asdict(self)
