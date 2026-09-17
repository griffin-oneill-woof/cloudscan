"""Collector interface. A collector reads one public source and returns evidence and lead signals.

To add a source: subclass Collector, implement `collect`, and add the class to REGISTRY in
collectors/__init__.py. Collectors in an earlier `stage` run first, so their discovered hosts
(e.g. from certificate logs) are available to later stages.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from ..models import Company, CollectorResult
from ..net import DNS
from ..ipranges import IPRanges


@dataclass
class ScanContext:
    company: Company
    dns: DNS
    http: httpx.AsyncClient
    ipranges: IPRanges
    hosts: set[str] = field(default_factory=set)       # extra hosts discovered by earlier stages
    options: dict = field(default_factory=dict)

    @property
    def domain(self) -> str:
        return self.company.domain

    @property
    def slugs(self) -> list[str]:
        """Likely account names on job boards / GitHub: 'acme' from acme.com, 'acmeinc', 'acme-inc'."""
        stem = self.domain.split(".")[0]
        out = [stem]
        if self.company.name:
            n = self.company.name.lower()
            n = re.sub(r"\b(inc|llc|ltd|corp|co|technologies|labs|hq)\b\.?", "", n).strip()
            out += [re.sub(r"[^a-z0-9]", "", n), re.sub(r"[^a-z0-9]+", "-", n).strip("-")]
        out += [stem + "hq", stem + "inc", "get" + stem, "try" + stem]
        seen, uniq = set(), []
        for s in out:
            if s and s not in seen:
                seen.add(s)
                uniq.append(s)
        return uniq


class Collector:
    name = "base"
    stage = 1                 # lower runs earlier
    timeout = 45              # seconds before the engine gives up on this collector
    description = ""

    async def collect(self, ctx: ScanContext, result: CollectorResult) -> None:  # pragma: no cover
        raise NotImplementedError
