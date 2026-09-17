"""Public job boards (Greenhouse, Lever, Ashby). Job posts name the stack a team runs and reveal hiring
for DevOps/SRE/platform/FinOps roles, which is also a buying signal."""
from __future__ import annotations

import asyncio

from .base import Collector
from ..models import Evidence, Signal
from ..net import get_json
from . import textscan as T


def normalize_greenhouse(data) -> list[dict]:
    return [{"title": j.get("title", ""), "text": T.plain(j.get("content", "")), "url": j.get("absolute_url"),
             "location": (j.get("location") or {}).get("name", "")} for j in (data or {}).get("jobs", [])]


def normalize_lever(data) -> list[dict]:
    out = []
    for j in data or []:
        parts = [j.get("descriptionPlain", ""), j.get("additionalPlain", "")]
        for lst in j.get("lists", []) or []:
            parts.append(T.plain(lst.get("content", "")))
        out.append({"title": j.get("text", ""), "text": " ".join(parts), "url": j.get("hostedUrl"),
                    "location": (j.get("categories") or {}).get("location", "")})
    return out


def normalize_ashby(data) -> list[dict]:
    return [{"title": j.get("title", ""), "text": j.get("descriptionPlain") or T.plain(j.get("descriptionHtml", "")),
             "url": j.get("jobUrl"), "location": j.get("location", "")} for j in (data or {}).get("jobs", [])]


BOARDS = [
    ("Greenhouse", "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true", normalize_greenhouse),
    ("Lever", "https://api.lever.co/v0/postings/{slug}?mode=json", normalize_lever),
    ("Ashby", "https://api.ashbyhq.com/posting-api/job-board/{slug}?includeCompensation=false", normalize_ashby),
]


def analyze_jobs(jobs: list[dict], board: str, source: str):
    """Turn normalized postings into evidence and signals. Pure function (unit tested)."""
    evidence, signals = [], []
    per_provider: dict[str, list[dict]] = {}
    role_counts = {"cloud_role": [], "finops_role": [], "data_role": []}
    cost_posts = []
    for j in jobs:
        text = f"{j['title']} {j['text']}"
        for prov, terms in T.providers_in(text).items():
            per_provider.setdefault(prov, []).append({**j, "terms": terms})
        for role in T.roles_in(j["title"]):
            role_counts[role].append(j)
        if T.mentions_cost(text):
            cost_posts.append(j)
    for prov, posts in per_provider.items():
        top = posts[0]
        # Never "strong": job text mentions a provider as often as a target/destination (a data or
        # integration company's postings routinely name every cloud its product connects to) as it
        # does the company's own hosting. Confirmation needs a technical source (DNS, HTTP, a trust
        # page) to corroborate.
        strength = "medium"
        evidence.append(Evidence(prov, strength, source,
                                 f"{len(posts)} open {board} role(s) mention {', '.join(top['terms'][:4])} — e.g. “{top['title']}”",
                                 top.get("url")))
    if role_counts["cloud_role"]:
        titles = "; ".join(j["title"] for j in role_counts["cloud_role"][:3])
        signals.append(Signal("hiring_cloud_role", f"Hiring {len(role_counts['cloud_role'])} infrastructure/DevOps role(s): {titles}",
                              source, min(3, len(role_counts["cloud_role"])) * 5, role_counts["cloud_role"][0].get("url")))
    if role_counts["finops_role"]:
        signals.append(Signal("hiring_finops_role", f"Hiring for cloud cost / FinOps: {role_counts['finops_role'][0]['title']}",
                              source, 20, role_counts["finops_role"][0].get("url")))
    if cost_posts:
        signals.append(Signal("cost_focus", f"{len(cost_posts)} job post(s) mention cloud cost work — e.g. “{cost_posts[0]['title']}”",
                              source, 10, cost_posts[0].get("url")))
    if jobs:
        signals.append(Signal("hiring_volume", f"{len(jobs)} open roles on {board}", source, 5 if len(jobs) >= 20 else 2))
    return evidence, signals


class JobBoards(Collector):
    name = "job_boards"
    stage = 1
    timeout = 40
    description = "Reads public job boards (Greenhouse, Lever, Ashby) for stack mentions and infrastructure hiring."

    async def collect(self, ctx, result):
        async def try_board(board, url_t, norm):
            for slug in ctx.slugs:
                data = await get_json(ctx.http, url_t.format(slug=slug))
                jobs = norm(data) if data else []
                if jobs:
                    return board, slug, jobs
            return None

        found = [f for f in await asyncio.gather(*(try_board(*b) for b in BOARDS)) if f]
        if not found:
            result.notes.append("No public Greenhouse, Lever or Ashby board found under the likely company slugs.")
            return
        for board, slug, jobs in found:
            ev, sig = analyze_jobs(jobs, board, self.name)
            result.evidence += ev
            result.signals += sig
            result.notes.append(f"{board} board '{slug}': {len(jobs)} open roles scanned.")
