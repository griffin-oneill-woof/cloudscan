"""Public GitHub organizations. Infrastructure-as-code repos, SDK usage, topics and descriptions reveal
the cloud a team builds on. Set GITHUB_TOKEN to raise the rate limit and enable code search."""
from __future__ import annotations

import os

from .base import Collector
from ..models import Evidence, Signal
from ..net import get_json_status
from . import textscan as T

API = "https://api.github.com"
IAC_TERMS = {
    "aws": ['provider "aws"', "aws-cdk-lib", "boto3", "@aws-sdk", "serverless.yml"],
    "gcp": ['provider "google"', "google-cloud-", "@google-cloud/", "app.yaml"],
    "azure": ['provider "azurerm"', "azure-", "@azure/"],
}


def analyze_repos(repos, org, source):
    evidence, signals = [], []
    per = {}
    for r in repos or []:
        if r.get("fork"):
            continue
        text = " ".join([r.get("name", ""), r.get("description") or "", " ".join(r.get("topics") or [])])
        for prov, terms in T.providers_in(text).items():
            per.setdefault(prov, []).append((r, terms))
        low = text.lower()
        if any(k in low for k in ("terraform", "kubernetes", "helm", "k8s", "pulumi")):
            signals.append(Signal("iac_public", f"Public infrastructure repo: {r.get('name')}", source, 2, r.get("html_url")))
    for prov, hits in per.items():
        r, terms = hits[0]
        evidence.append(Evidence(prov, "medium" if len(hits) >= 2 else "weak", source,
                                 f"{len(hits)} public repo(s) in github.com/{org} reference {', '.join(terms[:3])} — e.g. {r.get('name')}",
                                 r.get("html_url")))
    return evidence, signals[:3]



# GitHub returns 403 (occasionally 429) once the calling IP/token has exhausted its rate limit —
# unauthenticated requests get only 60/hour total, shared across every scan run against this host,
# so a team deployment without GITHUB_TOKEN exhausts it after a handful of scans.
RATE_LIMITED = (403, 429)


class GitHub(Collector):
    name = "github"
    stage = 1
    timeout = 30
    description = "Looks through the company's public GitHub organization for cloud-specific code and topics."

    async def collect(self, ctx, result):
        token = os.getenv("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        hint = "" if token else " Set GITHUB_TOKEN to raise GitHub's 60/hour unauthenticated limit."

        org = None
        for slug in ctx.slugs[:4]:
            info, status = await get_json_status(ctx.http, f"{API}/orgs/{slug}", headers=headers)
            if status in RATE_LIMITED:
                # Distinct from "no org found": we never actually got to check, so don't imply we did.
                result.notes.append(f"GitHub API rate limit hit while looking up the org.{hint}")
                return
            if info and info.get("blog") and ctx.domain in (info.get("blog") or "").lower():
                org = slug
                break
            if info and not org and info.get("public_repos", 0) > 0 and (info.get("email") or "").endswith(ctx.domain):
                org = slug
                break
        if not org:
            result.notes.append("No public GitHub organization linked to this domain was found.")
            return

        repos, status = await get_json_status(ctx.http, f"{API}/orgs/{org}/repos", params={"per_page": 100, "sort": "pushed"}, headers=headers)
        if status in RATE_LIMITED:
            result.notes.append(f"GitHub org '{org}' found, but hit the API rate limit before its repos could be read.{hint}")
            return
        ev, sig = analyze_repos(repos, org, self.name)
        result.evidence += ev
        result.signals += sig
        if token:
            for prov, terms in IAC_TERMS.items():
                if any(e.provider == prov and e.strength != "weak" for e in result.evidence):
                    continue
                q = " OR ".join(f'"{t}"' for t in terms[:2]) + f" org:{org}"
                data, status = await get_json_status(ctx.http, f"{API}/search/code", params={"q": q, "per_page": 5}, headers=headers)
                if status in RATE_LIMITED:
                    result.notes.append("GitHub code search rate limit hit; stopped early.")
                    break
                items = (data or {}).get("items", [])
                if items:
                    it = items[0]
                    result.evidence.append(Evidence(prov, "strong", self.name,
                                                    f"Public code in {it['repository']['full_name']} uses {prov.upper()} tooling ({it['path']})",
                                                    it.get("html_url")))
        result.notes.append(f"GitHub org '{org}': {len(repos or [])} public repos scanned.")
