"""Turns whatever the user typed — a URL, a domain or a company name — into a domain to scan."""
from __future__ import annotations

import os
import re

import httpx

from .models import Company
from .net import DNS, get_text

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
GUESS_TLDS = [".com", ".io", ".ai", ".co", ".dev", ".app", ".tech", ".so", ".xyz"]
APOLLO_SEARCH = "https://api.apollo.io/api/v1/mixed_companies/search"
APOLLO_ENRICH = "https://api.apollo.io/api/v1/organizations/enrich"


def normalize_domain(raw: str) -> str | None:
    s = raw.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s).split("/")[0].split("?")[0].split("#")[0].split("@")[-1].split(":")[0]
    s = re.sub(r"^www\d?\.", "", s).rstrip(".")
    return s if DOMAIN_RE.match(s) else None


def slugify(name: str) -> str:
    n = re.sub(r"\b(inc|llc|ltd|corp|corporation|co|company|technologies|labs|hq|group)\b\.?", "", name.lower())
    return re.sub(r"[^a-z0-9]", "", n)


async def resolve_company(query: str, dns: DNS, http: httpx.AsyncClient) -> list[Company]:
    """Return candidate companies, best first. A plain domain returns exactly one."""
    domain = normalize_domain(query)
    if domain:
        c = Company(query=query, domain=domain)
        await _enrich(c, http)
        return [c]

    candidates: list[Company] = []
    key = os.getenv("APOLLO_API_KEY")
    if key:
        try:
            r = await http.post(APOLLO_SEARCH, headers={"X-Api-Key": key, "Content-Type": "application/json"},
                                json={"q_organization_name": query, "per_page": 5})
            if r.status_code == 200:
                for org in (r.json().get("organizations") or r.json().get("accounts") or [])[:5]:
                    d = normalize_domain(org.get("primary_domain") or org.get("website_url") or "")
                    if d:
                        candidates.append(Company(query=query, domain=d, name=org.get("name"), resolved_by="apollo",
                                                  employees=org.get("estimated_num_employees"), country=org.get("country")))
        except httpx.HTTPError:
            pass
    if candidates:
        return candidates

    # No directory: try the obvious domains and keep ones whose homepage title contains the name.
    slug = slugify(query)
    if not slug:
        return []
    words = re.sub(r"[^a-z0-9 ]", "", query.lower()).split()
    token = words[0] if words else slug
    unverified = []
    for tld in GUESS_TLDS:
        d = slug + tld
        if not await dns.resolve(d):
            continue
        page = await get_text(http, f"https://{d}/", max_bytes=200_000)
        title = re.search(r"<title[^>]*>(.*?)</title>", page or "", re.I | re.S)
        if title and token in title.group(1).lower():
            candidates.append(Company(query=query, domain=d, name=query.strip(), resolved_by="guess"))
        elif page is None:
            unverified.append(Company(query=query, domain=d, name=query.strip(), resolved_by="guess_unverified"))
    return candidates or unverified


async def _enrich(c: Company, http: httpx.AsyncClient):
    """Optional firmographics for lead scoring. Uses one Apollo credit per call, so it is opt-in."""
    key = os.getenv("APOLLO_API_KEY")
    if not key or os.getenv("CLOUDSCAN_APOLLO_ENRICH") != "1":
        return
    try:
        r = await http.get(APOLLO_ENRICH, params={"domain": c.domain}, headers={"X-Api-Key": key})
        org = (r.json() or {}).get("organization") if r.status_code == 200 else None
        if org:
            c.name = org.get("name") or c.name
            c.employees = org.get("estimated_num_employees")
            c.country = org.get("country")
    except (httpx.HTTPError, ValueError):
        pass
