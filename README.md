# CloudScan

Finds which cloud provider (AWS, Google Cloud or Azure) any company runs on, and surfaces public
buying/lead signals, all from open data. No scope limit to a fixed company list, unlike the earlier
"Cloud Stack Lookup" artifact — give CloudScan a domain, a URL, or a company name.

Every signal comes from data the company already publishes: DNS, certificate transparency logs,
HTTP response headers, public job boards, trust/subprocessor pages, status pages, and public GitHub
organizations. Nothing is scraped from private sources, and nothing about individual people is
collected — see **Limitations & ethics** below.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10+ (uses `X | Y` union types and `from __future__ import annotations`).

Copy `.env.example` to `.env` and fill in anything you want (everything has a default; see
**Environment variables**).

## CLI

```bash
# One company, human-readable
python -m cloudscan scan acme.com

# Same, but DNS + headers only (seconds, not a minute)
python -m cloudscan scan acme.com --fast

# Same, machine-readable
python -m cloudscan scan "Acme Robotics" --json

# A CSV of companies -> a CSV of results
# input needs a "domain", "website", "company" or "name" column
python -m cloudscan batch companies.csv results.csv
python -m cloudscan batch companies.csv results.csv --full --concurrency 8

# Web UI + API
python -m cloudscan serve
python -m cloudscan serve --host 0.0.0.0 --port 8000
```

`scan --fast` and `batch` (without `--full`) run only `dns_hosting`, `dns_records` and
`http_fingerprint` — the sources that don't depend on third-party APIs and finish in a couple of
seconds. The rest (`ct_logs`, `job_boards`, `trust_center`, `status_page`, `github`) add slower,
richer evidence and lead signals.

## Running the server

```bash
uvicorn cloudscan.api:app --port 8000
# or
python -m cloudscan serve --port 8000
```

Then open `http://localhost:8000/` for the web UI, or call the API directly.

## API endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` | Serves `web/index.html`. |
| `GET` | `/api/health` | `{"ok": true, "sources": [...]}` — the registered collectors. |
| `GET` | `/api/scan?q=&fast=&fresh=` | Scan one company. `q` is required (domain, URL or name). `fast=true` skips the slower sources. `fresh=true` bypasses the cache. Returns the full report (see below). 404 if the query can't be resolved to any company. |
| `POST` | `/api/batch` | Body: `{"queries": [...], "fast": true, "key": "..."}`. Runs up to `CLOUDSCAN_BATCH_CONCURRENCY` scans at once and returns a trimmed result per query (domain, primary provider, summary, verdicts, lead). |
| `GET` | `/api/recent?limit=25&key=` | The most recently cached reports, newest first. |

If `CLOUDSCAN_API_KEY` is set, every endpoint above (except `/` and `/api/health`) requires a
matching `X-Api-Key` header (preferred — it isn't captured in URLs, access logs or browser
history the way a query param is) or `?key=`, or it 401s. **Not set by default** — the server
prints a startup warning to stderr if it's missing, since without it anyone who can reach the
server can scan, spend your Apollo credits (if enrichment is on), and burn your GitHub rate
limit. Set it before this is reachable by anyone but you. The bundled web UI has an "API key"
field that remembers what you type (in that browser's `localStorage`) and sends it as the header.

CORS is closed by default (the bundled UI is same-origin and needs none of it) — set
`CLOUDSCAN_CORS` to a comma-separated list of allowed origins only if a separate frontend needs
to call this API directly from the browser.

### Report shape (`/api/scan`)

```jsonc
{
  "company": {"domain": "acme.com", "name": "Acme Robotics", "resolved_by": "input", "employees": 220, "country": "United States"},
  "verdicts": [{"provider": "aws", "score": 12, "confidence": "confirmed", "evidence_count": 3}],
  "primary": "aws",
  "summary": "Acme Robotics runs on AWS.",
  "evidence": [{"provider": "aws", "strength": "strong", "source": "dns_hosting", "detail": "app.acme.com → ...", "url": null}],
  "signals": [{"kind": "hiring_cloud_role", "detail": "Hiring 2 infrastructure/DevOps role(s): ...", "source": "job_boards", "weight": 10, "url": "..."}],
  "lead": {"score": 78, "grade": "A", "factors": ["+35 confirmed on AWS", "..."]},
  "collectors": [{"name": "dns_hosting", "evidence": 1, "signals": 0, "notes": ["42 hosts checked."], "error": null, "duration_ms": 1450}],
  "scanned_at": "2026-09-16T23:40:00+00:00",
  "hosts_checked": 42,
  "cached": false,
  "alternatives": [{"name": "Acme Robotics Inc", "domain": "acme.io"}]
}
```

`alternatives` is populated when the query was a company name that matched more than one candidate
domain (via Apollo, or the guess-and-verify fallback) — the web UI offers these as one-click
re-scans.

## Environment variables

See `.env.example` for the full list with defaults and comments. Briefly:

- **Resolution/enrichment**: `APOLLO_API_KEY`, `CLOUDSCAN_APOLLO_ENRICH`, `GITHUB_TOKEN`
- **Cache**: `CLOUDSCAN_CACHE_DIR`, `CLOUDSCAN_DB`, `CLOUDSCAN_CACHE_TTL`
- **Network**: `CLOUDSCAN_NAMESERVERS`, `CLOUDSCAN_DNS_TIMEOUT`, `CLOUDSCAN_HTTP_TIMEOUT`, `CLOUDSCAN_USER_AGENT`
- **Azure IP ranges**: works out of the box (auto-discovered from Microsoft's download page weekly); `CLOUDSCAN_AZURE_RANGES_URL` / `CLOUDSCAN_AZURE_RANGES_FILE` only needed to pin a specific URL or mirror
- **API server**: `CLOUDSCAN_API_KEY`, `CLOUDSCAN_CORS`, `CLOUDSCAN_BATCH_CONCURRENCY`
- **ICP / lead scoring**: `CLOUDSCAN_ICP_MIN_EMPLOYEES`, `CLOUDSCAN_ICP_MAX_EMPLOYEES`, `CLOUDSCAN_ICP_COUNTRIES`

## Adding a collector

A collector reads one public source and turns it into `Evidence` (a provider observation) and/or
`Signal` (a lead signal that isn't itself proof of a provider).

1. Create `cloudscan/collectors/your_source.py` subclassing `Collector` (see
   `collectors/base.py`):

   ```python
   from .base import Collector
   from ..models import Evidence

   class YourSource(Collector):
       name = "your_source"
       stage = 1          # lower stages run first; stage 0 (ct_logs) discovers hosts stage 1 uses
       timeout = 30        # seconds before the engine gives up on this collector
       description = "One line for /api/health."

       async def collect(self, ctx, result):
           # ctx.domain, ctx.company, ctx.dns, ctx.http, ctx.hosts (discovered by earlier stages),
           # ctx.slugs (likely job-board/GitHub account names) are all available.
           result.evidence.append(Evidence("aws", "medium", self.name, "human-readable detail", url=None))
           result.notes.append("what this source found, for the collectors status table")
   ```

2. Register it in `cloudscan/collectors/__init__.py`: import the class and add it to `REGISTRY`.
   Add it to `FAST` too if it's cheap enough for `--fast`/scan `fast=true`.
3. A broken collector never breaks a scan — the engine wraps every `collect()` call in a timeout
   and a catch-all, and records the failure in `collectors[].error` instead. Write to `result.notes`
   even when you find nothing, so `/api/health` and the UI's status table stay informative.
4. Add fixtures-based unit tests in `tests/test_cloudscan.py` for any parsing/classification logic,
   the same way `ct_logs`, `job_boards`, `trust_center` etc. are tested — those run offline with no
   network access.

## Limitations & ethics

- **Company-level only.** No scraping of individuals; every signal is about a company's public
  infrastructure or hiring, not people.
- **Public data only.** Everything read is already published: DNS records, certificate transparency
  logs, HTTP response headers, public job board listings, published trust/subprocessor pages,
  status pages, and public GitHub organizations. Nothing requires authentication or bypasses any
  access control.
- **Best-effort, not certainty.** A "confirmed" verdict means strong public evidence (the product
  itself resolves to the provider), not an audited fact. Third-party edges (Cloudflare, Fastly,
  Akamai, Vercel, etc.) can hide the real origin — when that happens CloudScan says so rather than
  guessing.
- **Polite by default.** Requests use a descriptive `CLOUDSCAN_USER_AGENT`, respect timeouts, and
  cache results (`CLOUDSCAN_CACHE_TTL`, a week by default) so the same company isn't re-hit on every
  page load. `CLOUDSCAN_BATCH_CONCURRENCY` caps how many companies are scanned at once.
- **Apollo enrichment costs credits and is opt-in** (`CLOUDSCAN_APOLLO_ENRICH=1`), separate from
  just having `APOLLO_API_KEY` set for name resolution.
- **Not for anything adversarial.** This is a sales/research tool for reading a company's own public
  footprint, not a reconnaissance or intrusion tool — it doesn't probe for vulnerabilities, doesn't
  authenticate as anyone, and doesn't touch anything non-public.
