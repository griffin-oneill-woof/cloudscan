"""Command line.
  python -m cloudscan scan acme.com            one company, readable output
  python -m cloudscan scan "Acme Robotics" --json
  python -m cloudscan batch in.csv out.csv     column "domain" or "company"; --full for all sources
  python -m cloudscan serve                    web UI + API on http://localhost:8000
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys

from .engine import scan
from .models import PROVIDER_LABELS


def print_report(r: dict):
    c = r["company"]
    print(f"\n{c.get('name') or c['domain']}  ({c['domain']})")
    print("=" * 60)
    print(r["summary"])
    for v in r["verdicts"]:
        print(f"  {PROVIDER_LABELS[v['provider']]:<13} {v['confidence']:<10} score {v['score']}  ({v['evidence_count']} observations)")
    print(f"\nLead score {r['lead']['score']}/100 (grade {r['lead']['grade']})")
    for f in r["lead"]["factors"]:
        print(f"  {f}")
    print("\nEvidence")
    for e in r["evidence"]:
        print(f"  [{e['strength']:<6}] {e['provider'].upper():<5} {e['source']:<16} {e['detail']}")
    if r["signals"]:
        print("\nPublic lead signals")
        for s in r["signals"]:
            print(f"  - {s['detail']}" + (f"  <{s['url']}>" if s.get("url") else ""))
    print("\nSources")
    for col in r["collectors"]:
        status = col["error"] or f"{col['evidence']} evidence, {col['signals']} signals"
        print(f"  {col['name']:<16} {col['duration_ms']:>6} ms  {status}")


async def run_batch(src: str, dst: str, fast: bool, concurrency: int):
    with open(src, newline="") as f:
        rows = list(csv.DictReader(f))
    key = next((k for k in ("domain", "website", "company", "name") if rows and k in rows[0]), None)
    if not key:
        sys.exit("Input CSV needs a 'domain', 'website', 'company' or 'name' column.")
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(row):
        nonlocal done
        async with sem:
            try:
                r = await scan(row[key], fast=fast)
            except Exception as exc:
                r = {"error": str(exc)}
        done += 1
        print(f"[{done}/{len(rows)}] {row[key]}", file=sys.stderr)
        out = dict(row)
        if "error" in r:
            out.update(cloud_primary="", cloud_summary=r.get("message", r["error"]))
            return out
        out.update(
            scanned_domain=r["company"]["domain"], cloud_primary=r["primary"] or "",
            aws=next((v["confidence"] for v in r["verdicts"] if v["provider"] == "aws"), ""),
            gcp=next((v["confidence"] for v in r["verdicts"] if v["provider"] == "gcp"), ""),
            azure=next((v["confidence"] for v in r["verdicts"] if v["provider"] == "azure"), ""),
            lead_score=r["lead"]["score"], lead_grade=r["lead"]["grade"], cloud_summary=r["summary"],
            top_evidence=" | ".join(e["detail"] for e in r["evidence"][:3]),
            lead_signals=" | ".join(s["detail"] for s in r["signals"][:3]),
        )
        return out

    results = await asyncio.gather(*(one(r) for r in rows))
    fields = list(dict.fromkeys(k for r in results for k in r))
    with open(dst, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(results)
    print(f"Wrote {len(results)} rows to {dst}", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cloudscan", description="Find which cloud any company runs on, from public data.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("query")
    s.add_argument("--fast", action="store_true", help="DNS and headers only (seconds, not a minute)")
    s.add_argument("--json", action="store_true")
    b = sub.add_parser("batch")
    b.add_argument("input")
    b.add_argument("output")
    b.add_argument("--full", action="store_true", help="also read job boards, trust pages, status pages, GitHub")
    b.add_argument("--concurrency", type=int, default=4)
    v = sub.add_parser("serve")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    a = p.parse_args(argv)

    if a.cmd == "scan":
        r = asyncio.run(scan(a.query, fast=a.fast))
        if "error" in r:
            sys.exit(r["message"])
        print(json.dumps(r, indent=2) if a.json else "", end="")
        if not a.json:
            print_report(r)
    elif a.cmd == "batch":
        asyncio.run(run_batch(a.input, a.output, fast=not a.full, concurrency=a.concurrency))
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("cloudscan.api:app", host=a.host, port=a.port)


if __name__ == "__main__":
    main()
