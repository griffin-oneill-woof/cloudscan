"""Offline tests: parsers, classification and scoring. Run with `pytest`."""
import asyncio

import httpx

from cloudscan.collectors.ct_logs import parse_crtsh, rank_hosts, CertificateLogs
from cloudscan.collectors.dns_hosting import classify_chain, role_for, DNSHosting
from cloudscan.collectors.http_fingerprint import match_headers
from cloudscan.collectors.job_boards import analyze_jobs, normalize_greenhouse, normalize_lever, normalize_ashby
from cloudscan.collectors.status_page import analyze_status
from cloudscan.collectors.trust_center import analyze_page
from cloudscan.collectors.github import analyze_repos, GitHub
from cloudscan.collectors.base import ScanContext
from cloudscan.engine import build_verdicts, scan_company
from cloudscan.ipranges import IPRanges
from cloudscan.leads import estimate_spend_intensity, score_lead
from cloudscan.models import Company, Evidence, ProviderVerdict, Signal, CollectorResult
from cloudscan.net import Resolution, get_json_status
from cloudscan.resolver import normalize_domain


def test_normalize_domain():
    assert normalize_domain("https://www.Acme.com/pricing?x=1") == "acme.com"
    assert normalize_domain("app.acme.io") == "app.acme.io"
    assert normalize_domain("Acme Robotics") is None


def test_classify_chain_vendor_beats_provider():
    assert classify_chain(["cname.vercel-dns.com"], "acme.com")[0] == "vendor"
    assert classify_chain(["abc.cloudfront.net"], "acme.com") == ("provider", "aws", "abc.cloudfront.net")
    assert classify_chain(["x.bc.googleusercontent.com"], "acme.com")[1] == "gcp"
    assert classify_chain(["foo.azurefd.net"], "acme.com")[1] == "azure"
    assert classify_chain(["edge.acme.com"], "acme.com") is None
    assert classify_chain(["a1.awsglobalaccelerator.com"], "acme.com")[0] == "ambiguous"


def test_roles():
    assert role_for("app.acme.com", "acme.com") == "product"
    assert role_for("cdn.acme.com", "acme.com") == "infra"
    assert role_for("acme.com", "acme.com") == "website"
    assert role_for("api-prod-eu.acme.com", "acme.com") == "product"


def test_crtsh_parsing():
    rows = [{"name_value": "*.acme.com\napi.acme.com"}, {"name_value": "mail.acme.com"}, {"name_value": "grafana.internal.acme.com"},
            {"name_value": "other.com"}]
    hosts = parse_crtsh(rows, "acme.com")
    assert hosts == {"api.acme.com", "grafana.internal.acme.com"}
    assert rank_hosts(hosts)[0] == "api.acme.com"


def test_headers():
    vendor, hits = match_headers({"X-Amz-Cf-Id": "abc", "Via": "1.1 abc.cloudfront.net (CloudFront)"})
    assert vendor is None and {p for p, _ in hits} == {"aws"}
    vendor, hits = match_headers({"x-vercel-id": "iad1", "server": "AmazonS3"})
    assert vendor == "Vercel"
    assert match_headers({"x-azure-ref": "20240101"})[1][0][0] == "azure"


def test_job_boards():
    gh = normalize_greenhouse({"jobs": [
        {"title": "Senior Site Reliability Engineer", "content": "&lt;p&gt;We run on AWS (EKS, RDS) and care about cloud cost.&lt;/p&gt;", "absolute_url": "u1", "location": {"name": "NYC"}},
        {"title": "Platform Engineer", "content": "Terraform on AWS", "absolute_url": "u2"},
        {"title": "Account Executive", "content": "Sell our product", "absolute_url": "u3"},
    ]})
    ev, sig = analyze_jobs(gh, "Greenhouse", "job_boards")
    assert ev[0].provider == "aws" and ev[0].strength == "medium"
    kinds = {s.kind for s in sig}
    assert {"hiring_cloud_role", "cost_focus", "hiring_volume", "container_infra"} <= kinds


def test_job_boards_data_ml_signal():
    jobs = normalize_greenhouse({"jobs": [
        {"title": "ML Platform Engineer", "content": "Own our GPU training pipeline and Snowflake warehouse.", "absolute_url": "u1"},
    ]})
    _, sig = analyze_jobs(jobs, "Greenhouse", "job_boards")
    assert any(s.kind == "data_ml_infra" for s in sig)
    assert normalize_lever([{"text": "DevOps", "descriptionPlain": "GCP and GKE", "lists": [{"content": "<li>BigQuery</li>"}]}])[0]["text"]
    assert normalize_ashby({"jobs": [{"title": "FinOps Analyst", "descriptionPlain": "Azure spend"}]})[0]["title"] == "FinOps Analyst"


def test_trust_page():
    page = "<h1>Subprocessors</h1><table><tr><td>Amazon Web Services, Inc.</td><td>Cloud hosting</td></tr></table>"
    ev = analyze_page(page, "https://acme.com/subprocessors", "trust_center")
    assert ev[0].provider == "aws" and ev[0].strength == "strong"
    assert analyze_page("<p>Integrates with AWS!</p>", "u", "trust_center") == []


def test_status_page():
    comps = {"components": [{"name": "API (AWS us-east-1)"}, {"name": "Dashboard"}]}
    inc = {"incidents": [{"name": "Degraded", "incident_updates": [{"body": "Upstream Google Cloud issue"}]}]}
    ev = analyze_status(comps, inc, "https://status.acme.com", "status_page")
    assert {(e.provider, e.strength) for e in ev} == {("aws", "strong"), ("gcp", "medium")}


def test_github():
    repos = [{"name": "terraform-aws-infra", "description": "AWS infrastructure", "topics": ["terraform"], "html_url": "u"},
             {"name": "cdk-stacks", "description": "EKS clusters on AWS", "topics": [], "html_url": "u2"},
             {"name": "fork", "fork": True, "description": "GCP"}]
    ev, sig = analyze_repos(repos, "acme", "github")
    assert ev[0].provider == "aws" and ev[0].strength == "medium" and sig
    assert any(s.kind == "container_infra" for s in sig)


def test_verdicts_and_leads():
    ev = [Evidence("aws", "strong", "dns_hosting", "app"), Evidence("aws", "weak", "dns_records", "ns"),
          Evidence("gcp", "medium", "job_boards", "jobs"), Evidence("gcp", "weak", "github", "repo")]
    v = build_verdicts(ev)
    assert v[0].provider == "aws" and v[0].confidence == "confirmed"
    assert v[1].provider == "gcp" and v[1].confidence == "likely"
    lead = score_lead(v, ev, [], employees=200, country="United States")
    assert lead.score >= 70 and lead.grade == "A"


def test_spend_intensity_low_with_no_signals():
    v = [ProviderVerdict("aws", 12, "confirmed", 3)]
    spend = estimate_spend_intensity(v, [], [], hosts_checked=37)
    assert spend.level == "low" and spend.score == 0
    assert "no workload-intensity signals" in spend.factors[0]


def test_spend_intensity_container_and_data_ml_stack():
    v = [ProviderVerdict("aws", 12, "confirmed", 3)]
    signals = [Signal("container_infra", "K8s mentioned", "job_boards"), Signal("data_ml_infra", "GPU training", "job_boards")]
    spend = estimate_spend_intensity(v, [], signals, hosts_checked=37)
    assert spend.score == 50 and spend.level == "high"


def test_spend_intensity_multi_cloud_and_region_and_surface():
    v = [ProviderVerdict("aws", 12, "confirmed", 3), ProviderVerdict("gcp", 8, "likely", 2)]
    evidence = [Evidence("aws", "strong", "dns_hosting", "app.acme.com -> lb.us-east-1.elb.amazonaws.com"),
                Evidence("aws", "medium", "dns_hosting", "eu.acme.com -> lb.eu-west-1.elb.amazonaws.com")]
    spend = estimate_spend_intensity(v, evidence, [], hosts_checked=95)
    assert spend.score == 55  # 15 multi-cloud + 20 multi-region + 20 large surface
    assert any("multi-region" in f for f in spend.factors)
    assert any("multi-cloud" in f for f in spend.factors)


def test_spend_intensity_everything_hits_very_high_ceiling():
    v = [ProviderVerdict("aws", 12, "confirmed", 3), ProviderVerdict("gcp", 8, "likely", 2)]
    evidence = [Evidence("aws", "strong", "dns_hosting", "a.acme.com -> lb.us-east-1.elb.amazonaws.com"),
                Evidence("aws", "medium", "dns_hosting", "b.acme.com -> lb.eu-west-1.elb.amazonaws.com")]
    signals = [Signal("container_infra", "K8s", "job_boards"), Signal("data_ml_infra", "GPU", "job_boards")]
    spend = estimate_spend_intensity(v, evidence, signals, hosts_checked=95)
    assert spend.level == "very high" and spend.score == 100  # capped at 100, not 105


def test_ipranges():
    r = IPRanges()
    r.load_dict("aws", [("3.5.0.0/16", "S3 us-east-1")])
    assert r.match("3.5.1.2") == ("aws", "S3 us-east-1")
    assert r.match("8.8.8.8") is None


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_get_json_status():
    def handler(request):
        if "rate-limited" in str(request.url):
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json={"ok": True})

    async def run():
        async with mock_client(handler) as client:
            assert await get_json_status(client, "https://example.com/rate-limited") == (None, 429)
            assert await get_json_status(client, "https://example.com/ok") == ({"ok": True}, 200)

    asyncio.run(run())


def test_ct_logs_reports_rate_limit_distinctly():
    def rate_limited(request):
        return httpx.Response(429)

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    async def run():
        ctx = ScanContext(company=Company("acme.com", "acme.com"), dns=None, http=None, ipranges=None)
        async with mock_client(rate_limited) as client:
            ctx.http = client
            result = CollectorResult(name="ct_logs")
            await CertificateLogs().collect(ctx, result)
            assert "rate-limited" in result.notes[0] and not result.discovered_hosts
        async with mock_client(down) as client:
            ctx.http = client
            result = CollectorResult(name="ct_logs")
            await CertificateLogs().collect(ctx, result)
            assert "did not respond" in result.notes[0]

    asyncio.run(run())


def test_azure_url_resolved_from_landing_page(tmp_path, monkeypatch):
    landing_html = '<a href="https://download.microsoft.com/download/7/1/d/71d-guid/ServiceTags_Public_20260914.json" download>'

    def handler(request):
        if "microsoft.com" in str(request.url):
            return httpx.Response(200, text=landing_html)
        return httpx.Response(200, json={"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["20.1.2.0/24"]}}]})

    monkeypatch.setenv("CLOUDSCAN_CACHE_DIR", str(tmp_path))
    import importlib
    import cloudscan.ipranges as ipranges_mod
    importlib.reload(ipranges_mod)

    async def run():
        r = ipranges_mod.IPRanges()
        async with mock_client(handler) as client:
            url = await r._resolve_azure_url(client)
            assert url == "https://download.microsoft.com/download/7/1/d/71d-guid/ServiceTags_Public_20260914.json"

    asyncio.run(run())
    importlib.reload(ipranges_mod)  # restore CACHE_DIR for any test that runs after this one


def test_github_reports_rate_limit_instead_of_not_found():
    def handler(request):
        return httpx.Response(403, json={"message": "API rate limit exceeded"})

    async def run():
        ctx = ScanContext(company=Company("acme.com", "acme.com"), dns=None, http=None, ipranges=None)
        async with mock_client(handler) as client:
            ctx.http = client
            result = CollectorResult(name="github")
            await GitHub().collect(ctx, result)
            assert "rate limit" in result.notes[0]
            assert "No public GitHub organization" not in result.notes[0]

    asyncio.run(run())


class FakeDNS:
    table = {"app.acme.com": Resolution("app.acme.com", ["lb-1.us-east-1.elb.amazonaws.com"], ["3.5.1.2"]),
             "www.acme.com": Resolution("www.acme.com", ["proxy-ssl.webflow.com"], ["1.1.1.1"]),
             "api.acme.com": Resolution("api.acme.com", [], ["34.1.2.3"])}

    async def resolve(self, host):
        return self.table.get(host)

    async def ptr(self, ip):
        return {"34.1.2.3": ["3.2.1.34.bc.googleusercontent.com"]}.get(ip, [])

    async def records(self, name, rdtype):
        return []


def test_engine_end_to_end_offline():
    r = IPRanges()
    r.loaded = True
    import cloudscan.engine as eng
    eng._ipranges = r
    report = asyncio.run(scan_company(Company("acme.com", "acme.com"), dns=FakeDNS(), http=object(), collectors=[DNSHosting]))
    providers = {v.provider: v.confidence for v in report.verdicts}
    assert providers == {"aws": "confirmed", "gcp": "confirmed"}
    assert not any("webflow" in e.detail for e in report.evidence)
