from .ct_logs import CertificateLogs
from .dns_hosting import DNSHosting
from .dns_records import DNSRecords
from .http_fingerprint import HTTPFingerprint
from .job_boards import JobBoards
from .trust_center import TrustCenter
from .status_page import StatusPage
from .github import GitHub

# Every source the engine runs. Remove a class to disable a source; add one to extend the platform.
REGISTRY = [CertificateLogs, DNSHosting, DNSRecords, HTTPFingerprint, JobBoards, TrustCenter, StatusPage, GitHub]

# Fast mode skips the slower public-data sources.
FAST = {"dns_hosting", "dns_records", "http_fingerprint"}
