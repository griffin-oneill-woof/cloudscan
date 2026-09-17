"""Fingerprints. Edit this file to teach the scanner new patterns — no code changes needed elsewhere."""

# Subdomains probed on every scan, with the role they usually play.
#   product -> the company's own app/API (strong evidence)
#   infra   -> CDN, buckets, dev/staging (medium evidence)
#   website -> marketing site, often a site builder (weak, not counted as confirmation)
SUBDOMAINS = {
    "": "website", "www": "website",
    "app": "product", "api": "product", "auth": "product", "login": "product", "portal": "product",
    "admin": "product", "platform": "product", "sso": "product", "console": "product", "dashboard": "product",
    "gateway": "product", "ws": "product", "account": "product", "accounts": "product", "my": "product",
    "graphql": "product", "backend": "product", "internal": "product",
    "staging": "infra", "dev": "infra", "beta": "infra", "cdn": "infra", "assets": "infra", "static": "infra",
    "media": "infra", "files": "infra", "upload": "infra", "uploads": "infra", "cloud": "infra", "data": "infra",
    "img": "infra", "images": "infra", "k8s": "infra", "grafana": "infra", "vpn": "infra",
}

# Hostname fragments (CNAME targets / PTR names) -> provider
HOST_SIGNATURES = [
    ("elb.amazonaws.com", "aws"), ("compute.amazonaws.com", "aws"), ("compute-1.amazonaws.com", "aws"),
    ("cloudfront.net", "aws"), ("s3-website", "aws"), ("s3.amazonaws.com", "aws"), ("execute-api", "aws"),
    ("elasticbeanstalk.com", "aws"), ("amplifyapp.com", "aws"), ("awsapprunner.com", "aws"),
    ("lambda-url", "aws"), ("amazonaws.com", "aws"),
    ("bc.googleusercontent.com", "gcp"), ("googleusercontent.com", "gcp"), ("appspot.com", "gcp"),
    ("run.app", "gcp"), ("firebaseapp.com", "gcp"), ("web.app", "gcp"), ("cloudfunctions.net", "gcp"),
    ("azurewebsites.net", "azure"), ("cloudapp.azure.com", "azure"), ("cloudapp.net", "azure"),
    ("trafficmanager.net", "azure"), ("azureedge.net", "azure"), ("azurefd.net", "azure"),
    ("azure-api.net", "azure"), ("azurestaticapps.net", "azure"), ("azurecontainerapps.io", "azure"),
    ("blob.core.windows.net", "azure"), ("windows.net", "azure"),
]

# Shared infrastructure that sits on a hyperscaler but says nothing about the company's own usage.
AMBIGUOUS_HOSTS = ["awsglobalaccelerator.com"]

# Third-party SaaS. If a host's chain passes through one of these, the host is excluded.
VENDOR_SIGNATURES = [
    ("vercel", "Vercel"), ("webflow", "Webflow"), ("hubspot", "HubSpot"), ("zendesk", "Zendesk"),
    ("statuspage", "Statuspage"), ("intercom", "Intercom"), ("auth0", "Auth0"), ("okta", "Okta"),
    ("gitbook", "GitBook"), ("mintlify", "Mintlify"), ("readme.io", "ReadMe"), ("netlify", "Netlify"),
    ("framer", "Framer"), ("squarespace", "Squarespace"), ("wpengine", "WP Engine"), ("wordpress", "WordPress"),
    ("herokuapp", "Heroku"), ("herokudns", "Heroku"), ("ghost.io", "Ghost"), ("helpscout", "Help Scout"),
    ("freshdesk", "Freshdesk"), ("unbounce", "Unbounce"), ("mktoweb", "Marketo"), ("pardot", "Pardot"),
    ("pages.dev", "Cloudflare Pages"), ("cloudflare", "Cloudflare"), ("fastly", "Fastly"), ("akamai", "Akamai"),
    ("edgekey", "Akamai"), ("edgesuite", "Akamai"), ("shopify", "Shopify"), ("wixdns", "Wix"),
    ("github.io", "GitHub Pages"), ("onrender", "Render"), ("render.com", "Render"), ("fly.dev", "Fly.io"),
    ("workos", "WorkOS"), ("clerk", "Clerk"), ("stytch", "Stytch"), ("frontegg", "Frontegg"),
    ("instatus", "Instatus"), ("betteruptime", "Better Uptime"), ("atlassian", "Atlassian"),
    ("force.com", "Salesforce"), ("customer.io", "Customer.io"), ("sendgrid", "SendGrid"), ("mailgun", "Mailgun"),
    ("ashbyhq", "Ashby"), ("greenhouse", "Greenhouse"), ("lever.co", "Lever"), ("workable", "Workable"),
    ("typeform", "Typeform"), ("notion.site", "Notion"),
]
EDGE_VENDORS = {"Cloudflare", "Cloudflare Pages", "Fastly", "Akamai"}

# Name servers -> provider (DNS hosted there; supporting evidence only)
NS_SIGNATURES = [("awsdns", "aws"), ("googledomains.com", "gcp"), ("azure-dns", "azure")]

# SPF includes / TXT records -> provider (weak: shows an account, not hosting)
TXT_SIGNATURES = [("amazonses.com", "aws"), ("_spf.google.com", None), ("spf.protection.outlook.com", None)]

# HTTP response headers -> provider. (header name, value fragment or None for "present")
HEADER_SIGNATURES = [
    ("x-amz-cf-id", None, "aws"), ("x-amz-cf-pop", None, "aws"), ("x-amz-request-id", None, "aws"),
    ("x-amzn-requestid", None, "aws"), ("x-amzn-trace-id", None, "aws"), ("x-amz-apigw-id", None, "aws"),
    ("server", "amazons3", "aws"), ("server", "awselb", "aws"), ("via", "cloudfront", "aws"),
    ("x-goog-generation", None, "gcp"), ("x-guploader-uploadid", None, "gcp"), ("x-cloud-trace-context", None, "gcp"),
    ("via", "1.1 google", "gcp"), ("server", "google frontend", "gcp"),
    ("x-azure-ref", None, "azure"), ("x-ms-request-id", None, "azure"), ("x-msedge-ref", None, "azure"),
    ("server", "microsoft-iis", "azure"), ("x-powered-by", "asp.net", None),
]
# Headers that mean the response came from a third-party edge, so provider headers above it are theirs.
VENDOR_HEADERS = [("x-vercel-id", "Vercel"), ("cf-ray", "Cloudflare"), ("x-served-by", "Fastly"), ("x-nf-request-id", "Netlify")]

# Text patterns found in job posts, trust pages, status pages and repos.
PROVIDER_TEXT = {
    "aws": [r"\bAWS\b", r"Amazon Web Services", r"\bEC2\b", r"\bEKS\b", r"\bS3\b", r"\bLambda\b", r"\bRDS\b",
            r"DynamoDB", r"CloudFormation", r"\bECS\b", r"Redshift"],
    "gcp": [r"\bGCP\b", r"Google Cloud", r"\bGKE\b", r"BigQuery", r"Cloud Run", r"Pub/Sub", r"Cloud Spanner", r"Firestore"],
    "azure": [r"\bAzure\b", r"\bAKS\b", r"Cosmos ?DB", r"Microsoft Cloud"],
}
# Trust / subprocessor pages name providers formally; these are the strings to look for there.
SUBPROCESSOR_TEXT = {
    "aws": [r"Amazon Web Services", r"\bAWS\b"],
    "gcp": [r"Google Cloud Platform", r"Google Cloud", r"\bGCP\b"],
    "azure": [r"Microsoft Azure", r"\bAzure\b"],
}

# Lead signals in job titles / descriptions.
ROLE_PATTERNS = {
    "cloud_role": r"\b(devops|site reliability|\bsre\b|platform engineer|infrastructure|cloud engineer|cloud architect|kubernetes)\b",
    "finops_role": r"\b(finops|cloud cost|cost optimi[sz]ation|cloud economics)\b",
    "data_role": r"\b(data engineer|ml engineer|machine learning engineer|mlops)\b",
}
COST_TEXT = r"(cloud cost|finops|cost optimi[sz]ation|reserved instances|savings plans?|committed use|spot instances|reduce (our )?(cloud|infrastructure) (spend|costs?))"
