"""
Configuration constants, feature flags, and threat intelligence lists.
Comprehensive lists for general-purpose phishing detection.
"""

import os

# ── Feature flags ────────────────────────────────────────────────
API_KEY = os.getenv("VT_API_KEY")
VT_AVAILABLE = bool(API_KEY)

URL_SCAN_API_KEY = os.getenv("URL_SCAN_API_KEY")
URLSCAN_AVAILABLE = bool(URL_SCAN_API_KEY)

try:
    import whois  # noqa: F401
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import pdfplumber  # noqa: F401
    import docx  # noqa: F401
    ATTACHMENT_PARSING_AVAILABLE = True
except ImportError:
    ATTACHMENT_PARSING_AVAILABLE = False

try:
    from PIL import Image  # noqa: F401
    from pyzbar.pyzbar import decode as qr_decode  # noqa: F401
    import pytesseract  # noqa: F401
    IMAGE_SCANNING_AVAILABLE = True
except ImportError:
    IMAGE_SCANNING_AVAILABLE = False

try:
    import tldextract  # noqa: F401
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from oletools.olevba import VBA_Parser  # noqa: F401
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False



__all__ = [
    'API_KEY', 'VT_AVAILABLE', 'URL_SCAN_API_KEY', 'URLSCAN_AVAILABLE',
    'WHOIS_AVAILABLE', 'ATTACHMENT_PARSING_AVAILABLE', 'IMAGE_SCANNING_AVAILABLE',
    'TLDEXTRACT_AVAILABLE', 'OLETOOLS_AVAILABLE',
    'WEIGHTS', 'SETTINGS', 'ABUSED_LEGIT_SERVICES',
    'FINANCIAL_KEYWORDS', 'CREDENTIAL_KEYWORDS', 'URGENCY_KEYWORDS', 'SOCIAL_KEYWORDS',
    'PHISHING_THEMES',
    'IMPERSONATED_BRANDS', 'BRAND_DOMAINS',
    'RISKY_EXTENSIONS', 'RISKY_EXTENSIONS_SET',
    'SHORTENERS', 'REDIRECT_PARAM_NAMES', 'REFERENCE_URL_HOSTS', 'SUSPICIOUS_TLDS',
]

# ── Scoring weights ──────────────────────────────────────────────
WEIGHTS = {
    "mismatch_return_path": 2,
    "mismatch_reply_to": 2,
    "dmarc_fail": 7,
    "dmarc_weak_or_missing": 1,
    "spf_fail": 2,
    "spf_not_found": 1,
    "dkim_fail": 2,
    "dkim_not_found": 1,
    "auth_alignment_mismatch": 3,
    "compauth_fail": 3,
    "display_name_domain_mismatch": 4,
    "brand_impersonation": 3,
    "homograph_attack": 5,
    "malicious_link": 3,
    "malicious_domain": 4,
    "malicious_ip": 3,
    "malicious_attachment": 10,
    "suspicious_attachment": 4,
    "deceptive_link": 3,
    "suspicious_url_feature": 2,
    "abused_service_link": 2,
    "recent_domain": 5,
    "javascript_present": 2,
    "credential_form": 4,
    "urgent_keywords": 1,
    "high_risk_keywords": 4,
    "impersonation_keywords": 3,
}

SETTINGS = {
    "domain_age_threshold_days": 90,
    "default_vt_delay_seconds": 16,
    "default_max_vt_items": 40,
    "vt_request_timeout_seconds": 20,
    "urlscan_request_timeout_seconds": 15,
    "urlscan_poll_timeout_seconds": 10,
    "unshorten_timeout_seconds": 10,
}

# ── Threat intelligence lists ────────────────────────────────────
ABUSED_LEGIT_SERVICES = [
    "docs.google.com", "drive.google.com", "onedrive.live.com",
    "dropbox.com", "forms.gle", "1drv.ms", "sharepoint.com",
    "storage.googleapis.com", "github.io", "pages.dev", "workers.dev",
    "firebaseapp.com", "web.app", "surge.sh", "netlify.app",
    "vercel.app", "herokuapp.com", "glitch.me", "notion.site",
    "canva.com", "mailchi.mp", "sendgrid.net", "mailgun.org",
]

# ── Keywords: financial & payment ────────────────────────────────
FINANCIAL_KEYWORDS = [
    "wire transfer", "wire funds", "bank transfer", "bank account",
    "routing number", "account number", "swift code", "iban",
    "gift card", "gift cards", "itunes card", "google play card",
    "crypto", "bitcoin", "ethereum", "cryptocurrency", "wallet address",
    "urgent payment", "immediate payment", "payment overdue",
    "payroll", "direct deposit", "ach transfer", "zelle", "venmo",
    "invoice", "invoice attached", "payment due", "outstanding balance",
    "refund", "tax refund", "stimulus", "compensation",
    "inheritance", "lottery", "prize", "reward", "compensation fund",
]

# ── Keywords: credential theft ───────────────────────────────────
CREDENTIAL_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "validate your account", "re-verify", "account suspended",
    "account locked", "account will be closed", "unusual activity",
    "suspicious sign-in", "unauthorized access", "security alert",
    "password expired", "password reset", "change your password",
    "login here", "sign in here", "click to verify", "click here to confirm",
    "update your payment", "update your billing", "expired card",
    "confirm your email", "verify your email", "validate your email",
]

# ── Keywords: urgency & pressure ─────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "act fast", "right away",
    "within 24 hours", "within 48 hours", "expires today", "expires soon",
    "limited time", "time sensitive", "deadline", "final notice",
    "last warning", "final reminder", "do not ignore", "failure to",
    "you must", "you are required", "mandatory", "compulsory",
    "dear customer", "dear user", "dear valued", "dear account holder",
    "attention required", "action required", "immediate action",
]

# ── Keywords: social engineering ─────────────────────────────────
SOCIAL_KEYWORDS = [
    "congratulations", "you have been selected", "you have won",
    "exclusive offer", "special offer", "limited offer",
    "confidential", "do not share", "keep this private",
    "trusted partner", "verified sender", "secure message",
    "encrypted message", "protected document", "secure document",
    "shared a document", "shared a file", "has shared",
    "review the attached", "see attached", "please find attached",
    "download here", "view document", "access document",
    "candidate", "application", "resume", "cv", "job offer",
    "employment", "hiring", "onboarding", "interview",
    "shipment", "delivery", "tracking", "package", "fedex", "ups", "dhl",
    "receipt", "order confirmation", "purchase", "transaction",
]

# ── Phishing theme categories for pattern detection ──────────────
PHISHING_THEMES = {
    "financial": FINANCIAL_KEYWORDS,
    "credential_theft": CREDENTIAL_KEYWORDS,
    "urgency_pressure": URGENCY_KEYWORDS,
    "social_engineering": SOCIAL_KEYWORDS,
}

# ── Impersonated brands ─────────────────────────────────────────
IMPERSONATED_BRANDS = [
    "microsoft", "office 365", "outlook", "teams", "azure",
    "paypal", "venmo", "zelle", "cashapp",
    "amazon", "aws", "prime",
    "apple", "icloud", "itunes",
    "google", "gmail", "google drive", "google docs",
    "facebook", "instagram", "whatsapp", "meta",
    "docusign", "adobe", "dropbox", "box",
    "netflix", "spotify", "hulu", "disney",
    "coinbase", "binance", "kraken", "opensea",
    "github", "gitlab", "bitbucket",
    "linkedin", "twitter", "x",
    "chase", "wells fargo", "bank of america", "citibank", "hsbc",
    "fedex", "ups", "dhl", "usps", "royal mail",
    "zoom", "slack", "shopify", "stripe", "square",
    "irs", "hmrc", "cra", "ato", "social security",
]

BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "office 365": ["microsoft.com", "office.com"],
    "outlook": ["outlook.com", "hotmail.com", "live.com", "microsoft.com"],
    "teams": ["teams.microsoft.com", "microsoft.com"],
    "azure": ["azure.com", "microsoft.com", "windowsazure.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "cashapp": ["cash.app"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "aws": ["aws.amazon.com", "amazon.com"],
    "prime": ["amazon.com", "primevideo.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com"],
    "icloud": ["icloud.com", "apple.com"],
    "itunes": ["itunes.com", "apple.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "gmail": ["gmail.com", "googlemail.com", "google.com"],
    "google drive": ["drive.google.com", "google.com"],
    "google docs": ["docs.google.com", "google.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com"],
    "instagram": ["instagram.com", "facebook.com"],
    "whatsapp": ["whatsapp.com", "facebook.com"],
    "meta": ["meta.com", "facebook.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
    "box": ["box.com"],
    "netflix": ["netflix.com"],
    "spotify": ["spotify.com"],
    "hulu": ["hulu.com"],
    "disney": ["disneyplus.com", "disney.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "kraken": ["kraken.com"],
    "opensea": ["opensea.io"],
    "github": ["github.com", "github.io"],
    "gitlab": ["gitlab.com"],
    "bitbucket": ["bitbucket.org"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "x": ["x.com", "twitter.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
    "usps": ["usps.com"],
    "royal mail": ["royalmail.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com"],
    "shopify": ["shopify.com"],
    "stripe": ["stripe.com"],
    "square": ["squareup.com"],
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk", "hmrc.gov.uk"],
    "cra": ["canada.ca", "cra-arc.gc.ca"],
    "ato": ["ato.gov.au"],
    "social security": ["ssa.gov"],
}

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".iso", ".img", ".jar",
    ".msi", ".dll", ".chm", ".one", ".docm", ".xlsm", ".pptm",
    ".xlam", ".xll", ".html", ".htm", ".svg", ".shtml", ".xhtml",
    ".cpl", ".msc", ".reg", ".rgs", ".inf", ".application",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in",
    "rb.gy", "bl.ink", "clck.ru", "v.gd", "qr.ae", "t.ly",
    "short.io", "tiny.cc", "dwz.cn", "suo.im", "url.cn",
]

REDIRECT_PARAM_NAMES = [
    "url", "u", "uri", "redirect", "redirect_uri", "target", "to",
    "next", "continue", "return", "returnurl", "r", "goto", "link",
    "dest", "destination", "forward", "ref", "out", "view",
]

REFERENCE_URL_HOSTS = [
    "schemas.openxmlformats.org", "schemas.microsoft.com",
    "purl.org", "www.w3.org", "www.wps.cn", "schemas.google.com",
    "ns.adobe.com", "www.openxmlformats.org",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".space",
    ".site", ".online", ".store", ".icu", ".buzz", ".co", ".tk",
    ".ml", ".ga", ".cf", ".gq", ".cc", ".pw", ".ws", ".info",
    ".support", ".fit", ".guru", ".email", ".review", ".download",
    ".racing", ".win", ".bid", ".accountant", ".science", ".date",
    ".stream", ".men", ".party", ".trade", ".webcam", ".cam",
]

RISKY_EXTENSIONS_SET = set(RISKY_EXTENSIONS)
