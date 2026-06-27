"""
Core utilities: normalization, deduplication, hashing, URL/domain/IP helpers.
"""

import hashlib
import html
import ipaddress
import json
import re
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses

from .config import (
    BRAND_DOMAINS,
    IMPERSONATED_BRANDS,
    REDIRECT_PARAM_NAMES,
    REFERENCE_URL_HOSTS,
    SHORTENERS,
    TLDEXTRACT_AVAILABLE,
)

if TLDEXTRACT_AVAILABLE:
    import tldextract



__all__ = ['decode_header_value', 'unfold_header', 'unique_list', 'get_header_values', 'get_first_header', 'normalize_domain', 'registered_domain', 'domains_align', 'normalize_email_address', 'parse_mailbox_headers', 'get_primary_mailbox', 'strip_url_terminal_punctuation', 'clean_url', 'normalize_url', 'url_host', 'defang', 'is_reference_url', 'filter_actionable_urls', 'brand_mentions', 'brand_domain_mismatches', 'normalize_ip', 'is_public_ip', 'extract_ips', 'hashes_for_bytes', 'timestamp_to_iso', 'analyze_domain_for_spoofing']

# ── Header helpers ───────────────────────────────────────────────

def decode_header_value(value):
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def unfold_header(value):
    return re.sub(r"\r?\n[ \t]+", " ", decode_header_value(value)).strip()


def unique_list(values):
    out, seen = [], set()
    for value in values:
        if value is None:
            continue
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def get_header_values(msg, name):
    return [unfold_header(v) for v in msg.get_all(name, [])]


def get_first_header(msg, name):
    values = get_header_values(msg, name)
    return values[0] if values else None


# ── Domain normalization ─────────────────────────────────────────

def normalize_domain(domain):
    if not domain:
        return None

    domain = html.unescape(str(domain)).strip().lower()
    if "://" in domain:
        parsed = urllib.parse.urlsplit(domain)
        domain = parsed.hostname or domain

    domain = domain.strip(" <>[]{}()\"'`")
    domain = domain.rstrip(".,;:")
    if domain.startswith("@"):
        domain = domain[1:]
    if domain.endswith("."):
        domain = domain[:-1]

    if domain.count(":") == 1 and re.search(r":\d+$", domain):
        domain = domain.rsplit(":", 1)[0]

    if not domain or "@" in domain or "/" in domain:
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = domain.split(".")
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 for label in labels):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None
    return domain


def registered_domain(domain):
    domain = normalize_domain(domain)
    if not domain:
        return None
    if TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(domain)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", None)
        return reg or domain
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def domains_align(left, right):
    left_reg = registered_domain(left)
    right_reg = registered_domain(right)
    return bool(left_reg and right_reg and left_reg == right_reg)


# ── Email normalization ──────────────────────────────────────────

def normalize_email_address(address):
    if not address:
        return None
    address = decode_header_value(address).strip().strip("<>\"' ")
    address = address.rstrip(".,;")
    if "@" not in address:
        return None
    local, domain = address.rsplit("@", 1)
    domain = normalize_domain(domain)
    local = local.strip().strip("\"").lower()
    if not local or not domain:
        return None
    return f"{local}@{domain}"


def parse_mailbox_headers(msg, header_name):
    raw_values = get_header_values(msg, header_name)
    mailboxes = []
    for display_name, address in getaddresses(raw_values):
        normalized = normalize_email_address(address)
        if not normalized:
            continue
        domain = normalized.rsplit("@", 1)[1]
        mailboxes.append({
            "display_name": decode_header_value(display_name).strip().strip("\""),
            "address": normalized,
            "domain": domain,
            "raw_header": header_name,
        })
    return unique_list(mailboxes)


def get_primary_mailbox(msg, header_name):
    mailboxes = parse_mailbox_headers(msg, header_name)
    return mailboxes[0] if mailboxes else None


# ── URL normalization ────────────────────────────────────────────

def strip_url_terminal_punctuation(url):
    pairs = {")": "(", "]": "[", "}": "{"}
    while url:
        if url[-1] in ".,;:":
            url = url[:-1]
            continue
        if url[-1] in pairs and url.count(url[-1]) > url.count(pairs[url[-1]]):
            url = url[:-1]
            continue
        break
    return url


def clean_url(url):
    if not url:
        return None
    url = html.unescape(str(url)).strip()
    url = url.strip("<>\"'")
    url = strip_url_terminal_punctuation(url)
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return None
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit(parsed)


def normalize_url(url):
    url = clean_url(url)
    if not url:
        return None
    parsed = urllib.parse.urlsplit(url)
    host = normalize_domain(parsed.hostname)
    if not host:
        return url
    netloc = host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        netloc = f"{auth}@{netloc}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def url_host(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        return normalize_domain(parsed.hostname)
    except Exception:
        return None


def defang(value):
    if not value:
        return value
    return (
        str(value)
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def is_reference_url(url):
    host = url_host(url)
    if not host:
        return False
    if host in REFERENCE_URL_HOSTS:
        return True
    if host.endswith(".w3.org") or host.endswith(".openxmlformats.org"):
        return True
    return False


def filter_actionable_urls(urls):
    actionable, ignored = [], []
    for url in unique_list(urls):
        cleaned = clean_url(url)
        if not cleaned:
            continue
        if is_reference_url(cleaned):
            ignored.append(cleaned)
        else:
            actionable.append(cleaned)
    return unique_list(actionable), unique_list(ignored)


# ── Brand detection ──────────────────────────────────────────────

def brand_mentions(text):
    if not text:
        return []
    compact_text = re.sub(r"[^a-z0-9]+", "", text.lower())
    mentions = []
    for brand in IMPERSONATED_BRANDS:
        compact_brand = re.sub(r"[^a-z0-9]+", "", brand.lower())
        if compact_brand and compact_brand in compact_text:
            mentions.append(brand)
    return unique_list(mentions)


def brand_domain_mismatches(domain):
    domain = normalize_domain(domain)
    if not domain:
        return []
    compact_domain = re.sub(r"[^a-z0-9]+", "", domain.lower())
    mismatches = []
    for brand, official_domains in BRAND_DOMAINS.items():
        compact_brand = re.sub(r"[^a-z0-9]+", "", brand.lower())
        if not compact_brand or compact_brand not in compact_domain:
            continue
        if not any(domains_align(domain, official) for official in official_domains):
            mismatches.append({
                "brand": brand,
                "domain": domain,
                "official_domains": official_domains,
            })
    return mismatches


# ── IP helpers ───────────────────────────────────────────────────

def normalize_ip(candidate):
    if not candidate:
        return None
    candidate = str(candidate).strip().strip("[]()<>.,;")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def is_public_ip(ip_value):
    try:
        return ipaddress.ip_address(ip_value).is_global
    except ValueError:
        return False


def extract_ips(text, public_only=False):
    if not text:
        return []

    candidates = set()
    candidates.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    candidates.update(re.findall(r"\[([0-9A-Fa-f:]{2,})\]", text))
    candidates.update(re.findall(
        r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]{1,}(?![A-Fa-f0-9:])", text
    ))

    results = []
    for candidate in candidates:
        ip_value = normalize_ip(candidate)
        if not ip_value:
            continue
        if public_only and not is_public_ip(ip_value):
            continue
        results.append(ip_value)
    return sorted(set(results), key=lambda value: (":" in value, value))


# ── Hashing / timestamps ────────────────────────────────────────

def hashes_for_bytes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def timestamp_to_iso(timestamp_value):
    if not timestamp_value:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp_value), tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError) as exc:
        import logging
        logging.getLogger(__name__).debug("Could not convert timestamp %r: %s", timestamp_value, exc)
        return None


# ── Spoofing detection ──────────────────────────────────────────

def analyze_domain_for_spoofing(domain):
    if not domain:
        return {}
    normalized = normalize_domain(domain)
    findings = {
        "is_homograph_attack": False,
        "punycode_version": None,
        "unicode_normalized": unicodedata.normalize("NFKC", domain),
        "registered_domain": registered_domain(normalized),
    }
    if domain != unicodedata.normalize("NFKC", domain):
        findings["is_homograph_attack"] = True
    try:
        punycode = str(domain).encode("idna").decode("ascii")
        if punycode.startswith("xn--") or ".xn--" in punycode:
            findings["punycode_version"] = punycode
            findings["is_homograph_attack"] = True
    except UnicodeError:
        findings["is_homograph_attack"] = True
    return findings
