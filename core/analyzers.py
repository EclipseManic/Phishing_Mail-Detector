"""
All analysis modules — email parsing, headers, URLs, content, and attachments.
"""

import logging
import mimetypes
import os
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from io import BytesIO
from xml.etree import ElementTree

import requests
import urllib.parse
from bs4 import BeautifulSoup

from .config import (
    ATTACHMENT_PARSING_AVAILABLE,
    BRAND_DOMAINS,
    IMAGE_SCANNING_AVAILABLE,
    OLETOOLS_AVAILABLE,
    REDIRECT_PARAM_NAMES,
    RISKY_EXTENSIONS_SET,
    SHORTENERS,
    WHOIS_AVAILABLE,
    SETTINGS,
)
from .utils import (
    brand_domain_mismatches,
    brand_mentions,
    clean_url,
    decode_header_value,
    defang,
    domains_align,
    extract_ips,
    filter_actionable_urls,
    get_first_header,
    get_header_values,
    get_primary_mailbox,
    hashes_for_bytes,
    is_public_ip,
    normalize_domain,
    normalize_email_address,
    normalize_ip,
    normalize_url,
    parse_mailbox_headers,
    registered_domain,
    unfold_header,
    unique_list,
    url_host,
)

if WHOIS_AVAILABLE:
    import whois

if ATTACHMENT_PARSING_AVAILABLE:
    import pdfplumber
    import docx

if OLETOOLS_AVAILABLE:
    from oletools.olevba import VBA_Parser

if IMAGE_SCANNING_AVAILABLE:
    from PIL import Image
    from pyzbar.pyzbar import decode as qr_decode
    import pytesseract

logger = logging.getLogger(__name__)


__all__ = ['decode_part_text', 'parse_eml_file', 'parse_tag_value_header', 'parse_authentication_results', 'choose_primary_auth', 'parse_microsoft_security_headers', 'parse_received_headers', 'parse_dkim_signatures', 'parse_received_spf', 'check_domain_age', 'analyze_header', 'extract_urls_from_text', 'extract_urls_from_bytes', 'analyze_url', 'extract_links', 'unshorten_url', 'analyze_html_content', 'scan_images_for_qrcodes', 'detect_file_type', 'has_double_extension', 'analyze_pdf_static', 'analyze_ooxml_zip', 'analyze_ole_static', 'extract_links_from_attachment_text', 'analyze_attachment']



# ═══════════════════════════════════════════════════════════════════
# EMAIL PARSING
# ═══════════════════════════════════════════════════════════════════

def decode_part_text(part, payload):
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def parse_eml_file(file_path):
    """Parse an .eml file and return (msg, header_text, body, html_body, attachments, images)."""
    with open(file_path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    header_text = "".join(f"{key}: {unfold_header(value)}\n" for key, value in msg.items())
    body, html_body, attachments, images = "", "", [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            content_type = part.get_content_type() or "application/octet-stream"
            disposition = part.get_content_disposition()
            filename = decode_header_value(part.get_filename() or "").strip() or None
            payload = part.get_payload(decode=True)
            if payload is None:
                try:
                    content = part.get_content()
                    payload = (
                        content.encode(part.get_content_charset() or "utf-8", errors="ignore")
                        if isinstance(content, str) else b""
                    )
                except Exception:
                    payload = b""

            is_attachment = bool(
                disposition == "attachment"
                or filename
                or content_type.startswith("application/")
                or content_type in {"message/rfc822", "application/octet-stream"}
            )

            if is_attachment:
                attachments.append({
                    "filename": filename or "unknown",
                    "content_type": content_type,
                    "content_disposition": disposition or "",
                    "data": payload or b"",
                })
            elif content_type.startswith("image/"):
                images.append({
                    "filename": filename or "inline-image",
                    "content_type": content_type,
                    "data": payload or b"",
                })
            elif content_type == "text/plain":
                body += decode_part_text(part, payload)
            elif content_type == "text/html":
                html_body += decode_part_text(part, payload)
        except Exception as exc:
            logger.warning("Could not process a MIME part. Error: %s", exc)

    return msg, header_text, body, html_body, attachments, images


# ═══════════════════════════════════════════════════════════════════
# HEADER ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def parse_tag_value_header(value):
    tags = {}
    for item in unfold_header(value).split(";"):
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        tags[key.strip().lower()] = val.strip()
    return tags


def parse_authentication_results(msg):
    parsed_headers = []
    for header_name in ("Authentication-Results", "ARC-Authentication-Results"):
        for raw_value in get_header_values(msg, header_name):
            text = unfold_header(raw_value)
            result_values = {}
            for key in ("spf", "dkim", "dmarc", "arc", "compauth", "domainkeys"):
                matches = re.findall(rf"\b{re.escape(key)}\s*=\s*([A-Za-z0-9_-]+)", text, re.IGNORECASE)
                if matches:
                    result_values[key] = matches[-1].lower()

            params = {}
            for param in (
                "smtp.mailfrom", "smtp.rcpttodomain", "header.from",
                "header.d", "header.i", "client-ip", "action", "reason",
            ):
                pattern = rf"(?<![\w.]){re.escape(param)}\s*=\s*([^;\s\)]+)"
                values = [v.strip(" <>\"'") for v in re.findall(pattern, text, re.IGNORECASE)]
                if values:
                    params[param] = unique_list(values)

            sender_ip_matches = re.findall(
                r"sender\s+ip(?:\s+address)?(?:\s+is|:)?\s*([0-9A-Fa-f:.]+)", text, re.IGNORECASE,
            )
            sender_ips = extract_ips(" ".join(sender_ip_matches), public_only=True)
            sender_ips.extend(extract_ips(text, public_only=True))
            sender_ips = unique_list(sender_ips)

            parsed_headers.append({
                "header_name": header_name,
                "results": result_values,
                "params": params,
                "sender_ips": sender_ips,
                "raw": text,
            })
    return parsed_headers


def choose_primary_auth(auth_results):
    for item in auth_results:
        if item["header_name"].lower() == "authentication-results":
            return item
    return auth_results[0] if auth_results else {"results": {}, "params": {}, "sender_ips": [], "raw": ""}


def parse_microsoft_security_headers(msg):
    ms_header_names = [
        "X-Forefront-Antispam-Report",
        "X-Microsoft-Antispam",
        "X-MS-Exchange-Organization-Antispam-Report",
    ]
    fields = defaultdict(list)
    raw_headers = []

    for name in ms_header_names:
        for raw_value in get_header_values(msg, name):
            raw_headers.append({"name": name, "raw": raw_value})
            for item in raw_value.split(";"):
                item = item.strip()
                if ":" not in item:
                    continue
                key, value = item.split(":", 1)
                key = key.strip().upper()
                value = value.strip()
                if key and value:
                    fields[key].append(value)

    direct_headers = {}
    for name in [
        "X-MS-Exchange-Organization-SCL", "X-MS-Exchange-Organization-PCL",
        "X-MS-Exchange-Organization-BCL", "X-MS-Exchange-Organization-AuthSource",
        "X-MS-Exchange-Organization-AuthAs", "X-MS-Exchange-Organization-SenderIdResult",
        "X-MS-Exchange-Organization-MessageDirectionality", "X-Sender-IP", "X-Originating-IP",
    ]:
        values = get_header_values(msg, name)
        if values:
            direct_headers[name] = values

    return {
        "raw_headers": raw_headers,
        "fields": {key: unique_list(values) for key, values in fields.items()},
        "direct_headers": direct_headers,
    }


def parse_received_headers(msg):
    received = []
    for index, raw_value in enumerate(get_header_values(msg, "Received"), start=1):
        text = unfold_header(raw_value)
        from_match = re.search(r"\bfrom\s+([^\s(;]+)", text, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s(;]+)", text, re.IGNORECASE)
        with_match = re.search(r"\bwith\s+([A-Za-z0-9_./-]+)", text, re.IGNORECASE)
        tls_match = re.search(r"version=([^,\s)]+)", text, re.IGNORECASE)
        cipher_match = re.search(r"cipher=([^,\s)]+)", text, re.IGNORECASE)

        date_text = None
        date_iso = None
        if ";" in text:
            date_text = text.rsplit(";", 1)[-1].strip()
            try:
                date_iso = parsedate_to_datetime(date_text).astimezone(timezone.utc).isoformat()
            except Exception:
                date_iso = None

        all_ips = extract_ips(text, public_only=False)
        public_ips = [ip for ip in all_ips if is_public_ip(ip)]
        received.append({
            "hop": index,
            "from": from_match.group(1) if from_match else None,
            "by": by_match.group(1) if by_match else None,
            "with": with_match.group(1) if with_match else None,
            "tls_version": tls_match.group(1) if tls_match else None,
            "cipher": cipher_match.group(1) if cipher_match else None,
            "ips": all_ips,
            "public_ips": public_ips,
            "date": date_text,
            "date_utc": date_iso,
            "raw": text,
        })
    return received


def parse_dkim_signatures(msg):
    signatures = []
    for raw_value in get_header_values(msg, "DKIM-Signature"):
        tags = parse_tag_value_header(raw_value)
        domain = normalize_domain(tags.get("d"))
        signatures.append({
            "domain": domain,
            "selector": tags.get("s"),
            "algorithm": tags.get("a"),
            "canonicalization": tags.get("c"),
            "signed_headers": [h.strip() for h in tags.get("h", "").split(":") if h.strip()],
            "raw": raw_value,
        })
    return signatures


def parse_received_spf(msg):
    values = []
    for raw_value in get_header_values(msg, "Received-SPF"):
        result_match = re.match(r"([A-Za-z0-9_-]+)", raw_value)
        values.append({
            "result": result_match.group(1).lower() if result_match else None,
            "client_ip": (re.search(r"client-ip=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
            "envelope_from": (re.search(r"(?:envelope-from|smtp.mailfrom)=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
            "helo": (re.search(r"helo=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
            "raw": raw_value,
        })
    return values


def check_domain_age(domain):
    if not WHOIS_AVAILABLE or not domain:
        return None
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            return (datetime.now() - creation_date).days
    except Exception:
        return None
    return None


def analyze_header(msg):
    """Full header analysis — returns a dict of all header findings."""
    from_box = get_primary_mailbox(msg, "From")
    return_path_box = get_primary_mailbox(msg, "Return-Path")
    reply_to_box = get_primary_mailbox(msg, "Reply-To")
    to_boxes = parse_mailbox_headers(msg, "To")
    cc_boxes = parse_mailbox_headers(msg, "Cc")
    auth_results = parse_authentication_results(msg)
    primary_auth = choose_primary_auth(auth_results)
    microsoft_headers = parse_microsoft_security_headers(msg)
    received_path = parse_received_headers(msg)
    dkim_signatures = parse_dkim_signatures(msg)
    received_spf = parse_received_spf(msg)

    auth = primary_auth.get("results", {})
    params = primary_auth.get("params", {})
    from_domain = from_box["domain"] if from_box else None

    # Display name impersonation detection
    display_name_claimed_emails = []
    display_name_claimed_domains = []
    if from_box and from_box.get("display_name"):
        display_name = from_box["display_name"]
        display_name_claimed_emails = [normalize_email_address(addr) for _, addr in getaddresses([display_name])]
        display_name_claimed_emails = unique_list([addr for addr in display_name_claimed_emails if addr])
        display_name_claimed_domains = [addr.rsplit("@", 1)[1] for addr in display_name_claimed_emails]
        display_name_claimed_domains.extend([
            normalize_domain(match)
            for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", display_name, re.IGNORECASE)
        ])
        display_name_claimed_domains = unique_list([d for d in display_name_claimed_domains if d])

    display_name_domain_mismatch = None
    if from_domain and display_name_claimed_domains:
        display_name_domain_mismatch = not any(
            domains_align(from_domain, domain) for domain in display_name_claimed_domains
        )

    display_name_brand_mentions = brand_mentions(from_box.get("display_name") if from_box else "")
    display_name_brand_mismatch = False
    if from_domain and display_name_brand_mentions:
        for brand in display_name_brand_mentions:
            official_domains = BRAND_DOMAINS.get(brand, [])
            if official_domains and not any(domains_align(from_domain, official) for official in official_domains):
                display_name_brand_mismatch = True
                break

    # Auth alignment
    smtp_mailfrom_domains = [normalize_domain(v.split("@")[-1]) for v in params.get("smtp.mailfrom", [])]
    header_from_domains = [normalize_domain(v.split("@")[-1]) for v in params.get("header.from", [])]
    dkim_domains = [normalize_domain(v) for v in params.get("header.d", [])]
    dkim_domains.extend([item.get("domain") for item in dkim_signatures if item.get("domain")])
    dkim_domains = unique_list([d for d in dkim_domains if d])

    spf_aligned = None
    if from_domain and smtp_mailfrom_domains:
        spf_aligned = any(domains_align(from_domain, domain) for domain in smtp_mailfrom_domains if domain)

    dkim_aligned = None
    if from_domain and dkim_domains:
        dkim_aligned = any(domains_align(from_domain, domain) for domain in dkim_domains if domain)

    return_path_mismatch = None
    if from_box and return_path_box:
        return_path_mismatch = from_box["address"] != return_path_box["address"]

    reply_to_mismatch = None
    if from_box and reply_to_box:
        reply_to_mismatch = from_box["address"] != reply_to_box["address"]

    sender_ips = unique_list(
        primary_auth.get("sender_ips", [])
        + [ip for hop in received_path for ip in hop.get("public_ips", [])]
        + extract_ips(" ".join(microsoft_headers["direct_headers"].get("X-Sender-IP", [])), public_only=True)
        + extract_ips(" ".join(microsoft_headers["direct_headers"].get("X-Originating-IP", [])), public_only=True)
    )

    return {
        "From": from_box,
        "Return-Path": return_path_box,
        "Reply-To": reply_to_box,
        "To": to_boxes,
        "Cc": cc_boxes,
        "From Address": from_box["address"] if from_box else None,
        "Return-Path Address": return_path_box["address"] if return_path_box else None,
        "Reply-To Address": reply_to_box["address"] if reply_to_box else None,
        "Return-Path Mismatch": return_path_mismatch,
        "Reply-To Mismatch": reply_to_mismatch,
        "SPF Result": auth.get("spf", "not found"),
        "DKIM Result": auth.get("dkim", "not found"),
        "DMARC Result": auth.get("dmarc", "not found"),
        "CompAuth Result": auth.get("compauth"),
        "CompAuth Reason": (params.get("reason") or [None])[0],
        "Auth Action": (params.get("action") or [None])[0],
        "SPF MailFrom Domains": unique_list([d for d in smtp_mailfrom_domains if d]),
        "Header From Domains": unique_list([d for d in header_from_domains if d]),
        "DKIM Domains": dkim_domains,
        "Display Name Claimed Emails": display_name_claimed_emails,
        "Display Name Claimed Domains": display_name_claimed_domains,
        "Display Name Domain Mismatch": display_name_domain_mismatch,
        "Display Name Brand Mentions": display_name_brand_mentions,
        "Display Name Brand Mismatch": display_name_brand_mismatch,
        "SPF Aligned": spf_aligned,
        "DKIM Aligned": dkim_aligned,
        "Sender IPs": sender_ips,
        "Authentication-Results": auth_results,
        "Primary Authentication-Results": primary_auth,
        "Microsoft Security Headers": microsoft_headers,
        "Received Path": received_path,
        "DKIM Signatures": dkim_signatures,
        "Received-SPF": received_spf,
        "Subject": get_first_header(msg, "Subject"),
        "Message-ID": get_first_header(msg, "Message-ID"),
        "Date": get_first_header(msg, "Date"),
    }


# ═══════════════════════════════════════════════════════════════════
# URL ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def extract_urls_from_text(text):
    if not text:
        return []
    urls = []
    for match in re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE):
        cleaned = clean_url(match)
        if cleaned:
            urls.append(cleaned)
    return unique_list(urls)


def extract_urls_from_bytes(data):
    if not data:
        return []
    urls = []
    for match in re.findall(rb"https?://[^\s<>\"']+", data, re.IGNORECASE):
        try:
            cleaned = clean_url(match.decode("utf-8", errors="ignore"))
            if cleaned:
                urls.append(cleaned)
        except Exception:
            continue
    return unique_list(urls)


def analyze_url(url, source, link_text=None):
    """Deep analysis of a single URL — features, deception, brand mismatch."""
    normalized = normalize_url(url)
    parsed = urllib.parse.urlsplit(normalized or url)
    host = normalize_domain(parsed.hostname)
    features = []

    # ── Basic URL structure ─────────────────────────────────────
    if parsed.username or parsed.password:
        features.append("URL contains user-info before host")
    if host and host in SHORTENERS:
        features.append("URL uses a known shortener")
    if host and (host.startswith("xn--") or ".xn--" in host):
        features.append("URL host contains punycode")
    if parsed.hostname and normalize_ip(parsed.hostname):
        features.append("URL uses an IP literal as host")
    if host and len(host.split(".")) >= 4:
        features.append("URL has many subdomain levels")
    if parsed.port and parsed.port not in {80, 443}:
        features.append(f"URL uses non-standard port {parsed.port}")

    for mismatch in brand_domain_mismatches(host):
        features.append(
            f"URL domain contains brand token '{mismatch['brand']}' but is not an official brand domain"
        )

    # ── Query parameter analysis ────────────────────────────────
    query = urllib.parse.parse_qs(parsed.query)
    for key, values in query.items():
        if key.lower() in REDIRECT_PARAM_NAMES:
            if any(clean_url(urllib.parse.unquote(v)) for v in values):
                features.append(f"URL carries nested redirect parameter '{key}'")

    if len(query) > 5:
        features.append(f"URL has {len(query)} query parameters (tracking pattern)")

    full_url = normalized or url
    _check_encoded_data(full_url, query, features)

    # ── Google AMP redirect ─────────────────────────────────────
    if host in {"google.com", "www.google.com"} and parsed.path.lower().startswith("/amp/"):
        features.append("URL uses Google AMP as a redirect/wrapper")

    # ── Tracking path patterns ──────────────────────────────────
    path_lower = parsed.path.lower()
    tracking_patterns = [
        "/track", "/pixel", "/beacon", "/open", "/click",
        "/t/", "/r/", "/c/", "/l/",
        "/o/", "/wf/open",
    ]
    for pattern in tracking_patterns:
        if pattern in path_lower:
            features.append(f"URL path contains tracking pattern '{pattern.strip('/')}'")
            break

    # ── Embedded domain in path ─────────────────────────────────
    common_file_exts = {
        "html", "htm", "php", "aspx", "asp", "jsp", "png", "jpg", "jpeg",
        "gif", "svg", "css", "js", "pdf", "doc", "docx", "xls", "xlsx", "zip",
    }
    path_text = urllib.parse.unquote(parsed.path)
    for path_domain_match in re.finditer(r"([a-z0-9-]+\.)+[a-z]{2,}", path_text, re.IGNORECASE):
        candidate = path_domain_match.group(0)
        tld = candidate.rsplit(".", 1)[-1].lower()
        next_char = path_text[path_domain_match.end(): path_domain_match.end() + 1]
        if tld in common_file_exts and next_char != "/":
            continue
        embedded_domain = normalize_domain(candidate)
        if embedded_domain and host and not domains_align(embedded_domain, host):
            features.append(f"URL path contains embedded domain {embedded_domain}")
            break

    # ── Deceptive display text ──────────────────────────────────
    displayed_url = None
    deceptive_display = False
    if link_text:
        text_urls = extract_urls_from_text(link_text)
        if text_urls:
            displayed_url = text_urls[0]
            displayed_host = url_host(displayed_url)
            if displayed_host and host and not domains_align(displayed_host, host):
                deceptive_display = True
                features.append(f"Link text displays {displayed_host} but href points to {host}")

    return {
        "url": url,
        "normalized_url": normalized or url,
        "defanged": defang(normalized or url),
        "source": source,
        "host": host,
        "registered_domain": registered_domain(host),
        "path": parsed.path,
        "query_keys": sorted(query.keys()),
        "link_text": link_text,
        "displayed_url": displayed_url,
        "deceptive_display": deceptive_display,
        "features": unique_list(features),
        "is_tracking_pixel": _is_tracking_pixel(source, features, query),
        "vt": None,
        "redirect_chain": [],
        "final_url": None,
    }


def _check_encoded_data(full_url, query, features):
    """Detect JWT tokens, base64 data, and embedded PII in URLs."""
    import base64

    jwt_matches = re.findall(r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?)', full_url)
    if jwt_matches:
        features.append("URL contains JWT token (encoded data)")
        for jwt_token in jwt_matches:
            parts = jwt_token.split(".")
            if len(parts) >= 2:
                try:
                    payload_b64 = parts[1]
                    payload_b64 += "=" * (4 - len(payload_b64) % 4)
                    payload_bytes = base64.urlsafe_b64decode(payload_b64)
                    payload_text = payload_bytes.decode("utf-8", errors="ignore")
                    if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', payload_text):
                        features.append("JWT payload contains email address (PII tracking)")
                    if "password" in payload_text.lower() or "secret" in payload_text.lower():
                        features.append("JWT payload contains credential references")
                    if len(payload_text) > 200:
                        features.append(f"JWT payload is large ({len(payload_text)} chars) — likely contains user data")
                except Exception:
                    pass

    for key, values in query.items():
        for val in values:
            val_decoded = urllib.parse.unquote(val)
            if re.match(r'^[A-Za-z0-9+/=_-]{100,}$', val_decoded):
                features.append(f"URL parameter '{key}' contains long encoded string")
                break
            if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', val_decoded):
                features.append(f"URL parameter '{key}' contains email address")
                break

    if len(full_url) > 500:
        features.append(f"URL is very long ({len(full_url)} chars)")


def _is_tracking_pixel(source, features, query):
    """Determine if a URL is likely a tracking pixel/web beacon."""
    if "img" in source.lower() or "image" in source.lower():
        if query and any(
            kw in " ".join(features).lower()
            for kw in ["jwt", "encoded", "email", "tracking", "long"]
        ):
            return True
        if len(query) >= 2:
            return True
    if "meta" in source.lower() and query:
        return True
    return False


def extract_links(body, html_body):
    """Extract and deduplicate all links from email body and HTML."""
    url_records = []

    for url in extract_urls_from_text(body):
        url_records.append(analyze_url(url, "body.text"))

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for tag in soup.find_all(["a", "area"], href=True):
            url = clean_url(tag.get("href"))
            if url:
                url_records.append(analyze_url(url, "body.html.href", tag.get_text(" ", strip=True)))
        for tag in soup.find_all(["img", "script", "iframe"], src=True):
            url = clean_url(tag.get("src"))
            if url:
                url_records.append(analyze_url(url, f"body.html.{tag.name}.src"))
        for tag in soup.find_all("form", action=True):
            url = clean_url(tag.get("action"))
            if url:
                url_records.append(analyze_url(url, "body.html.form.action"))
        for tag in soup.find_all("meta"):
            content = tag.get("content", "")
            for url in extract_urls_from_text(content):
                url_records.append(analyze_url(url, "body.html.meta"))
        for url in extract_urls_from_text(soup.get_text(" ", strip=True)):
            url_records.append(analyze_url(url, "body.html.text"))

    deduped = {}
    for record in url_records:
        key = record["normalized_url"]
        if key not in deduped:
            deduped[key] = record
        else:
            deduped[key]["source"] = ",".join(
                unique_list(deduped[key]["source"].split(",") + [record["source"]])
            )
            deduped[key]["features"] = unique_list(deduped[key]["features"] + record["features"])
            if record.get("link_text") and not deduped[key].get("link_text"):
                deduped[key]["link_text"] = record["link_text"]
    return list(deduped.values())


def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=SETTINGS["unshorten_timeout_seconds"])
        chain = [r.url for r in response.history] + [response.url]
        return response.url, unique_list(chain)
    except Exception:
        return url, []


# ═══════════════════════════════════════════════════════════════════
# HTML CONTENT ANALYSIS & QR SCANNING
# ═══════════════════════════════════════════════════════════════════

def analyze_html_content(html_body):
    """Analyze HTML body for scripts, forms, hidden elements, iframes, meta refresh."""
    if not html_body:
        return {
            "javascript_present": False,
            "script_count": 0,
            "form_count": 0,
            "password_inputs": 0,
            "iframe_sources": [],
            "meta_refresh_urls": [],
            "hidden_element_count": 0,
        }

    soup = BeautifulSoup(html_body, "html.parser")
    script_count = len(soup.find_all("script"))
    forms = soup.find_all("form")
    password_inputs = len(soup.find_all("input", {"type": re.compile(r"password", re.IGNORECASE)}))
    iframe_sources = [clean_url(tag.get("src")) for tag in soup.find_all("iframe", src=True)]
    iframe_sources = unique_list([url for url in iframe_sources if url])
    meta_refresh_urls = []
    for tag in soup.find_all("meta"):
        if tag.get("http-equiv", "").lower() == "refresh":
            meta_refresh_urls.extend(extract_urls_from_text(tag.get("content", "")))

    hidden_elements = 0
    hidden_samples = []
    for tag in soup.find_all(True):
        style = tag.get("style", "")
        if tag.has_attr("hidden") or re.search(
            r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0", style, re.IGNORECASE
        ):
            hidden_elements += 1
            if len(hidden_samples) < 5:
                parts = [tag.name]
                tag_id = tag.get("id")
                if tag_id:
                    parts.append(f"#{tag_id}")
                tag_classes = tag.get("class") or []
                if tag_classes:
                    parts.append("." + ".".join(tag_classes[:3]))
                summary = "".join(parts)
                if len(summary) > 60:
                    summary = summary[:57] + "..."
                hidden_samples.append(summary)

    return {
        "javascript_present": script_count > 0,
        "script_count": script_count,
        "form_count": len(forms),
        "password_inputs": password_inputs,
        "iframe_sources": iframe_sources,
        "meta_refresh_urls": unique_list(meta_refresh_urls),
        "hidden_element_count": hidden_elements,
        "hidden_element_samples": hidden_samples,
    }


def scan_images_for_qrcodes(images_data):
    """Scan images for QR codes and OCR text containing URLs."""
    results = []
    if not IMAGE_SCANNING_AVAILABLE:
        return results
    for image in images_data:
        try:
            img = Image.open(BytesIO(image.get("data") or b""))
            decoded_qrs = qr_decode(img)
            urls = []
            if decoded_qrs:
                for qr in decoded_qrs:
                    value = qr.data.decode("utf-8", errors="ignore")
                    cleaned = clean_url(value)
                    if cleaned:
                        urls.append(cleaned)
            else:
                urls.extend(extract_urls_from_text(pytesseract.image_to_string(img)))

            for url in unique_list(urls):
                record = analyze_url(url, f"image.{image.get('filename')}.qr_or_ocr")
                results.append(record)
        except Exception as exc:
            logger.warning("Could not process image '%s'. Error: %s", image.get("filename"), exc)
    return results


# ═══════════════════════════════════════════════════════════════════
# ATTACHMENT ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def detect_file_type(data, filename=None, content_type=None):
    ext = os.path.splitext(filename or "")[1].lower()
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip_or_ooxml"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole_compound"
    if data.startswith(b"MZ"):
        return "pe_executable"
    if data.startswith(b"\x7fELF"):
        return "elf_executable"
    if data.startswith(b"Rar!"):
        return "rar_archive"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z_archive"
    if data.startswith(b"\x89PNG"):
        return "png_image"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    return (mimetypes.guess_type(filename or "")[0] or content_type or ext or "unknown").lower()


def has_double_extension(filename):
    name = (filename or "").lower()
    parts = [part for part in name.split(".") if part]
    if len(parts) < 3:
        return False
    visible_doc_exts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt"}
    return parts[-2] in visible_doc_exts and parts[-1] in {ext.lstrip(".") for ext in RISKY_EXTENSIONS_SET}


def analyze_pdf_static(data):
    lower = data.lower()
    indicators = []
    counts = {
        "javascript_markers": lower.count(b"/javascript") + lower.count(b"/js"),
        "open_action_markers": lower.count(b"/openaction"),
        "additional_action_markers": lower.count(b"/aa"),
        "launch_markers": lower.count(b"/launch"),
        "embedded_file_markers": lower.count(b"/embeddedfile"),
        "acroform_markers": lower.count(b"/acroform"),
        "uri_markers": lower.count(b"/uri"),
    }

    if counts["javascript_markers"]:
        indicators.append("PDF contains JavaScript markers")
    if counts["open_action_markers"]:
        indicators.append("PDF contains OpenAction markers")
    if counts["launch_markers"]:
        indicators.append("PDF contains Launch action markers")
    if counts["embedded_file_markers"]:
        indicators.append("PDF contains embedded file markers")
    if counts["acroform_markers"]:
        indicators.append("PDF contains AcroForm markers")

    uri_urls = []
    for match in re.findall(rb"/URI\s*\((.*?)\)", data, re.IGNORECASE | re.DOTALL):
        try:
            candidate = match.decode("utf-8", errors="ignore")
            cleaned = clean_url(candidate)
            if cleaned:
                uri_urls.append(cleaned)
        except Exception:
            continue

    return {
        "counts": counts,
        "indicators": indicators,
        "embedded_urls": unique_list(uri_urls + extract_urls_from_bytes(data)),
    }


def analyze_ooxml_zip(data):
    result = {
        "is_ooxml": False, "document_family": None, "file_count": 0,
        "macros_present": False, "external_relationships": [], "embedded_objects": [],
        "suspicious_archive_entries": [], "embedded_urls": [],
        "reference_urls_ignored": [], "indicators": [],
    }
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = archive.namelist()
            result["file_count"] = len(names)
            result["is_ooxml"] = "[Content_Types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            )
            if any(name.startswith("word/") for name in names):
                result["document_family"] = "word"
            elif any(name.startswith("xl/") for name in names):
                result["document_family"] = "excel"
            elif any(name.startswith("ppt/") for name in names):
                result["document_family"] = "powerpoint"

            result["macros_present"] = any(name.lower().endswith("vbaproject.bin") for name in names)
            if result["macros_present"]:
                result["indicators"].append("OOXML document contains VBA macro project")

            for name in names:
                lower = name.lower()
                if "/embeddings/" in lower or (lower.endswith(".bin") and "oleobject" in lower):
                    result["embedded_objects"].append(name)
                if lower.endswith(tuple(RISKY_EXTENSIONS_SET)):
                    result["suspicious_archive_entries"].append(name)

            if result["embedded_objects"]:
                result["indicators"].append("OOXML document contains embedded objects")
            if result["suspicious_archive_entries"]:
                result["indicators"].append("Archive contains risky file extensions")

            rel_ns = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
            for name in names:
                if not name.lower().endswith(".rels"):
                    continue
                try:
                    xml_data = archive.read(name)
                    root = ElementTree.fromstring(xml_data)
                    for rel in root.findall("rel:Relationship", rel_ns):
                        target = rel.attrib.get("Target", "")
                        mode = rel.attrib.get("TargetMode", "")
                        rel_type = rel.attrib.get("Type", "")
                        if mode.lower() == "external" or clean_url(target):
                            cleaned = clean_url(target)
                            result["external_relationships"].append({
                                "relationship_file": name, "type": rel_type,
                                "target": target, "url": cleaned,
                            })
                            if cleaned:
                                result["embedded_urls"].append(cleaned)
                except Exception:
                    continue

            if result["external_relationships"]:
                result["indicators"].append("OOXML document contains external relationships")

            for name in names:
                if name.lower().endswith((".xml", ".rels", ".txt")):
                    try:
                        result["embedded_urls"].extend(extract_urls_from_bytes(archive.read(name)))
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        return result
    result["embedded_urls"], result["reference_urls_ignored"] = filter_actionable_urls(result["embedded_urls"])
    return result


def analyze_ole_static(data, filename):
    result = {
        "oletools_available": OLETOOLS_AVAILABLE,
        "macros_present": None, "macro_indicators": [], "indicators": [],
    }
    if not OLETOOLS_AVAILABLE:
        result["indicators"].append(
            "OLE Office document detected; macro scan unavailable because oletools is not installed"
        )
        return result

    try:
        parser = VBA_Parser(filename or "attachment", data=data)
        macros_present = parser.detect_vba_macros()
        result["macros_present"] = macros_present
        if macros_present:
            result["indicators"].append("OLE document contains VBA macros")
            for indicator_type, keyword, description in parser.analyze_macros():
                result["macro_indicators"].append({
                    "type": indicator_type, "keyword": keyword, "description": description,
                })
        parser.close()
    except Exception as exc:
        result["indicators"].append(f"OLE macro scan failed: {exc}")
    return result


def extract_links_from_attachment_text(filename, data):
    if not ATTACHMENT_PARSING_AVAILABLE:
        return []
    filename_lower = (filename or "").lower()
    text = ""
    try:
        if filename_lower.endswith(".pdf") or data.startswith(b"%PDF"):
            with pdfplumber.open(BytesIO(data)) as pdf:
                text = "\n".join(page.extract_text() or "" for page in pdf.pages)
        elif filename_lower.endswith((".docx", ".docm")) or data.startswith(b"PK"):
            doc = docx.Document(BytesIO(data))
            text = "\n".join(para.text for para in doc.paragraphs)
    except Exception as exc:
        logger.debug("Could not extract links from attachment '%s': %s", filename, exc)
        return []
    return extract_urls_from_text(text)


def analyze_attachment(attachment):
    """Full attachment analysis — type detection, indicators, embedded URLs."""
    filename = attachment.get("filename") or "unknown"
    data = attachment.get("data") or b""
    content_type = attachment.get("content_type") or "application/octet-stream"
    detected_type = detect_file_type(data, filename, content_type)
    extension = os.path.splitext(filename)[1].lower()

    result = {
        "filename": filename, "content_type": content_type,
        "detected_type": detected_type, "size_bytes": len(data),
        "hashes": hashes_for_bytes(data), "extension": extension,
        "indicators": [], "embedded_urls": [], "reference_urls_ignored": [],
        "ooxml": None, "pdf": None, "ole": None, "vt": None,
    }

    if extension in RISKY_EXTENSIONS_SET:
        result["indicators"].append(f"Risky attachment extension: {extension}")
    if has_double_extension(filename):
        result["indicators"].append("Attachment uses a double extension")
    if detected_type in {"pe_executable", "elf_executable"}:
        result["indicators"].append(f"Executable file detected: {detected_type}")
    guessed_content_type = mimetypes.guess_type(filename)[0]
    if guessed_content_type and content_type and guessed_content_type.split("/")[0] != content_type.split("/")[0]:
        result["indicators"].append(
            f"MIME type mismatch: header says {content_type}, filename suggests {guessed_content_type}"
        )

    result["embedded_urls"].extend(extract_urls_from_bytes(data))
    result["embedded_urls"].extend(extract_links_from_attachment_text(filename, data))

    if detected_type == "pdf":
        pdf_result = analyze_pdf_static(data)
        result["pdf"] = pdf_result
        result["indicators"].extend(pdf_result["indicators"])
        result["embedded_urls"].extend(pdf_result["embedded_urls"])
    elif detected_type == "zip_or_ooxml":
        ooxml_result = analyze_ooxml_zip(data)
        result["ooxml"] = ooxml_result
        result["indicators"].extend(ooxml_result["indicators"])
        result["embedded_urls"].extend(ooxml_result["embedded_urls"])
        result["reference_urls_ignored"].extend(ooxml_result.get("reference_urls_ignored", []))
    elif detected_type == "ole_compound":
        ole_result = analyze_ole_static(data, filename)
        result["ole"] = ole_result
        result["indicators"].extend(ole_result["indicators"])

    actionable_urls, ignored_urls = filter_actionable_urls(result["embedded_urls"])
    result["embedded_urls"] = actionable_urls
    result["reference_urls_ignored"] = unique_list(result["reference_urls_ignored"] + ignored_urls)
    if result["embedded_urls"]:
        result["indicators"].append("Attachment contains embedded external URL(s)")
    result["indicators"] = unique_list(result["indicators"])
    return result

