"""
IOC extraction, risk scoring, and report building.
"""

import re
from datetime import datetime, timezone

from .config import (
    ABUSED_LEGIT_SERVICES,
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    IMPERSONATED_BRANDS,
    PHISHING_THEMES,
    SETTINGS,
    SOCIAL_KEYWORDS,
    SUSPICIOUS_TLDS,
    URGENCY_KEYWORDS,
    WEIGHTS,
)
from .utils import (
    defang,
    is_public_ip,
    normalize_domain,
    normalize_email_address,
    normalize_ip,
    normalize_url,
    registered_domain,
    unique_list,
)
from .apis import vt_detection_count, vt_summary_text, urlscan_detection_flagged, urlscan_summary_text


__all__ = ['build_observables', 'generate_score_and_feedback', 'build_report']



# ═══════════════════════════════════════════════════════════════════
# IOC (OBSERVABLE) EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def _add_observable(observables, index, observable_type, value, source, role=None, metadata=None):
    if not value:
        return None

    if observable_type == "email":
        normalized = normalize_email_address(value)
    elif observable_type == "domain":
        normalized = normalize_domain(value)
    elif observable_type == "ip":
        normalized = normalize_ip(value)
    elif observable_type == "url":
        normalized = normalize_url(value)
    elif observable_type in {"md5", "sha1", "sha256"}:
        normalized = str(value).lower()
    else:
        normalized = str(value).strip()

    if not normalized:
        return None

    key = (observable_type, normalized)
    if key not in index:
        observable = {
            "type": observable_type,
            "value": normalized,
            "defanged": defang(normalized) if observable_type in {"domain", "url", "email", "ip"} else normalized,
            "sources": [],
            "roles": [],
            "metadata": {},
            "vt": None,
        }
        if observable_type == "domain":
            observable["registered_domain"] = registered_domain(normalized)
        if observable_type == "ip":
            observable["is_public"] = is_public_ip(normalized)
        index[key] = observable
        observables.append(observable)
    else:
        observable = index[key]

    if source and source not in observable["sources"]:
        observable["sources"].append(source)
    if role and role not in observable["roles"]:
        observable["roles"].append(role)
    if metadata:
        for key_name, meta_value in metadata.items():
            if key_name not in observable["metadata"]:
                observable["metadata"][key_name] = meta_value
            elif observable["metadata"][key_name] != meta_value:
                existing = observable["metadata"][key_name]
                if not isinstance(existing, list):
                    existing = [existing]
                if not isinstance(meta_value, list):
                    meta_value = [meta_value]
                observable["metadata"][key_name] = unique_list(existing + meta_value)
    return observable


def build_observables(header_findings, url_records, attachment_results):
    """Extract all IOCs from headers, URLs, and attachments."""
    from .analyzers import analyze_url

    observables = []
    index = {}

    for header_name in ("From", "Return-Path", "Reply-To"):
        box = header_findings.get(header_name)
        if box:
            _add_observable(observables, index, "email", box["address"], f"header.{header_name}", header_name.lower())
            _add_observable(observables, index, "domain", box["domain"], f"header.{header_name}", f"{header_name.lower()}_domain")

    for header_name in ("To", "Cc"):
        for box in header_findings.get(header_name, []):
            _add_observable(observables, index, "email", box["address"], f"header.{header_name}", header_name.lower())
            _add_observable(observables, index, "domain", box["domain"], f"header.{header_name}", f"{header_name.lower()}_domain")

    for domain in header_findings.get("SPF MailFrom Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.smtp.mailfrom", "spf_mailfrom")
    for domain in header_findings.get("Header From Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.header.from", "header_from")
    for domain in header_findings.get("DKIM Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.header.d", "dkim_domain")
    for email_address in header_findings.get("Display Name Claimed Emails", []):
        _add_observable(observables, index, "email", email_address, "header.From.display_name", "display_name_claim")
    for domain in header_findings.get("Display Name Claimed Domains", []):
        _add_observable(observables, index, "domain", domain, "header.From.display_name", "display_name_claim_domain")
    for ip in header_findings.get("Sender IPs", []):
        _add_observable(observables, index, "ip", ip, "auth_or_received.sender_ip", "sender_ip")

    for hop in header_findings.get("Received Path", []):
        for ip in hop.get("public_ips", []):
            _add_observable(
                observables, index, "ip", ip,
                f"received.hop_{hop.get('hop')}", "received_public_ip",
                {"from": hop.get("from"), "by": hop.get("by")},
            )

    for record in url_records:
        _add_observable(
            observables, index, "url", record["normalized_url"],
            record["source"], "embedded_url",
            {"host": record.get("host"), "features": record.get("features")},
        )
        if record.get("host"):
            _add_observable(observables, index, "domain", record["host"], record["source"], "url_host")

    for attachment in attachment_results:
        hashes = attachment.get("hashes", {})
        for hash_type in ("md5", "sha1", "sha256"):
            _add_observable(
                observables, index, hash_type, hashes.get(hash_type),
                f"attachment.{attachment.get('filename')}", "attachment_hash",
            )
        for embedded_url in attachment.get("embedded_urls", []):
            record = analyze_url(embedded_url, f"attachment.{attachment.get('filename')}.embedded_url")
            _add_observable(observables, index, "url", record["normalized_url"], record["source"], "attachment_url")
            if record.get("host"):
                _add_observable(observables, index, "domain", record["host"], record["source"], "attachment_url_host")

    return observables


# ═══════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════

def _f(level, title, message, detail=""):
    return {"level": level, "title": title, "message": message, "detail": detail}


def _match_keywords(text, keyword_list):
    return [kw for kw in keyword_list if kw in text]


def generate_score_and_feedback(data):
    """Score analysis with prioritized tiers. Returns (score, feedback_items)."""
    w = WEIGHTS
    header = data["header_findings"]
    full_text = data["full_body"].lower()

    from_addr = header.get("From Address") or ""
    from_box = header.get("From") or {}
    from_domain = from_box.get("domain") or ""
    rp_addr = header.get("Return-Path Address") or ""
    rt_addr = header.get("Reply-To Address") or ""

    critical_floor = 0
    warning_score = 0
    positive_offset = 0
    items = []

    # DIMENSION 1: AUTHENTICATION
    critical_floor, warning_score, positive_offset, items = _score_auth(
        header, critical_floor, warning_score, positive_offset, items, w,
        from_addr, rp_addr, rt_addr, from_domain,
    )

    # DIMENSION 2: SENDER REPUTATION
    critical_floor, warning_score, positive_offset, items = _score_sender(
        data, header, critical_floor, warning_score, positive_offset, items, w, from_domain,
    )

    # DIMENSION 3: CONTENT SIGNALS
    critical_floor, warning_score, positive_offset, items = _score_content(
        data, critical_floor, warning_score, positive_offset, items, w, full_text,
    )

    # DIMENSION 4: URL ANALYSIS
    critical_floor, warning_score, positive_offset, items = _score_urls(
        data, critical_floor, warning_score, positive_offset, items, w,
    )

    # DIMENSION 5: ATTACHMENTS
    critical_floor, warning_score, positive_offset, items = _score_attachments(
        data, critical_floor, warning_score, positive_offset, items, w,
    )

    # DIMENSION 6: BEHAVIORAL COMBOS
    critical_floor, warning_score, positive_offset, items = _score_behavioral(
        data, header, full_text, critical_floor, warning_score, positive_offset, items, w,
    )

    # FINAL SCORE CALCULATION
    net_warning = max(0, warning_score - positive_offset)
    final_score = max(critical_floor, net_warning)

    spf = header.get("SPF Result")
    dkim = header.get("DKIM Result")
    dmarc = header.get("DMARC Result")
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        items.append(_f("positive", "Sender Identity Verified",
                        "SPF, DKIM, and DMARC passed.",
                        f"SPF={spf} DKIM={dkim} DMARC={dmarc}"))

    sender_ips = header.get("Sender IPs") or []
    if sender_ips:
        items.append(_f("positive", "Sender IPs Identified",
                        f"Found {len(sender_ips)} sender/relay IP(s).",
                        f"IPs: {', '.join(sender_ips[:5])}"))

    if not items:
        items.append(_f("positive", "No Risk Factors",
                        "No major risk factors detected.", "All checks passed"))

    return min(final_score, 10), unique_list(items)


def _score_auth(header, cf, ws, po, items, w, from_addr, rp_addr, rt_addr, from_domain):
    if header.get("Return-Path Mismatch"):
        ws += w["mismatch_return_path"]
        items.append(_f("critical", "Return-Path Mismatch",
                        f"{rp_addr} differs from {from_addr}.",
                        f"Return-Path: {rp_addr} | From: {from_addr}"))

    if header.get("Reply-To Mismatch"):
        ws += w["mismatch_reply_to"]
        items.append(_f("critical", "Reply-To Mismatch",
                        f"Replies go to {rt_addr} instead of {from_addr}.",
                        f"Reply-To: {rt_addr} | From: {from_addr}"))

    dmarc = header.get("DMARC Result", "not found")
    if dmarc == "fail":
        cf = max(cf, w["dmarc_fail"])
        items.append(_f("critical", "DMARC Failure", "Header From domain failed DMARC.", f"dmarc={dmarc}"))
    elif dmarc in {"none", "not found", "neutral"}:
        ws += w["dmarc_weak_or_missing"]
        items.append(_f("warning", "DMARC Weak/Missing",
                        f"DMARC result is '{dmarc}' — enforcement not confirmed.", f"dmarc={dmarc}"))

    spf = header.get("SPF Result", "not found")
    if spf not in {"pass", "not found", "neutral", "none"}:
        ws += w["spf_fail"]
        items.append(_f("critical", "SPF Failure", f"SPF result is '{spf}'.", f"spf={spf}"))
    elif spf == "not found":
        ws += w["spf_not_found"]
        items.append(_f("warning", "SPF Missing", "No SPF result found.", "No SPF header"))

    dkim = header.get("DKIM Result", "not found")
    if dkim not in {"pass", "not found", "neutral", "none"}:
        ws += w["dkim_fail"]
        items.append(_f("critical", "DKIM Failure", f"DKIM result is '{dkim}'.", f"dkim={dkim}"))
    elif dkim == "not found":
        ws += w["dkim_not_found"]
        items.append(_f("warning", "DKIM Missing", "No DKIM result found.", "No DKIM header"))

    spf_domains = header.get("SPF MailFrom Domains") or []
    header_domains = header.get("Header From Domains") or []

    if header.get("SPF Aligned") is False and spf == "pass":
        ws += w["auth_alignment_mismatch"]
        items.append(_f("critical", "SPF Alignment Mismatch",
                        f"SPF passed for {spf_domains} but Header From is {header_domains or from_domain}.",
                        f"MailFrom: {', '.join(spf_domains)} | Header From: {from_domain}"))

    if header.get("DKIM Aligned") is False and dkim == "pass":
        ws += w["auth_alignment_mismatch"]
        items.append(_f("critical", "DKIM Alignment Mismatch",
                        f"DKIM domain(s) {header.get('DKIM Domains')} do not align with Header From.",
                        f"DKIM: {', '.join(header.get('DKIM Domains') or [])} | Header From: {from_domain}"))

    compauth = header.get("CompAuth Result")
    if compauth and compauth not in {"pass", "softpass"}:
        ws += w["compauth_fail"]
        items.append(_f("critical", "Microsoft Composite Auth",
                        f"compauth={compauth} reason={header.get('CompAuth Reason')}.",
                        f"compauth={compauth}"))

    claimed_domains = header.get("Display Name Claimed Domains") or []
    brand_mentions_list = header.get("Display Name Brand Mentions") or []

    if header.get("Display Name Domain Mismatch"):
        cf = max(cf, w["display_name_domain_mismatch"])
        items.append(_f("critical", "Display Name Impersonation",
                        f"Display name claims {claimed_domains} but From is {from_domain}.",
                        f"Claims: {', '.join(claimed_domains)} | From: {from_domain}"))

    if header.get("Display Name Brand Mismatch"):
        cf = max(cf, w["brand_impersonation"])
        items.append(_f("critical", "Brand Display Name Mismatch",
                        f"Display name mentions {brand_mentions_list} but From is {from_domain}.",
                        f"Brands: {', '.join(brand_mentions_list)} | Domain: {from_domain}"))

    return cf, ws, po, items


def _score_sender(data, header, cf, ws, po, items, w, from_domain):
    spoof = data["spoof_findings"]
    domain_age = data["domain_age"]
    threshold = SETTINGS["domain_age_threshold_days"]

    if spoof.get("is_homograph_attack"):
        cf = max(cf, w["homograph_attack"])
        punycode = spoof.get("punycode_version") or ""
        items.append(_f("critical", "Homograph/Punycode Risk",
                        "Sender domain contains look-alike encoding.",
                        f"Punycode: {punycode}" if punycode else "Unicode normalization mismatch"))

    if domain_age is not None:
        if domain_age < threshold:
            cf = max(cf, w["recent_domain"])
            items.append(_f("critical", "Recently Created Domain",
                            f"Sender domain is only {domain_age} days old.",
                            f"Age: {domain_age}d (threshold: {threshold}d)"))
        elif domain_age < threshold * 2:
            ws += 2
            items.append(_f("warning", "Young Domain",
                            f"Sender domain is only {domain_age} days old — less than 6 months.",
                            f"Age: {domain_age}d | Threshold: {threshold}d"))
        elif domain_age > 365 * 3:
            po += 1

    if from_domain:
        tld = "." + from_domain.rsplit(".", 1)[-1] if "." in from_domain else ""
        if tld in SUSPICIOUS_TLDS:
            ws += 2
            items.append(_f("warning", "Suspicious TLD",
                            f"Sender domain uses '{tld}' — a TLD commonly abused for phishing.",
                            f"Domain: {from_domain} | TLD: {tld}"))

    dkim_domains = header.get("DKIM Domains") or []
    if dkim_domains and from_domain:
        dkim_lower = [d.lower() for d in dkim_domains if d]
        from_lower = from_domain.lower()
        if from_lower not in dkim_lower and not any(from_lower.endswith("." + d) for d in dkim_lower):
            ws += 1
            items.append(_f("warning", "DKIM Signed by Third Party",
                            f"DKIM-signed by {dkim_domains} but From is {from_domain}.",
                            f"DKIM: {', '.join(dkim_domains)} | From: {from_domain}"))

    return cf, ws, po, items


def _score_content(data, cf, ws, po, items, w, full_text):
    content = data["content_findings"]

    script_count = content.get("script_count", 0)
    form_count = content.get("form_count", 0)
    password_inputs = content.get("password_inputs", 0)
    iframe_count = len(content.get("iframe_sources") or [])
    hidden_count = content.get("hidden_element_count", 0)
    meta_count = len(content.get("meta_refresh_urls") or [])

    if content.get("javascript_present"):
        ws += w["javascript_present"]
        items.append(_f("warning", "HTML Script Content",
                        f"Email contains {script_count} script tag(s).", f"Scripts: {script_count}"))

    if password_inputs or form_count:
        cf = max(cf, w["credential_form"])
        items.append(_f("critical", "Credential Form Indicators",
                        f"HTML contains {form_count} form(s) and {password_inputs} password input(s).",
                        f"Forms: {form_count} | Password inputs: {password_inputs}"))

    if hidden_count > 0:
        ws += 2
        samples = content.get("hidden_element_samples") or []
        items.append(_f("warning", "Hidden HTML Elements",
                        f"Email contains {hidden_count} hidden element(s).",
                        f"Hidden: {hidden_count} | Samples: {', '.join(samples[:3])}" if samples else f"Hidden: {hidden_count}"))

    if iframe_count > 0:
        sources = content.get("iframe_sources") or []
        ws += 2
        items.append(_f("warning", "Iframe Elements",
                        f"Email contains {iframe_count} iframe(s).",
                        f"Sources: {', '.join(defang(s) for s in sources[:3])}" if sources else f"Iframes: {iframe_count}"))

    if meta_count > 0:
        urls = content.get("meta_refresh_urls") or []
        ws += 2
        items.append(_f("warning", "Meta Refresh Redirects",
                        f"HTML contains {meta_count} meta-refresh redirect(s).",
                        f"URLs: {', '.join(defang(u) for u in urls[:3])}" if urls else f"Count: {meta_count}"))

    for theme_name, keywords in PHISHING_THEMES.items():
        matched = _match_keywords(full_text, keywords)
        if not matched:
            continue
        count = len(matched)
        if theme_name == "financial":
            pts = min(count, 4) + 1
            if count >= 3:
                cf = max(cf, 4)
            ws += pts
            items.append(_f("critical" if count >= 3 else "warning", "Financial Keywords Detected",
                            f"Found {count} financial/payment-related term(s).",
                            f"Matched: {', '.join(matched[:6])}"))
        elif theme_name == "credential_theft":
            pts = min(count, 4) + 1
            if count >= 3:
                cf = max(cf, w["high_risk_keywords"])
            ws += pts
            items.append(_f("critical" if count >= 3 else "warning", "Credential Theft Keywords",
                            f"Found {count} credential-phishing term(s).",
                            f"Matched: {', '.join(matched[:6])}"))
        elif theme_name == "urgency_pressure":
            if count >= 2:
                ws += 2
                items.append(_f("warning", "Pressure Language",
                                f"Found {count} urgency/pressure term(s).",
                                f"Matched: {', '.join(matched[:6])}"))
        elif theme_name == "social_engineering":
            if count >= 3:
                ws += 2
                items.append(_f("warning", "Social Engineering Language",
                                f"Found {count} social-engineering term(s).",
                                f"Matched: {', '.join(matched[:6])}"))

    body_brands = [b for b in IMPERSONATED_BRANDS if b in full_text]
    if body_brands:
        all_matched = _match_keywords(full_text, CREDENTIAL_KEYWORDS + URGENCY_KEYWORDS)
        if all_matched:
            cf = max(cf, w["impersonation_keywords"])
            items.append(_f("critical", "Brand Impersonation in Body",
                            f"Brand names appear with phishing-associated language.",
                            f"Brands: {', '.join(body_brands[:5])} | Keywords: {', '.join(all_matched[:3])}"))

    return cf, ws, po, items


def _score_urls(data, cf, ws, po, items, w):
    for url_record in data["url_results"]:
        url_defanged = defang(url_record.get("normalized_url") or "")
        host = url_record.get("host") or ""
        features = url_record.get("features") or []

        if url_record.get("deceptive_display"):
            cf = max(cf, w["deceptive_link"])
            displayed = defang(url_record.get("displayed_url") or "")
            items.append(_f("critical", "Deceptive Link",
                            f"Displayed URL does not match href for {url_defanged}.",
                            f"href={url_defanged} | display={displayed}"))

        if features:
            feature_count = len(features)
            has_encoded = any(kw in " ".join(features).lower()
                              for kw in ["jwt", "encoded", "base64", "email address"])
            has_tracking = any("tracking" in f.lower() for f in features)
            has_pii = any("email" in f.lower() or "pii" in f.lower() for f in features)

            base = w["suspicious_url_feature"]
            url_score = base + max(0, (feature_count - 1))

            if has_encoded or (has_tracking and has_pii):
                cf = max(cf, url_score)
            else:
                ws += url_score

            level = "critical" if has_encoded or (has_tracking and has_pii) else "warning"
            items.append(_f(level, "Suspicious URL Feature",
                            f"{url_defanged}: {', '.join(features)}.",
                            f"Host: {host} | Flags: {feature_count}"))

        if url_record.get("is_tracking_pixel"):
            ws += 3
            items.append(_f("warning", "Tracking Pixel Detected",
                            "URL is a tracking pixel/web beacon embedded as an image.",
                            f"Host: {host} | Source: {url_record.get('source', '')}"))

        if any(service in host for service in ABUSED_LEGIT_SERVICES):
            ws += w["abused_service_link"]
            items.append(_f("warning", "Abused Legit Service",
                            f"Link uses {host}, a service often abused for phishing.",
                            f"Service: {host}"))

    urlscan_results = data.get("urlscan", {})
    for url_val, us_result in urlscan_results.items():
        if urlscan_detection_flagged(us_result):
            us_text = urlscan_summary_text(us_result)
            brands = us_result.get("brands", [])
            categories = us_result.get("categories", [])
            detail_parts = [f"urlscan: {us_text}"]
            if brands:
                detail_parts.append(f"Brands: {', '.join(brands[:3])}")
            if categories:
                detail_parts.append(f"Categories: {', '.join(categories[:3])}")
            cf = max(cf, 5)
            items.append(_f("critical", "urlscan.io Flagged URL",
                            f"urlscan.io flagged {defang(url_val)} as malicious/suspicious.",
                            " | ".join(detail_parts)))

    return cf, ws, po, items


def _score_attachments(data, cf, ws, po, items, w):
    for attachment in data["attachment_results"]:
        detections = vt_detection_count(attachment.get("vt"))
        sha256 = attachment.get("hashes", {}).get("sha256", "")
        filename = attachment.get("filename", "unknown")
        detected_type = attachment.get("detected_type", "")
        size = attachment.get("size_bytes", 0)
        size_str = f"{size / 1024:.1f}KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f}MB"
        indicators = attachment.get("indicators") or []

        if detections > 0:
            vt_text = vt_summary_text(attachment.get("vt"))
            cf = max(cf, w["malicious_attachment"])
            items.append(_f("critical", "Malicious Attachment",
                            f"{filename} sha256={sha256} -> {vt_text}.",
                            f"VT: {vt_text} | Type: {detected_type} | Size: {size_str}"))
        elif indicators:
            cf = max(cf, w["suspicious_attachment"])
            items.append(_f("critical", "Suspicious Attachment",
                            f"{filename}: {', '.join(indicators)}.",
                            f"Type: {detected_type} | Size: {size_str} | Issues: {len(indicators)}"))

        ooxml = attachment.get("ooxml") or {}
        ole = attachment.get("ole") or {}
        if ooxml.get("macros_present") or ole.get("macros_present"):
            cf = max(cf, 8)
            items.append(_f("critical", "Macro-Enabled Document",
                            f"{filename} contains VBA macros.",
                            f"Type: {detected_type} | Macros: present"))

        embedded_urls = attachment.get("embedded_urls") or []
        if embedded_urls:
            ws += 2
            items.append(_f("warning", "URLs Inside Attachment",
                            f"{filename} contains {len(embedded_urls)} embedded URL(s).",
                            f"Type: {detected_type} | URLs: {len(embedded_urls)}"))

    return cf, ws, po, items


def _score_behavioral(data, header, full_text, cf, ws, po, items, w):
    has_attachments = bool(data["attachment_results"])

    all_phishing_kw = _match_keywords(full_text, CREDENTIAL_KEYWORDS + URGENCY_KEYWORDS + FINANCIAL_KEYWORDS)
    if has_attachments and all_phishing_kw:
        ws += 2
        items.append(_f("warning", "Attachment with Phishing Language",
                        "Email has attachments combined with phishing-associated wording.",
                        f"Attachments: {len(data['attachment_results'])} | Keywords: {', '.join(all_phishing_kw[:3])}"))

    auth_failures = 0
    if header.get("SPF Result", "pass") not in {"pass", "not found", "neutral", "none"}:
        auth_failures += 1
    if header.get("DKIM Result", "pass") not in {"pass", "not found", "neutral", "none"}:
        auth_failures += 1
    if header.get("DMARC Result", "pass") == "fail":
        auth_failures += 1
    if auth_failures >= 2:
        cf = max(cf, 6)
        items.append(_f("critical", "Multiple Authentication Failures",
                        f"Email failed {auth_failures} authentication checks.",
                        f"Failures: {auth_failures}/3"))

    has_mismatch = header.get("Return-Path Mismatch") or header.get("Reply-To Mismatch")
    has_urgency = _match_keywords(full_text, URGENCY_KEYWORDS)
    if has_mismatch and has_urgency:
        cf = max(cf, 5)
        items.append(_f("critical", "Mismatch with Urgency",
                        "Header mismatches combined with urgency language — classic phishing pattern.",
                        f"Urgency terms: {', '.join(has_urgency[:3])}"))

    url_count = len(data["url_results"])
    if url_count > 10:
        ws += 2
        items.append(_f("warning", "URL-Heavy Email",
                        f"Email contains {url_count} distinct URLs.", f"URLs: {url_count}"))

    domain_age = data["domain_age"]
    if domain_age is not None and domain_age < SETTINGS["domain_age_threshold_days"] * 2 and has_attachments:
        ws += 2
        items.append(_f("warning", "Young Domain with Attachment",
                        f"Young domain ({domain_age}d old) sending attachments.",
                        f"Age: {domain_age}d | Attachments: {len(data['attachment_results'])}"))

    return cf, ws, po, items


# ═══════════════════════════════════════════════════════════════════
# REPORT BUILDING
# ═══════════════════════════════════════════════════════════════════

def build_report(analysis_data, score, feedback_items, eml_file=None, verdict=None):
    return {
        "file": eml_file,
        "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score": score,
        "feedback": feedback_items,
        "summary": {
            "observable_count": len(analysis_data["observables"]),
            "url_count": len(analysis_data["url_results"]),
            "attachment_count": len(analysis_data["attachment_results"]),
            "sender_ips": analysis_data["header_findings"].get("Sender IPs", []),
        },
        "details": {
            "header_findings": analysis_data["header_findings"],
            "spoof_findings": analysis_data["spoof_findings"],
            "domain_age_days": analysis_data["domain_age"],
            "content_findings": analysis_data["content_findings"],
            "observables": analysis_data["observables"],
            "url_results": analysis_data["url_results"],
            "attachment_results": analysis_data["attachment_results"],
            "virustotal": analysis_data["virustotal"],
            "urlscan": analysis_data.get("urlscan", {}),
            "urlscan_doms": analysis_data.get("urlscan_doms", {}),
            "urlscan_hars": analysis_data.get("urlscan_hars", {}),
        },
    }
