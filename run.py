"""
Advanced Phishing Mail Detector — Web Application
Flask-based GUI for email phishing analysis.
"""

import contextlib
import io
import logging
import os
import tempfile
import webbrowser
from pathlib import Path
from threading import Timer

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

# Import from the modular package
from core import (
    analyze_attachment,
    analyze_domain_for_spoofing,
    analyze_header,
    analyze_html_content,
    analyze_url,
    build_observables,
    build_report,
    check_domain_age,
    enrich_with_virustotal,
    extract_links,
    generate_score_and_feedback,
    normalize_url,
    parse_eml_file,
    scan_images_for_qrcodes,
    unshorten_url,
    unique_list,
    url_host,
    clean_url,
    defang,
    registered_domain,
    vt_detection_count,
    urlscan_submit,
    urlscan_search_or_submit,
    urlscan_get_dom,
    urlscan_get_har,
    urlscan_detection_flagged,
    VT_AVAILABLE,
    WHOIS_AVAILABLE,
    URLSCAN_AVAILABLE,
)
from core.config import SETTINGS
from core.apis import urlscan_search


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# ── Helpers ───────────────────────────────────────────────────────
def bool_from_form(name):
    return str(request.form.get(name, "")).lower() in {"1", "true", "yes", "on"}


def normalize_url_record(record):
    cleaned = normalize_url(record.get("normalized_url") or record.get("url") or "")
    if not cleaned:
        return None
    normalized = dict(record)
    normalized["url"] = clean_url(normalized.get("url") or cleaned) or cleaned
    normalized["normalized_url"] = cleaned
    normalized["defanged"] = defang(cleaned)
    normalized["host"] = url_host(cleaned)
    normalized["registered_domain"] = registered_domain(normalized["host"])
    return normalized


def better_vt_result(current, candidate):
    if not current:
        return candidate
    if not candidate:
        return current
    if not isinstance(current, dict) or not isinstance(candidate, dict):
        return candidate or current
    if vt_detection_count(candidate) > vt_detection_count(current):
        return candidate
    if current.get("status") in {"not_found", "skipped", "error"} and candidate.get("status") == "ok":
        return candidate
    return current


def dedupe_url_records(url_records):
    deduped = {}
    for record in url_records:
        record = normalize_url_record(record)
        if not record:
            continue
        key = record["normalized_url"]
        if key not in deduped:
            deduped[key] = record
            continue
        deduped[key]["source"] = ",".join(
            unique_list(deduped[key]["source"].split(",") + [record["source"]])
        )
        deduped[key]["features"] = unique_list(deduped[key]["features"] + record["features"])
        deduped[key]["vt"] = better_vt_result(deduped[key].get("vt"), record.get("vt"))
    return list(deduped.values())


def normalize_attachment_urls(attachment_results):
    for attachment in attachment_results:
        embedded_urls = []
        for url in attachment.get("embedded_urls", []):
            cleaned = normalize_url(url)
            if cleaned:
                embedded_urls.append(cleaned)
        attachment["embedded_urls"] = unique_list(embedded_urls)
    return attachment_results


# ── Core analysis pipeline ────────────────────────────────────────
def build_analysis_payload(file_path, original_name, use_external_enrichment=False, resolve_redirects=False):
    msg, header_text, body, html_body, attachments, images = parse_eml_file(file_path)

    header_findings = analyze_header(msg)
    from_addr = header_findings.get("From Address")
    sender_domain = from_addr.split("@")[-1] if from_addr else None
    spoof_findings = analyze_domain_for_spoofing(sender_domain)
    domain_age = check_domain_age(sender_domain) if use_external_enrichment and sender_domain else None

    url_records = extract_links(body, html_body)
    url_records.extend(scan_images_for_qrcodes(images))

    attachment_results = normalize_attachment_urls(
        [analyze_attachment(att) for att in attachments]
    )
    for attachment in attachment_results:
        for embedded_url in attachment.get("embedded_urls", []):
            url_records.append(
                analyze_url(embedded_url, f"attachment.{attachment['filename']}.embedded_url")
            )

    url_records = dedupe_url_records(url_records)

    if resolve_redirects:
        for record in url_records:
            final_url, redirect_chain = unshorten_url(record["normalized_url"])
            record["final_url"] = final_url
            record["redirect_chain"] = redirect_chain
            if final_url and final_url != record["normalized_url"]:
                final_record = analyze_url(final_url, f"{record['source']}.redirect_final")
                record["features"] = unique_list(record["features"] + final_record["features"])

    content_findings = analyze_html_content(html_body)
    observables = build_observables(header_findings, url_records, attachment_results)

    vt_summary = enrich_with_virustotal(
        observables, url_records, attachment_results,
        delay_seconds=SETTINGS["default_vt_delay_seconds"] if use_external_enrichment else 0,
        max_items=SETTINGS["default_max_vt_items"],
        no_vt=not use_external_enrichment,
    )

    # urlscan.io enrichment — search existing scans first, then submit new ones
    urlscan_results = {}
    urlscan_doms = {}
    urlscan_hars = {}
    if use_external_enrichment and URLSCAN_AVAILABLE:
        for url_record in url_records[:5]:
            url_val = url_record.get("normalized_url") or url_record.get("url")
            if url_val and url_val not in urlscan_results:
                # Search first, submit only if not found
                result = urlscan_search_or_submit(url_val, tags=["phishing-detector", original_name[:50]])
                urlscan_results[url_val] = result
                url_record["urlscan"] = result

                # Fetch DOM and HAR for completed scans
                scan_id = result.get("scan_id")
                if scan_id and result.get("status") == "ok":
                    dom_result = urlscan_get_dom(scan_id)
                    if dom_result.get("status") == "ok":
                        urlscan_doms[url_val] = {
                            "size_bytes": dom_result.get("size_bytes", 0),
                            "content_type": dom_result.get("content_type", ""),
                            "dom_preview": dom_result.get("dom", "")[:2000],
                        }
                    har_result = urlscan_get_har(scan_id)
                    if har_result.get("status") == "ok":
                        urlscan_hars[url_val] = {
                            "total_entries": har_result.get("total_entries", 0),
                            "domains_contacted": har_result.get("domains_contacted", []),
                            "requests": har_result.get("requests", [])[:20],
                        }

        # Also search for domains found in the email
        sender_domain = from_addr.split("@")[-1] if from_addr else None
        if sender_domain:
            domain_search = urlscan_search(f"domain:{sender_domain}", size=3)
            if domain_search.get("status") == "ok" and domain_search.get("results"):
                urlscan_results[f"_search_domain:{sender_domain}"] = domain_search

    analysis_data = {
        "header_text": header_text,
        "header_findings": header_findings,
        "spoof_findings": spoof_findings,
        "url_results": url_records,
        "attachment_results": attachment_results,
        "observables": observables,
        "full_body": body + "\n" + html_body,
        "domain_age": domain_age,
        "content_findings": content_findings,
        "virustotal": vt_summary,
        "urlscan": urlscan_results,
        "urlscan_doms": urlscan_doms,
        "urlscan_hars": urlscan_hars,
    }

    score, feedback_items = generate_score_and_feedback(analysis_data)

    if score >= 7:
        verdict, severity = "UNSAFE", "high"
    elif score >= 4:
        verdict, severity = "CAUTIOUS", "medium"
    else:
        verdict, severity = "SAFE", "low"

    report = build_report(
        analysis_data, score, feedback_items, eml_file=original_name, verdict=verdict,
    )

    signal_counts = {"critical": 0, "warning": 0, "positive": 0}
    for item in feedback_items:
        level = item.get("level", "warning") if isinstance(item, dict) else "warning"
        if level in signal_counts:
            signal_counts[level] += 1

    return {
        "file": {"name": original_name, "size_bytes": os.path.getsize(file_path)},
        "verdict": verdict,
        "severity": severity,
        "score": score,
        "feedback": feedback_items,
        "signal_counts": signal_counts,
        "summary": report["summary"],
        "details": report["details"],
        "options": {
            "external_enrichment": use_external_enrichment,
            "resolve_redirects": resolve_redirects,
            "virustotal_available": VT_AVAILABLE,
            "whois_available": WHOIS_AVAILABLE,
            "urlscan_available": URLSCAN_AVAILABLE,
        },
        "report": report,
    }


# ── Routes ────────────────────────────────────────────────────────
@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze_upload():
    # CSRF protection: require X-Requested-With header (browsers won't send cross-origin)
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return jsonify({"error": "Missing X-Requested-With header."}), 403

    uploaded = request.files.get("email_file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Upload an .eml file before running analysis."}), 400

    original_name = secure_filename(uploaded.filename) or "uploaded_email.eml"
    suffix = Path(original_name).suffix or ".eml"
    use_external = bool_from_form("external_enrichment")
    resolve_redirects = bool_from_form("resolve_redirects")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            uploaded.save(tmp)
            tmp_path = tmp.name

        with contextlib.redirect_stdout(io.StringIO()):
            payload = build_analysis_payload(tmp_path, original_name, use_external, resolve_redirects)

        return jsonify(payload)
    except Exception as exc:
        logger.exception("Analysis failed")
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.errorhandler(413)
def upload_too_large(_exc):
    return jsonify({"error": "Upload too large. Maximum is 25 MB."}), 413


# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG") == "1"
    url = f"http://127.0.0.1:{port}/"

    if os.getenv("DISABLE_AUTO_OPEN") != "1":
        if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            Timer(0.8, lambda: webbrowser.open(url)).start()

    logger.info("Starting Phishing Mail Detector on %s", url)
    logger.info("VT API key: %s, urlscan API key: %s, whois: %s",
                "configured" if VT_AVAILABLE else "not set",
                "configured" if URLSCAN_AVAILABLE else "not set",
                "available" if WHOIS_AVAILABLE else "not installed")
    app.run(host="127.0.0.1", port=port, debug=debug)
