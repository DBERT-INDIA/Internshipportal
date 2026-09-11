# Canonical app â€” promoted from templates/app.py on 2026-06-04
from flask import Flask, render_template, request, jsonify, send_from_directory, Response, make_response, redirect, session, abort, g, has_request_context, flash
from urllib.parse import quote
from markupsafe import Markup, escape
import os
import io
import csv
import re
import smtplib
import sqlite3
import secrets
import hashlib
import hmac
import base64
import string
import random
import threading
from datetime import datetime, date, timedelta, time as dtime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import time
import uuid
import json
import requests


try:
    from dotenv import load_dotenv
    _env_dir = os.path.dirname(__file__)
    # Load legacy/server '_env' first, then '.env' (overrides) so local '.env' wins.
    load_dotenv(os.path.join(_env_dir, '_env'))
    load_dotenv(os.path.join(_env_dir, '.env'), override=True)
except ImportError:
    pass

app = Flask(__name__)
_FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
app.secret_key = _FLASK_SECRET_KEY or "digitalblinc2026secretkey"  # dev fallback; prod-guarded below
app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
# NF1 (spec Â§5.1) â€” root cause of the deep-link logout.
# Flask's own session cookie used to be called "dbert_session", which is ALSO the
# name the auth token was issued under historically. Any `session[...] = ...`
# (e.g. the tutor deep-link stashing post_login_return_to) therefore rewrote the
# cookie and destroyed the auth token: login "succeeded", the next request 401'd.
# The auth token now lives in "dbert_auth"; giving Flask a third, distinct name
# makes the collision structurally impossible and lets legacy "dbert_session"
# auth cookies keep working until they expire (read-fallback below).
app.config["SESSION_COOKIE_NAME"] = "dbert_flask"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# SEC-009: Default COOKIE_SECURE to True in production
is_prod = os.environ.get("FLASK_DEBUG", "false").lower() != "true"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1" if is_prod else "0") == "1"

app.config["SESSION_COOKIE_SECURE"] = COOKIE_SECURE
# Phase 8.0: trust exactly ONE proxy hop (Nginx). Safe only because Nginx overwrites
# X-Forwarded-For / X-Real-IP with the true client IP (see SECURITY_DEPLOY.md).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
TUTOR_SSO_SECRET = os.environ.get("TUTOR_SSO_SECRET", "")


def csp_nonce():
    """The per-response script nonce. Templates call this in every inline
    <script nonce="{{ csp_nonce() }}">.

    Generated once per request and cached on `g`, because every <script> on the
    page must carry the SAME value as the header. Returns '' when there is no
    request context (so a template rendered outside one still renders) and when
    CSP_ALLOW_INLINE is set â€” in that mode the header carries 'unsafe-inline'
    instead, and emitting a nonce would be what disables it.
    """
    if CSP_ALLOW_INLINE:
        return ""
    if not has_request_context():
        return ""
    n = getattr(g, "_csp_nonce", None)
    if n is None:
        n = secrets.token_urlsafe(16)
        g._csp_nonce = n
    return n


@app.context_processor
def inject_globals():
    """Phase 12.5/12.6 â€” make GA4 id + canonical origin available to every template."""
    return {"GA4_ID": GA4_ID, "SITE_ORIGIN": SITE_ORIGIN,
            "OG_IMAGE_URL": OG_IMAGE_URL, "LOGO_URL": LOGO_URL,
            "csp_nonce": csp_nonce}
TUTOR_BASE_URL = os.environ.get("TUTOR_BASE_URL", "https://tutor.dbert.online")
# Guard: crash loudly on startup if a secret is missing/defaulted in production â€”
# prevents a silent same-value match (SSO forgery) or a forgeable session cookie.
if os.environ.get("FLASK_DEBUG", "false").lower() != "true":
    assert _FLASK_SECRET_KEY, (
        "FLASK_SECRET_KEY must be explicitly set in production (the default dev "
        "key would let anyone forge session cookies)."
    )

ONESIGNAL_APP_ID      = os.environ.get("ONESIGNAL_APP_ID",      "1b181bc1-46b8-4359-ac7a-e87ecab91be4")
ONESIGNAL_REST_API_KEY = os.environ.get("ONESIGNAL_REST_API_KEY", "")
CRON_SECRET           = os.environ.get("CRON_SECRET", "")  # protects /cron/* endpoints; set in .env
# Track 2 Â§7 instant-indexing (all OPTIONAL â€” graceful no-op if unset; never block publish).
# Google Indexing API service-account JSON (the whole key file contents) + IndexNow key.
GOOGLE_INDEXING_SA_JSON = os.environ.get("GOOGLE_INDEXING_SA_JSON", "")
INDEXNOW_KEY            = os.environ.get("INDEXNOW_KEY", "")
# Phase 8.4: optional Cloudflare Turnstile (invisible) â€” DEFAULT OFF. When disabled,
# verify_turnstile() passes through, so no UI/UX change. Flip on via .env later.
TURNSTILE_ENABLED  = os.environ.get("TURNSTILE_ENABLED", "false").lower() == "true"
TURNSTILE_SECRET   = os.environ.get("TURNSTILE_SECRET", "")
TURNSTILE_SITEKEY  = os.environ.get("TURNSTILE_SITEKEY", "")
# Phase 5 (spec Â§5.3), completed in Phase 9: the policy is ENFORCED and
# script-src is now NONCE-BASED â€” 'unsafe-inline' is gone.
#
# How this works, and why it had to be done in one move:
#   A nonce in script-src makes browsers IGNORE 'unsafe-inline' completely.
#   That is the whole point â€” injected <script> no longer runs â€” but it also
#   kills every inline event handler, because a nonce is an attribute of a
#   <script> element and cannot be attached to an onclick="". So the nonce and
#   the removal of the 300 inline handlers had to land together; there is no
#   half-way state where both work.
#
#   Every inline <script> now carries nonce="{{ csp_nonce() }}", and every
#   former on*= handler is a data-act-* attribute dispatched by
#   static/js/csp-actions.js. Nothing evaluates a string as code, so
#   'unsafe-eval' is not needed either.
#
# style-src KEEPS 'unsafe-inline': the markup carries many style="" attributes,
# and a nonce cannot cover an attribute. That is a much smaller exposure than
# script â€” an attacker gains styling, not execution â€” and closing it means
# removing every inline style attribute, which is a separate piece of work.
#
# OPS ESCAPE HATCHES, in increasing order of retreat:
#   CSP_ENFORCE=0      -> report-only; violations are reported, nothing blocked.
#   CSP_ALLOW_INLINE=1 -> drop the nonce and put 'unsafe-inline' back. Only for
#                         an emergency: it restores the pre-Phase-9 exposure.
#                         Note both cannot apply at once â€” a nonce present in
#                         the header is exactly what disables 'unsafe-inline'.
CSP_ENFORCE = os.environ.get("CSP_ENFORCE", "1") == "1"
CSP_ALLOW_INLINE = os.environ.get("CSP_ALLOW_INLINE", "0") == "1"

_CSP_SCRIPT_ORIGINS = (
    "https://cdn.onesignal.com https://cdnjs.cloudflare.com "
    "https://challenges.cloudflare.com https://www.googletagmanager.com"
)


def csp_policy_for(nonce):
    """The policy for one response. `nonce` is '' only when CSP_ALLOW_INLINE."""
    script_src = (
        f"script-src 'self' 'unsafe-inline' {_CSP_SCRIPT_ORIGINS}"
        if not nonce else
        f"script-src 'self' 'nonce-{nonce}' {_CSP_SCRIPT_ORIGINS}"
    )
    return (
        "default-src 'self'; "
        f"{script_src}; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://onesignal.com https://*.onesignal.com https://api.onesignal.com https://www.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com; "
        "frame-src https://challenges.cloudflare.com; "
        "worker-src 'self' https://cdn.onesignal.com; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        "object-src 'none'"
    )


# Nonce-free rendering of the policy, for ops tooling that wants to read it
# without a request in hand.
CSP_POLICY = csp_policy_for("")
CSP_REPORT_ONLY = CSP_POLICY  # kept: referenced elsewhere / by ops tooling
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# P2-6: Production configuration validation
if not _is_debug:
    if len(app.config.get("SECRET_KEY", "")) < 32:
        print("[WARNING] FLASK_SECRET_KEY is shorter than 32 chars.")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "careers@dbert.online")
SMTP_PASS = os.environ.get("SMTP_PASS", "")  # never hardcode â€” supplied via .env
FROM_EMAIL = os.environ.get("FROM_EMAIL", "careers@dbert.online")
FROM_NAME  = os.environ.get("FROM_NAME", "DBERT Careers")
# Email transport. "ses" = Amazon SES HTTPS API (port 443 â€” bypasses blocked SMTP :587,
# and SES auto-signs DKIM once the domain is verified). "smtp" = legacy Gmail/SMTP (default).
# SES creds come from the standard AWS chain: an EC2 IAM role (preferred) or
# AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in the environment. Requires `pip install boto3`.
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "smtp").lower()
AWS_SES_REGION = os.environ.get("AWS_SES_REGION", os.environ.get("AWS_REGION", "us-east-1"))
# T17: "cpanel_api" = relay through the standalone dbert-mailer microservice (T18),
# which sends over localhost SMTP on the cPanel box (not blocked like EC2 egress).
CPANEL_EMAIL_API_URL = os.environ.get("CPANEL_EMAIL_API_URL", "")
CPANEL_EMAIL_API_KEY = os.environ.get("CPANEL_EMAIL_API_KEY", "")
# Master switch: when false, NO emails are sent (logged as SKIPPED). Push notifications are
# unaffected â€” they are sent independently via send_push_notification(). Flip to true to resume.
EMAILS_ENABLED = os.environ.get("EMAILS_ENABLED", "true").lower() == "true"

def _resolve_db_file():
    """Resolve the live DB. If DB_FILE is set in environment, use it.
    Otherwise fall back to internship.db in the project root."""
    _env_db = os.environ.get("DB_FILE", "")
    if _env_db:
        return _env_db
    return os.path.join(os.path.dirname(__file__), "internship.db")

DB_FILE          = _resolve_db_file()
ALLOWED_EXT      = {"png", "jpg", "jpeg", "pdf"}
SESSION_DAYS     = 7
ADMIN_KEY        = os.environ.get("ADMIN_KEY", "dbert_admin_2026")          # kept for legacy CSV exports
ADMIN_USERNAME   = os.environ.get("ADMIN_USERNAME", "dbert_admin")
ADMIN_PASSWORD   = os.environ.get("ADMIN_PASSWORD", "dbert_admin_2026")

# Production guard: refuse to boot with shipped default credentials/secret when not in debug.
# (Mirrors the TUTOR_SSO_SECRET guard above. Prevents an accidental insecure deploy.)
if os.environ.get("FLASK_DEBUG", "false").lower() != "true":
    _insecure = []
    if app.secret_key == "digitalblinc2026secretkey": _insecure.append("FLASK_SECRET_KEY")
    if ADMIN_PASSWORD == "dbert_admin_2026":           _insecure.append("ADMIN_PASSWORD")
    if ADMIN_KEY == "dbert_admin_2026":                _insecure.append("ADMIN_KEY")
    if ADMIN_USERNAME == "dbert_admin":                _insecure.append("ADMIN_USERNAME")
    assert not _insecure, (
        "Refusing to start in production with default value(s) for: " + ", ".join(_insecure) +
        ". Set strong values in .env (or set FLASK_DEBUG=true for local dev)."
    )

# â”€â”€ Phase 5 Â§5.4: encryption key for financial PII (ambassador UPI ids) â”€â”€â”€â”€
# Deliberately NO hardcoded fallback. Unlike the Gemini-key helper, a silent
# default here would mean payout details are "encrypted" with a key that is in
# the source tree â€” worse than plaintext, because it looks safe.
# The guard only fires once the referral program is switched on, so this does
# not block deploys before Phase 7 ships.
FERNET_KEY = os.environ.get("FERNET_KEY", "")
AMBASSADOR_ENABLED = os.environ.get("AMBASSADOR_ENABLED", "0") == "1"
if AMBASSADOR_ENABLED and os.environ.get("FLASK_DEBUG", "false").lower() != "true":
    assert FERNET_KEY, (
        "FERNET_KEY must be set when AMBASSADOR_ENABLED=1 â€” ambassador UPI ids "
        "are financial PII and are stored encrypted (spec Â§5.4). Generate one "
        "with: python -c \"from cryptography.fernet import Fernet; "
        "print(Fernet.generate_key().decode())\""
    )
UPI_ID           = os.environ.get("UPI_ID", "Q681021429@ybl")
UPI_AMOUNT       = int(os.environ.get("UPI_AMOUNT", "499"))
# Phase 12 â€” paid program (parallel product to the â‚¹499 free-track deposit).
PAID_PROGRAM_AMOUNT = int(os.environ.get("PAID_PROGRAM_AMOUNT", "1599"))
# Phase 12.5 â€” Google Analytics 4 measurement id (shared across all pages).
GA4_ID = os.environ.get("GA4_ID", "G-GZ17KZ7MDW")
# Spec Â§8 â€” Measurement Protocol secret for SERVER-side events (referral_signup /
# referral_conversion fire in request handlers where there is no gtag). Optional:
# unset means those two events simply do not send.
GA4_API_SECRET = os.environ.get("GA4_API_SECRET", "")
# Canonical public origin for SEO tags (canonical/OG/sitemap).
SITE_ORIGIN = os.environ.get("SITE_ORIGIN", "https://internship.dbert.online")
# Spec Â§7 â€” AdSense publisher id for /ads.txt. Format: pub- + 16 digits.
# Overridable per-environment so staging never claims production's inventory.
ADSENSE_PUB_ID = os.environ.get("ADSENSE_PUB_ID", "pub-1320532532258767")
# Optional absolute URLs for social/preview assets. Left blank by default so we never
# emit a broken og:image / logo reference; set these once the assets exist.
OG_IMAGE_URL = os.environ.get("OG_IMAGE_URL", "")
LOGO_URL     = os.environ.get("LOGO_URL", "")
_deadline_str = os.environ.get("ENROLLMENT_DEADLINE", "2026-12-31")
ENROLLMENT_DEADLINE = date(*map(int, _deadline_str.split("-")))

# â”€â”€ Phase 8: rate-limit config â€” (limit, window_seconds), env-overridable â”€â”€
def _rl(name, default_limit, default_window):
    return (int(os.environ.get(f"RL_{name}_LIMIT", default_limit)),
            int(os.environ.get(f"RL_{name}_WINDOW", default_window)))
RL_LOGIN_EMAIL   = _rl("LOGIN_EMAIL",   5, 900)    # 5 / 15 min per email
RL_LOGIN_IP      = _rl("LOGIN_IP",     20, 900)    # 20 / 15 min per IP
RL_APPLY_IP      = _rl("APPLY_IP",      3, 3600)   # 3 / hour per IP
RL_FORGOT_EMAIL  = _rl("FORGOT_EMAIL",  3, 3600)   # 3 / hour per email
RL_FORGOT_IP     = _rl("FORGOT_IP",    10, 3600)   # 10 / hour per IP
RL_RESET_IP      = _rl("RESET_IP",     10, 3600)   # 10 / hour per IP
RL_CHECKEMAIL_IP = _rl("CHECKEMAIL_IP", 20, 600)   # 20 / 10 min per IP
RL_SETPW_IP      = _rl("SETPW_IP",     10, 3600)   # 10 / hour per IP
RL_ENROLL_IP     = _rl("ENROLL_IP",     5, 3600)   # 5 / hour per IP
RL_COMMENT_IP    = _rl("COMMENT_IP",   20, 600)    # 20 / 10 min per IP
RL_COMMENT_INTERN = _rl("COMMENT_INTERN", 10, 600) # 10 / 10 min per intern
RL_MAX_WINDOW    = 7200                              # rate_purge horizon (> largest window)

# â”€â”€ P17: mobile auth token lifetimes (seconds), env-overridable â”€â”€
# Access = short-lived HS256 JWT (reuses TUTOR_SSO_SECRET). Refresh = opaque,
# long-lived, stored hashed in mobile_refresh_tokens and rotated on every use.
ACCESS_TTL  = int(os.environ.get("ACCESS_TTL",  "3600"))                 # 1 hour
REFRESH_TTL = int(os.environ.get("REFRESH_TTL", str(60 * 24 * 3600)))   # 60 days

# Phase 9: max distinct applications (domains) one person may have. Env-overridable.
MAX_APPLICATIONS_PER_PERSON = int(os.environ.get("MAX_APPLICATIONS_PER_PERSON", "3"))

# â”€â”€ Phase 11: AI pre-selection interview (Gemini) config â”€â”€
def _parse_gemini_keys():
    """Ordered, de-duplicated key list. Supports GEMINI_API_KEYS (comma-separated)
    plus GEMINI_API_KEY / GEMINI_API_KEY_1..N. Server-side only â€” never sent to the browser."""
    keys, seen = [], set()
    def _add(v):
        v = (v or "").strip()
        if v and v not in seen:
            seen.add(v); keys.append(v)
    for k in os.environ.get("GEMINI_API_KEYS", "").split(","):
        _add(k)
    _add(os.environ.get("GEMINI_API_KEY", ""))
    for i in range(1, 21):
        _add(os.environ.get(f"GEMINI_API_KEY_{i}", ""))
    return keys

GEMINI_API_KEYS         = _parse_gemini_keys()
GEMINI_MODEL            = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
INTERVIEW_ENABLED       = os.environ.get("INTERVIEW_ENABLED", "true").lower() == "true"
GITHUB_TOKEN            = os.environ.get("GITHUB_TOKEN", "").strip()
GEMINI_TIMEOUT          = int(os.environ.get("GEMINI_TIMEOUT", "8"))    # seconds per call (was 30)
# Wall-clock cap on the whole GitHub+Gemini network phase of /interview/start. Once
# exceeded, _gemini_call stops trying further keys/retries and returns None â†’ static
# bank. Guarantees the endpoint returns fast even if every key is dead/expired.
GEMINI_TOTAL_BUDGET     = int(os.environ.get("GEMINI_TOTAL_BUDGET", "30"))  # seconds, combined (was 12)
GITHUB_TIMEOUT          = int(os.environ.get("GITHUB_TIMEOUT", "6"))    # seconds per GitHub call (was 15)
GEMINI_ENDPOINT         = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
# How many questions the interview asks. Must equal the sum of INTERVIEW_BLUEPRINT counts
# (the static bank assembles exactly this many). Override via env only alongside the blueprint.
# T5: domain-only blueprint (technical 2 + applied 1 + communication 1) -- the generic
# learning/commitment/goals/obstacle INTERVIEW_SHARED_BANK sections were dropped.
INTERVIEW_NUM_QUESTIONS = int(os.environ.get("INTERVIEW_NUM_QUESTIONS", "4"))
INTERVIEW_MAX_ATTEMPTS  = int(os.environ.get("INTERVIEW_MAX_ATTEMPTS", "2"))
INTERVIEW_COOLING_HOURS = int(os.environ.get("INTERVIEW_COOLING_HOURS", "24"))
RL_INTERVIEW_IP         = _rl("INTERVIEW_IP", 10, 3600)   # 10 / hour per IP (start/submit)

STATUS_APPLY_PENDING      = "Apply Pending"
STATUS_UNDER_REVIEW       = "Under Review"
STATUS_ON_HOLD            = "On Hold"
STATUS_SELECTED           = "Selected"
STATUS_ENROLLMENT_PENDING = "Enrollment Pending"
STATUS_ENROLLED           = "Enrolled"
STATUS_ACCEPTED           = "Accepted"
STATUS_REJECTED           = "Rejected"
STATUS_PAID_ENROLLED      = "Paid-Enrolled"   # Phase 12 â€” â‚¹1599 direct-enroll (parallel paid track)

VALID_STATUSES = {
    STATUS_APPLY_PENDING, STATUS_UNDER_REVIEW, STATUS_ON_HOLD,
    STATUS_SELECTED, STATUS_ENROLLMENT_PENDING, STATUS_ENROLLED,
    STATUS_ACCEPTED, STATUS_REJECTED, STATUS_PAID_ENROLLED,
}

VALID_DOMAINS = [
    "AI Agent Development",
    "Data Analyst",
    "Full Stack Development",
    "Python Automation",
]

DOMAIN_SLUGS = {
    d: d.lower().replace(" ", "-") for d in VALID_DOMAINS
}

_LIVE_SQL = "status='published' AND (expires_at IS NULL OR expires_at > datetime('now','localtime'))"

# T7: public ids for portal-authored courses are offset so they never collide with
# tutor course ids in certifications_json / course_payments.course_id.
_PORTAL_COURSE_ID_OFFSET = 100000

VALID_COURSES = [
    "B.Tech", "B.E.", "BCA", "B.Sc", "BBA", "B.Com",
    "M.Tech", "MCA", "M.Sc", "MBA", "Diploma", "Other",
]

VALID_SEMESTERS = [
    "1st Semester", "2nd Semester", "3rd Semester", "4th Semester",
    "5th Semester", "6th Semester", "7th Semester", "8th Semester", "Graduate",
]

VALID_YEARS = [str(y) for y in range(2024, 2033)]

JOB_DESCRIPTIONS = {
    "AI Agent Development": {
        "icon": "ðŸ¤–", "type": "Remote / Part-time",
        "skills": ["Python", "LangChain", "OpenAI API", "RAG Pipelines", "FastAPI"],
        "work": ["Build LLM-powered autonomous agents", "Design and implement RAG pipelines",
                 "Integrate external APIs with AI workflows", "Test and evaluate agent performance"],
        "stipend": "â‚¹8,000 â€“ â‚¹18,000/month", "duration": "2 months",
    },
    "Data Analyst": {
        "icon": "ðŸ“Š", "type": "Remote / Part-time",
        "skills": ["Python", "SQL", "Excel", "Power BI", "Pandas"],
        "work": ["Clean and process raw datasets", "Build interactive dashboards",
                 "Generate weekly insight reports", "Support business decisions with data"],
        "stipend": "â‚¹6,000 â€“ â‚¹14,000/month", "duration": "2 months",
    },
    "Full Stack Development": {
        "icon": "ðŸ’»", "type": "Remote / Part-time",
        "skills": ["HTML/CSS", "JavaScript", "React or Flask", "REST APIs", "SQL"],
        "work": ["Build responsive web interfaces", "Develop and consume REST APIs",
                 "Maintain and extend existing codebases", "Deploy features to production"],
        "stipend": "â‚¹7,000 â€“ â‚¹16,000/month", "duration": "2 months",
    },
    "Python Automation": {
        "icon": "âš™ï¸", "type": "Remote / Part-time",
        "skills": ["Python", "Selenium", "BeautifulSoup", "APIs", "Scheduling"],
        "work": ["Build web scrapers and bots", "Automate repetitive business workflows",
                 "Create scheduled data pipelines", "Integrate third-party APIs"],
        "stipend": "â‚¹5,000 â€“ â‚¹12,000/month", "duration": "2 months",
    },
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com",
    "trashmail.com", "sharklasers.com", "dispostable.com", "mintemail.com", "maildrop.cc",
    "getnada.com", "temp-mail.org", "tempmailo.com", "emailondeck.com", "throwawaymail.com",
    "fakeinbox.com", "moakt.com", "mytemp.email", "tmpmail.org", "tempmail.dev",
}

DOMAIN_ALIASES = {
    "ai agent": "AI Agent Development", "ai agent development": "AI Agent Development", "ai": "AI Agent Development",
    "data analyst": "Data Analyst", "data analysis": "Data Analyst", "data": "Data Analyst",
    "full stack": "Full Stack Development", "full stack development": "Full Stack Development",
    "fullstack": "Full Stack Development", "web": "Full Stack Development",
    "python": "Python Automation", "python automation": "Python Automation",
    "python automantion": "Python Automation",
}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# HELPERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def normalize_domain(raw):
    if not raw: return None
    cleaned = raw.strip().lower()
    if cleaned in DOMAIN_ALIASES: return DOMAIN_ALIASES[cleaned]
    for alias, canonical in DOMAIN_ALIASES.items():
        if alias in cleaned: return canonical
    for d in VALID_DOMAINS:
        if d.lower() in cleaned or cleaned in d.lower(): return d
    return None


def row_to_dict(row):
    return {k: row[k] for k in row.keys()}


def log_error(context, e): print(f"[{context}] Error: {e}")
def log_security_event(event, details=None, severity="INFO"):
    """P2-4: Structured security event logging for monitoring/SIEM."""
    from flask import g
    import json as _json
    entry = {
        "ts": now_str(),
        "event": event,
        "severity": severity,
        "ip": get_client_ip() if has_request_context() else "",
        "path": request.path if has_request_context() else "",
        "req_id": getattr(g, "request_id", "") if has_request_context() else "",
    }
    if details:
        entry["details"] = details
    print(f"[SECURITY] {_json.dumps(entry)}")


def log_info(context, msg): print(f"[{context}] {msg}")
def now_str(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def hash_password(p): return hashlib.sha256((p or "").encode()).hexdigest()

# â”€â”€ P17.0: password-hash upgrade (legacy unsalted SHA-256 -> salted KDF) â”€â”€
# Legacy rows store a bare 64-hex SHA-256 digest. New rows store a werkzeug
# salted KDF hash (e.g. "pbkdf2:sha256:...$salt$hash"). verify_password reads
# both; set_password_hash always writes the new format; login paths lazily
# re-hash a legacy row to the new format on a successful login.
_LEGACY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def is_legacy_hash(stored_hash):
    """True only for the old bare unsalted SHA-256 (64 lowercase hex) format."""
    return bool(stored_hash) and bool(_LEGACY_HASH_RE.match(stored_hash))


def set_password_hash(plaintext):
    """Hash a password for storage with a salted KDF (new format).
    pbkdf2:sha256 is chosen for portability â€” it needs no OpenSSL scrypt."""
    return generate_password_hash(plaintext or "", method="pbkdf2:sha256")


def verify_password(stored_hash, plaintext):
    """Constant-time-ish verify of `plaintext` against either a legacy unsalted
    SHA-256 hash or a new salted KDF hash. Pure: never writes to the DB â€” callers
    do lazy migration via is_legacy_hash() after a successful verify."""
    if not stored_hash:
        return False
    if is_legacy_hash(stored_hash):
        return hmac.compare_digest(stored_hash, hash_password(plaintext))
    try:
        return check_password_hash(stored_hash, plaintext or "")
    except Exception:
        return False


def migrate_password_hash(table, email, plaintext):
    """Lazy migration: re-hash a verified legacy password to the new KDF format
    and update the row in place. `table` is an internal constant (intern_accounts
    / mentors), never user input. Best-effort â€” a failure must not break login."""
    try:
        with get_db() as conn:
            conn.execute(
                f"UPDATE {table} SET password_hash=?, updated_at=? WHERE email=?",
                (set_password_hash(plaintext), now_str(), email.lower()),
            )
            conn.commit()
    except Exception as e:
        log_error("pw-migrate", e)


def generate_password(n=10): return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))
def allowed_file(fn): return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def sniff_upload_type(file_storage):
    """Phase 8.5: verify real file type by magic bytes (not extension).
    Returns 'png' | 'jpg' | 'pdf' or None. Rewinds the stream afterwards."""
    try:
        head = file_storage.stream.read(8)
        file_storage.stream.seek(0)
    except Exception:
        return None
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"%PDF"):
        return "pdf"
    return None
def is_valid_email(e): return bool(re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", e or ""))
def is_valid_email_domain(email):
    if not is_valid_email(email): return False
    return email.split("@")[-1].lower().strip() not in DISPOSABLE_DOMAINS
def is_valid_phone(p): return bool(re.match(r"^[6-9]\d{9}$", p or ""))
def is_valid_url(u):
    if not u: return True
    return bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", u.strip(), re.IGNORECASE))

def clean_text(v):
    if v is None: return ""
    if isinstance(v, float):
        import math
        if math.isnan(v): return ""
        return str(v).strip()
    return str(v).strip()

def get_client_ip():
    # Phase 8.0: trust X-Real-IP (set by Nginx to the true client) first, then the
    # ProxyFix-corrected remote_addr. Do NOT read X-Forwarded-For directly (forgeable).
    xri = request.headers.get("X-Real-IP", "").strip()
    return xri or (request.remote_addr or "")


# â”€â”€ Phase 8.1: shared SQLite rate-limit core (consistent across Gunicorn workers) â”€â”€
def rate_purge():
    """Opportunistic cleanup of rate_events older than the largest window."""
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM rate_events WHERE created_at < ?", (time.time() - RL_MAX_WINDOW,))
            conn.commit()
    except Exception as e:
        log_error("rate_purge", e)


def rate_check(bucket, limit, window_seconds):
    """Sliding-window check shared by all workers via the rate_events table.
    Returns (allowed: bool, retry_after: int). Records the event when allowed.
    Fails OPEN (never blocks real users) if the limiter DB errors."""
    now = time.time()
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM rate_events WHERE bucket=? AND created_at < ?",
                         (bucket, now - window_seconds))
            cnt = conn.execute("SELECT COUNT(*) FROM rate_events WHERE bucket=?", (bucket,)).fetchone()[0]
            if cnt >= limit:
                oldest = conn.execute("SELECT MIN(created_at) FROM rate_events WHERE bucket=?",
                                      (bucket,)).fetchone()[0]
                conn.commit()
                retry_after = max(1, int((oldest + window_seconds) - now) + 1) if oldest else window_seconds
                return (False, retry_after)
            conn.execute("INSERT INTO rate_events (bucket, created_at) VALUES (?,?)", (bucket, now))
            conn.commit()
        if random.random() < 0.01:
            rate_purge()
        return (True, 0)
    except Exception as e:
        log_error("rate_check", e)
        # SEC-010: Fail closed to prevent abuse during DB issues
        return (False, 60)


def too_many(retry_after):
    """Standard 429 response with a Retry-After header."""
    resp = make_response(jsonify({
        "status": "error",
        "message": "Too many requests. Please try again later.",
        "retry_after": int(retry_after),
    }), 429)
    resp.headers["Retry-After"] = str(int(retry_after))
    return resp


def log_abuse(ip, route, bucket, reason, email=None):
    """Record a blocked/abusive request for the admin Security tab (8.6)."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO abuse_log (timestamp, ip, route, bucket, reason, email) VALUES (?,?,?,?,?,?)",
                (now_str(), ip, route, bucket, reason, (email or None))
            )
            conn.commit()
    except Exception as e:
        log_error("log_abuse", e)


# â”€â”€ Phase 8.2: per-account failed-login lockout (failures only; cleared on success) â”€â”€
def _login_fail_bucket(identity):
    return f"loginfail:email:{identity}"

def login_locked(identity):
    """(locked, retry_after) for an identity based on failed attempts in the window.
    Fails OPEN on DB error."""
    limit, window = RL_LOGIN_EMAIL
    now = time.time()
    bucket = _login_fail_bucket(identity)
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM rate_events WHERE bucket=? AND created_at < ?", (bucket, now - window))
            cnt = conn.execute("SELECT COUNT(*) FROM rate_events WHERE bucket=?", (bucket,)).fetchone()[0]
            if cnt >= limit:
                oldest = conn.execute("SELECT MIN(created_at) FROM rate_events WHERE bucket=?",
                                      (bucket,)).fetchone()[0]
                conn.commit()
                return (True, max(1, int((oldest + window) - now) + 1) if oldest else window)
            conn.commit()
        return (False, 0)
    except Exception as e:
        log_error("login_locked", e)
        return (False, 0)

def record_login_fail(identity):
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO rate_events (bucket, created_at) VALUES (?,?)",
                         (_login_fail_bucket(identity), time.time())); conn.commit()
    except Exception as e:
        log_error("record_login_fail", e)

def clear_login_fails(identity):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM rate_events WHERE bucket=?", (_login_fail_bucket(identity),)); conn.commit()
    except Exception as e:
        log_error("clear_login_fails", e)


# â”€â”€ Phase 8.4: invisible bot defenses (signed timing token + Turnstile passthrough) â”€â”€
def make_timing_token():
    """Signed page-load timestamp. Form submit echoes it back; verify_timing_token
    enforces a minimum human fill time and a max age."""
    ts = str(int(time.time() * 1000))
    sig = hmac.new(app.secret_key.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(ts.encode()).decode() + "." + sig

def verify_timing_token(token, min_ms=3000, max_ms=3600 * 1000):
    """True only if the token is authentic AND elapsed is in [min_ms, max_ms]."""
    try:
        b64, sig = (token or "").split(".", 1)
        ts = base64.urlsafe_b64decode(b64.encode()).decode()
        expected = hmac.new(app.secret_key.encode(), ts.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        elapsed = int(time.time() * 1000) - int(ts)
        return min_ms <= elapsed <= max_ms
    except Exception:
        return False

def verify_turnstile(token, ip):
    """Cloudflare Turnstile check. Disabled by default (returns True). When enabled,
    verifies server-side; fails OPEN if Cloudflare is unreachable (availability)."""
    if not TURNSTILE_ENABLED:
        return True
    if not TURNSTILE_SECRET or not token:
        return False
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip},
            timeout=8,
        )
        return bool(r.json().get("success"))
    except Exception as e:
        log_error("turnstile", e)
        return True

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    # Production: with multiple Gunicorn workers sharing one SQLite file, wait for locks
    # instead of failing instantly with "database is locked".
    conn.execute("PRAGMA busy_timeout=8000")
    return conn

def ensure_column(conn, table, col, defn):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if col not in cols: conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")

def get_config(key, default=None):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT value FROM platform_config WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
    except Exception as e:
        log_error("get_config", e)
        return default

def set_config(key, value):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO platform_config (key, value, updated_at) VALUES (?, ?, datetime('now','localtime')) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now','localtime')",
                (key, str(value))
            )
            conn.commit()
            return True
    except Exception as e:
        log_error("set_config", e)
        return False

# â”€â”€ UP2.1: BYOK Gemini Key Encryption Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _encrypt_gemini_key(raw_key: str) -> str:
    if not raw_key:
        return ""
    secret = (_FLASK_SECRET_KEY or "dbert_gemini_encryption_secret_2026").encode('utf-8')
    nonce = secrets.token_bytes(16)
    key_bytes = raw_key.encode('utf-8')
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(key_bytes):
        msg = nonce + counter.to_bytes(4, 'big')
        keystream.extend(hmac.new(secret, msg, hashlib.sha256).digest())
        counter += 1
    cipher_bytes = bytes([b ^ k for b, k in zip(key_bytes, keystream[:len(key_bytes)])])
    token = nonce + cipher_bytes
    return base64.urlsafe_b64encode(token).decode('utf-8')

def _decrypt_gemini_key(encrypted_str: str) -> str:
    if not encrypted_str:
        return ""
    try:
        token = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
        if len(token) < 17:
            return ""
        nonce = token[:16]
        cipher_bytes = token[16:]
        secret = (_FLASK_SECRET_KEY or "dbert_gemini_encryption_secret_2026").encode('utf-8')
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(cipher_bytes):
            msg = nonce + counter.to_bytes(4, 'big')
            keystream.extend(hmac.new(secret, msg, hashlib.sha256).digest())
            counter += 1
        plain_bytes = bytes([b ^ k for b, k in zip(cipher_bytes, keystream[:len(cipher_bytes)])])
        return plain_bytes.decode('utf-8')
    except Exception:
        return ""

def _hash_gemini_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.strip().encode('utf-8')).hexdigest()

# â”€â”€ UP2.2: Daily Fallback Quota Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def get_daily_fallback_usage(intern_id, usage_date=None):
    if usage_date is None:
        usage_date = date.today().isoformat()
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT count FROM dbert_fallback_usage WHERE intern_id = ? AND usage_date = ?",
                (intern_id, usage_date)
            ).fetchone()
            return row["count"] if row else 0
    except Exception as e:
        log_error("get_daily_fallback_usage", e)
        return 0

def increment_daily_fallback_usage(intern_id, usage_date=None):
    if usage_date is None:
        usage_date = date.today().isoformat()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO dbert_fallback_usage (intern_id, usage_date, count) VALUES (?, ?, 1) "
                "ON CONFLICT(intern_id, usage_date) DO UPDATE SET count = count + 1",
                (intern_id, usage_date)
            )
            conn.commit()
            return True
    except Exception as e:
        log_error("increment_daily_fallback_usage", e)
        return False

def can_use_fallback(intern_id, usage_date=None):
    limit = int(get_config("GEMINI_FALLBACK_DAILY_LIMIT", "5"))
    current = get_daily_fallback_usage(intern_id, usage_date)
    return current < limit

def _validate_gemini_key_live(raw_key: str):
    if not raw_key or not raw_key.startswith("AIza"):
        return False, None
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={raw_key.strip()}"
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            data = r.json()
            models = [m.get("name") for m in data.get("models", []) if "generateContent" in m.get("supportedGenerationMethods", [])]
            return True, models
        return False, None
    except Exception as e:
        log_error("validate_gemini_key", e)
        return False, None

# â”€â”€ UP3.2: Unified Staff Review Audit Logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def log_staff_review(queue_name, staff_id, subject_type, subject_id, decision, reason_code=None, reviewed_input_snapshot=None):
    try:
        snapshot_json = json.dumps(reviewed_input_snapshot) if isinstance(reviewed_input_snapshot, (dict, list)) else reviewed_input_snapshot
        with get_db() as conn:
            conn.execute(
                "INSERT INTO review_log (queue_name, staff_id, subject_type, subject_id, decision, reason_code, reviewed_input_snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (queue_name, staff_id, subject_type, subject_id, decision, reason_code, snapshot_json)
            )
            conn.commit()
            return True
    except Exception as e:
        log_error("log_staff_review", e)
        return False

def current_staff():
    staff_id = session.get("staff_id")
    if not staff_id:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM staff_accounts WHERE id = ? AND is_active = 1", (staff_id,)).fetchone()
        return dict(row) if row else None








def get_week_bounds(ref_date=None):
    """Return (week_start, week_end) as date objects for the Sunâ€“Sat week containing ref_date."""
    if ref_date is None:
        ref_date = date.today()
    # weekday(): Mon=0 â€¦ Sun=6  â†’  days since Sunday = (weekday+1) % 7
    days_since_sunday = (ref_date.weekday() + 1) % 7
    week_start = ref_date - timedelta(days=days_since_sunday)
    week_end   = week_start + timedelta(days=6)
    return week_start, week_end


UPCOMING_MONDAYS_COUNT = 3

def get_upcoming_mondays():
    """Return at most the next 3 upcoming Mondays (strictly future; if today is
    Monday, start from next Monday), each on or before 31 Dec 2026.
    Format: list of '%Y-%m-%d' strings."""
    mondays = []
    today = date.today()
    # Next Monday is always strictly in the future (7 days ahead if today is Monday).
    if today.weekday() == 0:
        next_monday = today + timedelta(days=7)
    else:
        next_monday = today + timedelta(days=(7 - today.weekday()))
    current = next_monday
    while current <= ENROLLMENT_DEADLINE and len(mondays) < UPCOMING_MONDAYS_COUNT:
        mondays.append(current.strftime("%Y-%m-%d"))
        current += timedelta(days=7)
    return mondays


def make_batch_label(joining_date_str):
    """Convert '2026-07-21' â†’ '21 Jul 2026 Batch'"""
    try:
        d = datetime.strptime(joining_date_str, "%Y-%m-%d")
        return d.strftime("%-d %b %Y Batch")
    except Exception:
        return joining_date_str + " Batch"


def validate_joining_date(joining_date_str, allow_past_for_backfill=False):
    """Validate that joining_date is a Monday, <= 31 Dec 2026, not in the past,
    AND is one of the currently-available joining Mondays (next 3).
    allow_past_for_backfill=True (Track 6 addendum, admin-only bulk-accept import):
    still requires a real Monday and skips the not-in-the-past / must-be-upcoming
    checks, for backfilling interns whose real joining date has already occurred.
    Default False preserves the original behavior for every other caller
    (the interactive self-serve enrollment flow)."""
    try:
        d = datetime.strptime(joining_date_str, "%Y-%m-%d").date()
    except Exception:
        return False, "Invalid date format."
    if d.weekday() != 0:
        return False, "Joining date must be a Monday."
    if d > ENROLLMENT_DEADLINE:
        return False, "Joining date must be on or before 31 Dec 2026."
    if allow_past_for_backfill:
        return True, ""
    if d < date.today():
        return False, "Joining date cannot be in the past."
    if joining_date_str not in get_upcoming_mondays():
        return False, "Please choose one of the available joining Mondays."
    return True, ""


def auto_assign_joining_date_on_accept(conn, app_row):
    """When an application transitions to Accepted, every accepted intern needs a
    joining_date set -- otherwise course content unlocks immediately instead of
    waiting for their batch start (see joining_unlocked()). If they already
    self-enrolled (paid the deposit, picked their own Monday), that choice is left
    untouched. Only applicants with NO enrollment row at all get one auto-created
    here (next upcoming Monday, no payment screenshot -- admin override, not a real
    deposit). Used by both the single-edit modal and the bulk-status action, since
    both call admin_update_application_status(). Returns the joining_date to surface
    in the status-update email (existing, newly-assigned, or None)."""
    email = app_row["email"]
    existing = conn.execute("SELECT joining_date FROM enrollments WHERE email=? LIMIT 1", (email,)).fetchone()
    if existing:
        return existing["joining_date"]
    mondays = get_upcoming_mondays()
    if not mondays:
        return None  # e.g. past the enrollment deadline -- nothing sensible to assign
    joining_date = mondays[0]
    batch_label  = make_batch_label(joining_date)
    acct = conn.execute("SELECT * FROM intern_accounts WHERE email=? LIMIT 1", (email,)).fetchone()
    name            = acct["name"]            if acct else app_row["name"]
    phone           = acct["phone"]           if acct else app_row["phone"]
    city            = acct["city"]            if acct else app_row["city"]
    college         = acct["college"]         if acct else app_row["college"]
    course          = acct["course"]          if acct else app_row["course"]
    semester        = acct["semester"]        if acct else app_row["semester"]
    year_of_passing = acct["year_of_passing"] if acct else app_row["year_of_passing"]
    conn.execute("""
        INSERT INTO enrollments
        (application_id,timestamp,name,email,phone,city,college,course,semester,
        year_of_passing,domain,joining_date,batch_label,payment_screenshot,payment_status,
        admin_note,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (app_row["id"], now_str(), name, email, phone, city, college, course, semester,
          year_of_passing, app_row["domain"], joining_date, batch_label, "", "Accepted",
          "Auto-enrolled on admin Accept (no deposit/screenshot on file).", now_str(), now_str()))
    return joining_date


def joining_unlocked(joining_date_str):
    """True if now >= joining date at 18:00 server-local. Empty/invalid = unlocked."""
    if not joining_date_str:
        return True
    try:
        jd = datetime.strptime(joining_date_str, "%Y-%m-%d").date()
        return datetime.now() >= datetime.combine(jd, dtime(18, 0))   # dtime = datetime.time
    except ValueError:
        return True


def init_db():
    with get_db() as conn:
        # Production: WAL allows concurrent readers during a write â€” much better under
        # multiple Gunicorn workers. Persistent DB-level setting; safe to re-assert.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception as e:
            log_error("init-wal", e)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL,
                city TEXT NOT NULL, college TEXT NOT NULL, course TEXT NOT NULL,
                semester TEXT NOT NULL, year_of_passing TEXT NOT NULL, domain TEXT NOT NULL,
                why_join TEXT NOT NULL, portfolio TEXT,
                status TEXT DEFAULT 'Apply Pending',
                mentor_note TEXT, mentor_email TEXT, reviewed_at TEXT,
                rejected_at TEXT,
                visitor_id TEXT, source TEXT DEFAULT 'web',
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(email, domain)
            );
            CREATE TABLE IF NOT EXISTS intern_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, application_id INTEGER,
                name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, phone TEXT,
                city TEXT, college TEXT, course TEXT, semester TEXT, year_of_passing TEXT,
                domain TEXT, password_hash TEXT, password_set INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(application_id) REFERENCES applications(id)
            );
            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, application_id INTEGER,
                timestamp TEXT NOT NULL, name TEXT, email TEXT NOT NULL UNIQUE,
                phone TEXT, city TEXT, college TEXT, course TEXT, semester TEXT,
                year_of_passing TEXT, domain TEXT,
                joining_date TEXT,
                batch_label TEXT,
                payment_screenshot TEXT,
                payment_status TEXT DEFAULT 'Pending Verification',
                admin_note TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(application_id) REFERENCES applications(id)
            );
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL,
                role TEXT DEFAULT 'intern', session_token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS device_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT, email TEXT,
                ip_address TEXT, user_agent TEXT, screen_res TEXT, timezone TEXT,
                language TEXT, device_type TEXT, referrer TEXT,
                is_return_visit INTEGER DEFAULT 0, visit_count INTEGER DEFAULT 1,
                time_on_page INTEGER DEFAULT 0, intent_score INTEGER DEFAULT 0,
                path TEXT, last_seen TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS mentors (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE, domain TEXT NOT NULL,
                password_hash TEXT, is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS email_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                email TEXT NOT NULL, name TEXT, subject TEXT,
                email_sent TEXT DEFAULT 'YES'
            );
            CREATE TABLE IF NOT EXISTS check_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                email TEXT NOT NULL, name TEXT, check_count INTEGER, ip TEXT
            );
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                week_start TEXT NOT NULL,
                week_end   TEXT NOT NULL,
                total_minutes INTEGER DEFAULT 0,
                updated_at TEXT,
                UNIQUE(intern_id, week_start),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE TABLE IF NOT EXISTS tutor_progress (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id       INTEGER NOT NULL,
                lessons_json    TEXT    DEFAULT '[]',
                quizzes_json    TEXT    DEFAULT '[]',
                projects_json   TEXT    DEFAULT '[]',
                completion_pct  REAL    DEFAULT 0.0,
                total_lessons   INTEGER DEFAULT 0,
                done_lessons    INTEGER DEFAULT 0,
                updated_at      TEXT,
                UNIQUE(intern_id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE TABLE IF NOT EXISTS rate_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rate_bucket_time ON rate_events(bucket, created_at);
            CREATE TABLE IF NOT EXISTS abuse_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                route TEXT,
                bucket TEXT,
                reason TEXT,
                email TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_abuse_time ON abuse_log(id DESC);
            CREATE TABLE IF NOT EXISTS interviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                application_id INTEGER,
                domain TEXT,
                attempt_no INTEGER DEFAULT 1,
                status TEXT DEFAULT 'not_started',
                questions_json TEXT,
                answers_json TEXT,
                mentor_assessment_json TEXT,
                candidate_focus_json TEXT,
                github_summary TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_interviews_email ON interviews(email);
            CREATE TABLE IF NOT EXISTS mobile_refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,   -- HASH of the refresh token, never plaintext
                intern_id  TEXT NOT NULL,          -- str(intern_accounts.id)
                email      TEXT NOT NULL,
                issued_at  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked    INTEGER NOT NULL DEFAULT 0,
                last_used_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_mobile_refresh_hash   ON mobile_refresh_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_mobile_refresh_intern ON mobile_refresh_tokens(intern_id);
            -- Track 1 Â§6: the tutor PUSHES coin + certificate events here over the
            -- durable outbox. These are read-only MIRRORS â€” the portal never
            -- credits/debits coins; the tutor owns reconcile_balances. Dedupe on
            -- the per-event idem_key / (intern,cert) UNIQUE so replays are safe.
            CREATE TABLE IF NOT EXISTS coin_ledger_mirror (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id     INTEGER NOT NULL,
                -- Phase 4 two-ledger model (spec Â§4). Two INDEPENDENT ledgers,
                -- never mixed:
                --   'task'       credit, spendable in-portal (course discount)
                --   'referral'   credit, withdrawable only (10% commission)
                --   'spent'      debit, task-coin redemption in-portal
                --   'withdrawal' debit, approved referral payout
                -- The legacy 'earned' and 'ad' kinds are migrated to 'task'.
                ledger_kind   TEXT NOT NULL,
                delta         INTEGER NOT NULL,
                balance_after INTEGER,
                reason        TEXT,
                event_ts      TEXT,
                received_at   TEXT DEFAULT (datetime('now','localtime')),
                idem_key      TEXT UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_coin_mirror_intern ON coin_ledger_mirror(intern_id, event_ts);
            CREATE INDEX IF NOT EXISTS idx_coin_mirror_kind ON coin_ledger_mirror(intern_id, ledger_kind);

            -- â”€â”€ Phase 7: College Ambassador (spec Â§6.2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            CREATE TABLE IF NOT EXISTS referrals (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_intern_id INTEGER NOT NULL,
                referred_email     TEXT,
                referred_intern_id INTEGER,          -- filled when they sign up
                source_code        TEXT,
                status             TEXT DEFAULT 'clicked',   -- clicked|signed_up|converted
                flagged            INTEGER DEFAULT 0,        -- Â§6.4 device-overlap flag
                flag_reason        TEXT,
                created_at         TEXT DEFAULT (datetime('now','localtime')),
                updated_at         TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_intern_id, status);
            CREATE INDEX IF NOT EXISTS idx_referrals_referred ON referrals(referred_intern_id);
            -- one attribution row per referred account: re-clicking a link must
            -- not inflate the funnel or double-credit on conversion.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_referrals_unique_referred
                ON referrals(referred_intern_id) WHERE referred_intern_id IS NOT NULL;

            CREATE TABLE IF NOT EXISTS ambassador_withdrawals (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id            INTEGER NOT NULL,
                amount               INTEGER NOT NULL,
                status               TEXT DEFAULT 'pending',  -- pending|approved|paid|rejected
                requested_at         TEXT DEFAULT (datetime('now','localtime')),
                reviewed_by_admin_id INTEGER,
                reviewed_at          TEXT,
                admin_note           TEXT,
                upi_viewed_by        TEXT,   -- Â§6.5 audit: who decrypted the UPI
                upi_viewed_at        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_withdrawals_intern ON ambassador_withdrawals(intern_id, status);
            -- Phase 4 one-time, idempotent migration (spec Â§4). credit_intern_coins()
            -- historically wrote 'earned', and the retired ad path wrote 'ad'; both
            -- are task-side credits, so they fold into 'task'. No real ad balances
            -- exist to preserve â€” that path has returned 410 for some time.
            UPDATE coin_ledger_mirror SET ledger_kind='task'
             WHERE ledger_kind IN ('earned','ad');
            CREATE TABLE IF NOT EXISTS intern_certificates (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id    INTEGER NOT NULL,
                course_id    INTEGER,
                course_title TEXT,
                cert_id      TEXT,
                issued_at    TEXT,
                url          TEXT,
                received_at  TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(intern_id, cert_id)
            );
            CREATE INDEX IF NOT EXISTS idx_intern_certs_intern ON intern_certificates(intern_id);
            -- Track 2 Â§1: third-party companies that post jobs/internships. One
            -- login per company (work email = login id). Admin approves before any
            -- post can be published; drafting is allowed while unapproved.
            CREATE TABLE IF NOT EXISTS companies (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE,
                phone         TEXT,
                website       TEXT,
                about         TEXT,
                password_hash TEXT,
                is_approved   INTEGER DEFAULT 0,
                is_active     INTEGER DEFAULT 1,
                created_at    TEXT DEFAULT (datetime('now','localtime')),
                updated_at    TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_companies_email ON companies(email);
            -- Track 2 Â§6: intern CV (one per intern). Public page /cv/<slug>;
            -- certificates are auto-pulled from intern_certificates at render.
            CREATE TABLE IF NOT EXISTS cvs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id       INTEGER NOT NULL UNIQUE,
                slug            TEXT UNIQUE,
                headline        TEXT,
                summary         TEXT,
                skills_json     TEXT,
                projects_json   TEXT,
                experience_json TEXT,
                education_json  TEXT,
                links_json      TEXT,
                is_public       INTEGER DEFAULT 1,
                updated_at      TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_cvs_slug ON cvs(slug);
            -- Track 2 Â§2: third-party job/internship posts. Max 3 LIVE per company;
            -- auto-expire 30 days after publish. URL = <slug>-<id>.
            CREATE TABLE IF NOT EXISTS posts (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id         INTEGER NOT NULL,
                post_type          TEXT NOT NULL,
                domain             TEXT NOT NULL,
                title              TEXT NOT NULL,
                slug               TEXT,
                description        TEXT,
                responsibilities   TEXT,
                skills             TEXT,
                location           TEXT,
                work_mode          TEXT,
                stipend_min        INTEGER,
                stipend_max        INTEGER,
                pay_period         TEXT,
                is_unpaid          INTEGER DEFAULT 0,
                duration           TEXT,
                openings           INTEGER DEFAULT 1,
                apply_by           TEXT,
                certifications_json TEXT,
                eligibility        TEXT,
                status             TEXT DEFAULT 'draft',
                published_at       TEXT,
                expires_at         TEXT,
                views              INTEGER DEFAULT 0,
                created_at         TEXT DEFAULT (datetime('now','localtime')),
                updated_at         TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );
            CREATE INDEX IF NOT EXISTS idx_posts_company ON posts(company_id, status);
            CREATE INDEX IF NOT EXISTS idx_posts_live ON posts(post_type, status, domain);
            -- Track 2 Â§3: an application = Apply-Now + a REQUIRED comment (the
            -- comment is public; the record/CV/status is private to the company).
            CREATE TABLE IF NOT EXISTS post_applications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id    INTEGER NOT NULL,
                intern_id  INTEGER NOT NULL,
                comment    TEXT NOT NULL,
                cv_id      INTEGER,
                status     TEXT DEFAULT 'Applied',
                created_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(post_id, intern_id),
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_postapps_post ON post_applications(post_id, id);
            CREATE INDEX IF NOT EXISTS idx_postapps_intern ON post_applications(intern_id);
            -- T4: public comment thread on a post. ANY signed-up intern can comment here
            -- without applying -- distinct from post_applications.comment, which is the
            -- private company-only "interest note" submitted alongside an application.
            CREATE TABLE IF NOT EXISTS post_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL, intern_id INTEGER NOT NULL,
                body TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(post_id) REFERENCES posts(id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id));
            CREATE INDEX IF NOT EXISTS idx_postcomments_post ON post_comments(post_id, id);
            -- T6: company-uploaded interview questions for a post. UGC -- stays 'pending'
            -- until an admin approves it; only approved questions ever reach an intern.
            CREATE TABLE IF NOT EXISTS post_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL, company_id INTEGER NOT NULL,
                text TEXT NOT NULL, sort_order INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',  -- pending|approved|rejected
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(post_id) REFERENCES posts(id));
            CREATE INDEX IF NOT EXISTS idx_postq_post ON post_questions(post_id, sort_order);
            -- Track 2 Â§5: unified messaging. A conversation is always anchored to an
            -- intern + a non-intern counterparty (mentor|admin|company). NEVER
            -- internâ†”intern. post_id is normalised to 0 (not NULL) so the UNIQUE
            -- key dedupes one thread per (intern, counterparty, post). admin is a
            -- singleton realm â†’ counterparty_id = 0.
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                counterparty_type TEXT NOT NULL,   -- 'mentor'|'admin'|'company'
                counterparty_id INTEGER NOT NULL,
                post_id INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(intern_id, counterparty_type, counterparty_id, post_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_type TEXT NOT NULL,         -- 'intern'|'mentor'|'admin'|'company'
                sender_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
            );
            CREATE INDEX IF NOT EXISTS idx_conv_intern ON conversations(intern_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_conv_cp ON conversations(counterparty_type, counterparty_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, id);
            -- UAT #26: durable in-app notifications (the Notifications tab). Written
            -- alongside every push so users can review/clear past notices.
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                kind TEXT DEFAULT 'general',
                title TEXT NOT NULL,
                body TEXT,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_notif_intern ON notifications(intern_id, is_read, created_at);
            -- UAT #25: paid-course payments (QR + screenshot, admin-verified â†’ tutor unlock).
            CREATE TABLE IF NOT EXISTS course_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                course_id INTEGER NOT NULL,
                course_title TEXT,
                amount INTEGER,
                payment_screenshot TEXT,
                status TEXT DEFAULT 'pending',     -- pending|verified|rejected
                admin_note TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_course_pay_active
                ON course_payments(intern_id, course_id) WHERE status IN ('pending','verified');
            -- Track 5: â‚¹499 refundable security deposit for job-board hires (post_applications
            -- flow), separate from the legacy applications/enrollments table entirely -- the
            -- legacy flow is a closed, non-growing population (confirmed via EC2 data: zero new
            -- web-multistep applications since 2026-06-29) and is left completely untouched.
            CREATE TABLE IF NOT EXISTS post_hire_deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_application_id INTEGER NOT NULL,
                intern_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                amount INTEGER,
                payment_screenshot TEXT,
                status TEXT DEFAULT 'pending',     -- pending|verified|rejected|refunded
                admin_note TEXT,
                refunded_at TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                updated_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_post_hire_deposit_active
                ON post_hire_deposits(post_application_id) WHERE status IN ('pending','verified');
            -- T7: portal-side courses (admin/DBERT or company-authored), merged into
            -- _public_courses() alongside the tutor catalogue. Public-facing ids are
            -- offset by _PORTAL_COURSE_ID_OFFSET so they never collide with tutor ids
            -- in certifications_json / course_payments.course_id.
            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                slug TEXT,
                domain TEXT,
                company_id INTEGER,                 -- NULL = DBERT/admin course
                is_paid INTEGER DEFAULT 0,
                price_inr INTEGER DEFAULT 0,
                content_status TEXT DEFAULT 'pending', -- pending|approved|rejected (DBERT review before co-sign)
                source TEXT DEFAULT 'custom',       -- 'custom' | 'tutor'
                is_active INTEGER DEFAULT 1,
                payout_note TEXT,                   -- back-office: remittance to company (DBERT collects)
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_courses_status ON courses(content_status, is_active);
            -- UAT #35: company-hosted Cohorts. A cohort is an open-to-all, virtual
            -- (Zoom/Discord) learning session; the company sets date/time + link;
            -- admin-approves before it goes live; interns enrol â†’ get the link +
            -- an auto reminder 1h before (cron). Converges with #36-B (events).
            CREATE TABLE IF NOT EXISTS cohorts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id  INTEGER NOT NULL,
                title       TEXT NOT NULL,
                description TEXT,
                skills      TEXT,
                platform    TEXT,                      -- 'Zoom'|'Discord'|...
                meeting_url TEXT,                      -- revealed to enrollees only
                starts_at   TEXT,                      -- 'YYYY-MM-DD HH:MM' (IST)
                capacity    INTEGER DEFAULT 0,         -- 0 = unlimited
                status      TEXT DEFAULT 'pending',    -- pending|published|rejected
                created_at  TEXT DEFAULT (datetime('now','localtime')),
                updated_at  TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );
            CREATE INDEX IF NOT EXISTS idx_cohorts_company ON cohorts(company_id, status);
            CREATE INDEX IF NOT EXISTS idx_cohorts_live ON cohorts(status, starts_at);
            CREATE TABLE IF NOT EXISTS cohort_enrollments (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                cohort_id     INTEGER NOT NULL,
                intern_id     INTEGER NOT NULL,
                reminder_sent INTEGER DEFAULT 0,
                created_at    TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(cohort_id, intern_id),
                FOREIGN KEY(cohort_id) REFERENCES cohorts(id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_cohort_enr ON cohort_enrollments(cohort_id, intern_id);
            -- UAT #36-D: interns follow a company â†’ get alerts (notifications) when
            -- the company publishes a new post or a new cohort goes live.
            CREATE TABLE IF NOT EXISTS company_follows (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id  INTEGER NOT NULL,
                company_id INTEGER NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(intern_id, company_id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id),
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );
            CREATE INDEX IF NOT EXISTS idx_follows_company ON company_follows(company_id);
            CREATE INDEX IF NOT EXISTS idx_follows_intern ON company_follows(intern_id);
            -- UP0.2: Unified platform config table
            CREATE TABLE IF NOT EXISTS platform_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now','localtime'))
            );
            -- UP1.2: Guided Learning tables
            CREATE TABLE IF NOT EXISTS course_chapters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL,
                day_number INTEGER NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(course_id) REFERENCES courses(id)
            );
            CREATE INDEX IF NOT EXISTS idx_chapters_course ON course_chapters(course_id, day_number);

            CREATE TABLE IF NOT EXISTS course_subtopics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chapter_id INTEGER NOT NULL,
                sort_order INTEGER NOT NULL,
                title TEXT NOT NULL,
                brief TEXT NOT NULL,
                key_takeaways_json TEXT,
                prompt_seed TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(chapter_id) REFERENCES course_chapters(id)
            );
            CREATE INDEX IF NOT EXISTS idx_subtopics_chapter ON course_subtopics(chapter_id, sort_order);

            CREATE TABLE IF NOT EXISTS course_enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                course_id INTEGER NOT NULL,
                enrolled_at TEXT DEFAULT (datetime('now','localtime')),
                last_accessed_at TEXT DEFAULT (datetime('now','localtime')),
                current_day INTEGER DEFAULT 1,
                completed_at TEXT,
                UNIQUE(intern_id, course_id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id),
                FOREIGN KEY(course_id) REFERENCES courses(id)
            );
            CREATE INDEX IF NOT EXISTS idx_course_enr_intern ON course_enrollments(intern_id);

            CREATE TABLE IF NOT EXISTS course_subtopic_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enrollment_id INTEGER NOT NULL,
                subtopic_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(enrollment_id) REFERENCES course_enrollments(id),
                FOREIGN KEY(subtopic_id) REFERENCES course_subtopics(id)
            );
            CREATE INDEX IF NOT EXISTS idx_chats_subtopic ON course_subtopic_chats(enrollment_id, subtopic_id);

            CREATE TABLE IF NOT EXISTS course_day_quizzes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL,
                day_number INTEGER NOT NULL,
                questions_json TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(course_id, day_number),
                FOREIGN KEY(course_id) REFERENCES courses(id)
            );

            CREATE TABLE IF NOT EXISTS day_quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enrollment_id INTEGER NOT NULL,
                day_quiz_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                tab_switches INTEGER DEFAULT 0,
                time_taken_sec INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(enrollment_id) REFERENCES course_enrollments(id),
                FOREIGN KEY(day_quiz_id) REFERENCES course_day_quizzes(id)
            );
            CREATE INDEX IF NOT EXISTS idx_quiz_attempts_enr ON day_quiz_attempts(enrollment_id, day_quiz_id);
            -- UP2.1: BYOK Gemini encrypted key store
            CREATE TABLE IF NOT EXISTS user_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                encrypted_key TEXT NOT NULL,
                key_hash TEXT UNIQUE,
                validated_at TEXT,
                available_models_json TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_user_keys_intern ON user_api_keys(intern_id);
            -- UP2.2: Daily fallback usage tracking
            CREATE TABLE IF NOT EXISTS dbert_fallback_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                usage_date TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(intern_id, usage_date),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_fallback_usage ON dbert_fallback_usage(intern_id, usage_date);
            -- UP3.1: Staff accounts and queue role assignments
            CREATE TABLE IF NOT EXISTS staff_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_staff_email ON staff_accounts(email);

            CREATE TABLE IF NOT EXISTS staff_queue_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_id INTEGER NOT NULL,
                queue_name TEXT NOT NULL,
                UNIQUE(staff_id, queue_name),
                FOREIGN KEY(staff_id) REFERENCES staff_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_staff_roles ON staff_queue_roles(staff_id, queue_name);
            -- UP3.2: Unified audit log for staff queue reviews
            CREATE TABLE IF NOT EXISTS review_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queue_name TEXT NOT NULL,
                staff_id INTEGER NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reason_code TEXT,
                reviewed_input_snapshot TEXT,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(staff_id) REFERENCES staff_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_review_queue ON review_log(queue_name, created_at);
            CREATE INDEX IF NOT EXISTS idx_review_subject ON review_log(subject_type, subject_id);
            -- UP4.1: Capstone project briefs and intern submission queue
            CREATE TABLE IF NOT EXISTS course_projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL UNIQUE,
                brief TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(course_id) REFERENCES courses(id)
            );

            CREATE TABLE IF NOT EXISTS project_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enrollment_id INTEGER NOT NULL,
                intern_id INTEGER NOT NULL,
                course_id INTEGER NOT NULL,
                github_repo_url TEXT NOT NULL,
                project_title TEXT NOT NULL,
                project_description TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                reviewed_by_staff_id INTEGER,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(enrollment_id) REFERENCES course_enrollments(id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id),
                FOREIGN KEY(course_id) REFERENCES courses(id),
                FOREIGN KEY(reviewed_by_staff_id) REFERENCES staff_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_project_sub_status ON project_submissions(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_project_sub_intern ON project_submissions(intern_id, course_id);

            -- UP5.1: Open Tasks, versions, and intern task submissions
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                coin_reward INTEGER NOT NULL DEFAULT 10,
                is_active INTEGER DEFAULT 1,
                author_type TEXT DEFAULT 'admin',
                author_id INTEGER,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_active ON tasks(is_active, created_at);

            CREATE TABLE IF NOT EXISTS task_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                instructions TEXT NOT NULL,
                rubric TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                UNIQUE(task_id, version_number),
                FOREIGN KEY(task_id) REFERENCES tasks(id)
            );
            CREATE INDEX IF NOT EXISTS idx_task_ver ON task_versions(task_id, version_number);

            CREATE TABLE IF NOT EXISTS task_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intern_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                task_version_id INTEGER NOT NULL,
                submission_content TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                coins_awarded INTEGER DEFAULT 0,
                reviewed_by_staff_id INTEGER,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id),
                FOREIGN KEY(task_id) REFERENCES tasks(id),
                FOREIGN KEY(task_version_id) REFERENCES task_versions(id),
                FOREIGN KEY(reviewed_by_staff_id) REFERENCES staff_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_task_sub_status ON task_submissions(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_task_sub_intern ON task_submissions(intern_id, task_id);

            -- UP7.1: Mentor 1-on-1 availability slots and intern bookings
            CREATE TABLE IF NOT EXISTS mentor_availability_slots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mentor_staff_id INTEGER NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                is_booked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(mentor_staff_id) REFERENCES staff_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_mentor_slots ON mentor_availability_slots(mentor_staff_id, is_booked, start_time);

            CREATE TABLE IF NOT EXISTS mentor_session_bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_id INTEGER NOT NULL UNIQUE,
                intern_id INTEGER NOT NULL,
                meeting_link TEXT,
                status TEXT DEFAULT 'booked',
                created_at TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY(slot_id) REFERENCES mentor_availability_slots(id),
                FOREIGN KEY(intern_id) REFERENCES intern_accounts(id)
            );
            CREATE INDEX IF NOT EXISTS idx_mentor_bookings ON mentor_session_bookings(intern_id, status);

            -- UP9.1: Email verification OTP storage
            CREATE TABLE IF NOT EXISTS signup_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                otp TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            );
            CREATE INDEX IF NOT EXISTS idx_signup_otps ON signup_otps(email, is_used, expires_at);
        """)
        # Seed UP0.2 default config & feature flags
        defaults = [
            ("FREE_COURSE_QUOTA", "5"),
            ("POST_QUOTA_MIN_PRICE_INR", "99"),
            ("COIN_TO_INR_RATE", "1"),
            ("GEMINI_FALLBACK_DAILY_LIMIT", "5"),
            ("FLAG_GUIDED_LEARNING", "0"),
            ("FLAG_BYOK_REQUIRED", "0"),
            ("FLAG_TASKS_COINS", "0"),
            ("FLAG_CERT_GATE", "0"),
            ("FLAG_MENTOR_SESSIONS", "0"),
            ("FLAG_PAID_1999_LIVE", "0"),
        ]
        for k, v in defaults:
            conn.execute("INSERT OR IGNORE INTO platform_config (key, value) VALUES (?, ?)", (k, v))
        conn.commit()
        # Seed UP3.1 default staff account from admin credentials
        staff_email = f"{ADMIN_USERNAME}@dbert.online"
        existing_staff = conn.execute("SELECT id FROM staff_accounts WHERE email = ?", (staff_email,)).fetchone()
        if not existing_staff:
            pwd_hash = generate_password_hash(ADMIN_PASSWORD)
            conn.execute(
                "INSERT INTO staff_accounts (name, email, password_hash) VALUES (?, ?, ?)",
                ("DBERT Admin Staff", staff_email, pwd_hash)
            )
            staff_id = conn.execute("SELECT id FROM staff_accounts WHERE email = ?", (staff_email,)).fetchone()["id"]
            for q in ["courses", "payments", "projects", "tasks"]:
                conn.execute(
                    "INSERT OR IGNORE INTO staff_queue_roles (staff_id, queue_name) VALUES (?, ?)",
                    (staff_id, q)
                )
            conn.commit()
        # Migrate existing tables safely
        for col, defn in [
            ("city", "TEXT"), ("course", "TEXT"), ("year_of_passing", "TEXT"),
            ("visitor_id", "TEXT"), ("source", "TEXT DEFAULT 'web'"), ("updated_at", "TEXT"),
            ("rejected_at", "TEXT"),
            ("enroll_reminders_sent", "INTEGER DEFAULT 0"), ("last_reminder_at", "TEXT"),
            # Phase 13: indirect purchase-intent answers captured at signup stage 3 (JSON).
            ("intent_answers", "TEXT"),
        ]:
            ensure_column(conn, "applications", col, defn)
        for col, defn in [
            ("password_set", "INTEGER DEFAULT 0"), ("course", "TEXT"),
            ("year_of_passing", "TEXT"), ("city", "TEXT"), ("application_id", "INTEGER"),
            ("tutor_completion_pct", "REAL DEFAULT 0.0"), ("tutor_updated_at", "TEXT"),
            ("tutor_seconds_credited", "INTEGER DEFAULT 0"),
            ("tutor_week_credited", "TEXT DEFAULT ''"),
            # Phase 11: interview profile URLs + attempt tracking
            ("linkedin_url", "TEXT"), ("github_url", "TEXT"),
            ("interview_attempts", "INTEGER DEFAULT 0"),
            ("interview_last_attempt_at", "TEXT"),
            ("interview_locked", "INTEGER DEFAULT 0"),
            # Phase 13: multistep signup â€” consent + progress tracking.
            # signup_stage: 0/1=account created, 2=academics done, 3=application submitted (complete).
            ("terms_accepted_at", "TEXT"), ("newsletter_opt_in", "INTEGER DEFAULT 0"),
            ("signup_stage", "INTEGER DEFAULT 3"),
            # Phase 7 â€” College Ambassador (spec Â§6.2). upi_id_encrypted holds
            # Fernet ciphertext only; the plaintext never touches this table.
            ("referral_code", "TEXT"),
            ("referred_by_intern_id", "INTEGER"),
            ("upi_id_encrypted", "TEXT"),
        ]:
            ensure_column(conn, "intern_accounts", col, defn)
        # Unique index rather than a UNIQUE column: ensure_column cannot add a
        # constraint to an existing table, and codes must not collide.
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_intern_referral_code "
                     "ON intern_accounts(referral_code) WHERE referral_code IS NOT NULL")
        for col, defn in [
            ("application_id", "INTEGER"), ("city", "TEXT"), ("course", "TEXT"),
            ("semester", "TEXT"), ("year_of_passing", "TEXT"), ("admin_note", "TEXT"),
            ("updated_at", "TEXT"), ("joining_date", "TEXT"), ("batch_label", "TEXT"),
            ("product", "TEXT DEFAULT 'free_deposit'"), ("amount", "INTEGER"),  # Phase 12
            ("email", "TEXT"),
        ]:
            ensure_column(conn, "enrollments", col, defn)
        ensure_column(conn, "mentors", "password_hash", "TEXT")
        # Track 2 Â§3 funnel: carry a logged-out Apply-Now resume target across the
        # multi-stage signup. The session cookie (SESSION_COOKIE_NAME='dbert_session')
        # is overwritten by the DB auth token at stage1, so a flask-session 'next'
        # can't survive to stage3 â€” persist it on the auth-session row instead.
        ensure_column(conn, "user_sessions", "next_url", "TEXT")
        # Track 2 Â§B (UAT #4): cert-gated selection bookkeeping on a job/internship application.
        for col, defn in [
            ("needed_certs_json", "TEXT"),   # [{course_id,title}] the company asks the intern to complete
            ("decision_note", "TEXT"),       # optional company note shown to the applicant
            ("decided_at", "TEXT"),
            ("notified_at", "TEXT"),
        ]:
            ensure_column(conn, "post_applications", col, defn)
        for col, defn in [
            ("visitor_id", "TEXT"), ("time_on_page", "INTEGER DEFAULT 0"),
            ("intent_score", "INTEGER DEFAULT 0"), ("path", "TEXT"),
        ]:
            ensure_column(conn, "device_profiles", col, defn)
        ensure_column(conn, "email_log", "subject", "TEXT")
        ensure_column(conn, "email_log", "opened_at", "TEXT")  # Phase 13: open-tracking pixel
        # T5: interviews are now per (intern, post) -- gated on a prior application to that
        # post -- and carry anti-copy telemetry (informational only, never enforced).
        for col, defn in [
            ("post_id", "INTEGER"),
            ("time_taken_sec", "INTEGER DEFAULT 0"),
            ("tab_switches", "INTEGER DEFAULT 0"),
        ]:
            ensure_column(conn, "interviews", col, defn)
        # Open Tasks enhancements: task_type, target_domain, payment_type, submission_type
        for col, defn in [
            ("task_type", "TEXT DEFAULT 'general'"),
            ("target_domain", "TEXT DEFAULT ''"),
            ("payment_type", "TEXT DEFAULT 'paid'"),
            ("submission_type", "TEXT DEFAULT 'url'"),
        ]:
            ensure_column(conn, "tasks", col, defn)
        ensure_column(conn, "task_submissions", "submission_file", "TEXT DEFAULT ''")
        # One device_profiles row per visitor_id (enables the track_visit UPSERT).
        # NOTE: existing DBs must be deduped first (migrations/phase6_dedup_devices.py).
        # Self-healing: if duplicates exist (e.g. a DB that accumulated dupes before
        # the index existed), collapse to one row per visitor_id, then build the index.
        # Keeps boot from crash-looping on UNIQUE constraint failure.
        # UP4.2: Add tier column to intern_certificates
        ensure_column(conn, "intern_certificates", "tier", "TEXT DEFAULT 'completed'")

        # UP8.2: Extend course_payments with commission tracking columns
        ensure_column(conn, "course_payments", "platform_commission_pct", "REAL DEFAULT 15.0")
        ensure_column(conn, "course_payments", "author_earnings_inr", "INTEGER DEFAULT 0")
        ensure_column(conn, "course_payments", "commission_pct_snapshot", "REAL DEFAULT 0.0")
        ensure_column(conn, "course_payments", "commission_amount", "REAL DEFAULT 0.0")
        ensure_column(conn, "course_payments", "payee_type", "TEXT DEFAULT 'admin'")
        ensure_column(conn, "course_payments", "settled_at", "TEXT")

        # UP9.1: Add email_verified to intern_accounts
        ensure_column(conn, "intern_accounts", "email_verified", "INTEGER DEFAULT 0")

        # UP1.1: Extend courses table schema
        for col, defn in [
            ("level", "TEXT DEFAULT 'Beginner'"),
            ("estimated_hours", "INTEGER DEFAULT 10"),
            ("author_type", "TEXT DEFAULT 'admin'"),
            ("author_id", "INTEGER"),
            ("company_id", "INTEGER"),
            ("requires_project", "INTEGER DEFAULT 0"),
            ("banner_gradient", "TEXT DEFAULT 'linear-gradient(135deg, #8B5CF6, #3B82F6)'"),
            ("content_status", "TEXT DEFAULT 'approved'"),
            ("source", "TEXT DEFAULT 'portal'"),
            ("created_at", "TEXT DEFAULT ''"),
            ("updated_at", "TEXT DEFAULT ''"),
        ]:
            ensure_column(conn, "courses", col, defn)
        conn.execute("UPDATE courses SET created_at = datetime('now','localtime') WHERE created_at IS NULL OR created_at = ''")
        conn.execute("UPDATE courses SET updated_at = datetime('now','localtime') WHERE updated_at IS NULL OR updated_at = ''")
        conn.execute("UPDATE courses SET author_type='company', author_id=company_id WHERE company_id IS NOT NULL AND (author_type IS NULL OR author_type='admin')")
        conn.commit()
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_device_visitor ON device_profiles(visitor_id)")
        except sqlite3.IntegrityError:
            conn.execute("DELETE FROM device_profiles WHERE id NOT IN (SELECT MAX(id) FROM device_profiles GROUP BY visitor_id)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_device_visitor ON device_profiles(visitor_id)")
        conn.commit()

        # Seed default chapters and subtopics for any course lacking syllabus content
        courses = conn.execute("SELECT id, title, domain FROM courses").fetchall()
        for c in courses:
            cid = c["id"]
            ch_cnt = conn.execute("SELECT COUNT(*) FROM course_chapters WHERE course_id=?", (cid,)).fetchone()[0]
            if ch_cnt == 0:
                c1 = conn.execute(
                    "INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 1, 'Foundations & Environment')",
                    (cid,)
                ).lastrowid
                conn.execute(
                    "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) "
                    "VALUES (?, 1, 'Core Architecture & Syntax', 'Master fundamental language constructs and environment setup.', ?)",
                    (c1, json.dumps(["Understand dynamic typing & memory model", "Write clean, modular code", "Set up isolated virtual environments"]))
                )
                conn.execute(
                    "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) "
                    "VALUES (?, 2, 'Functions, Modules & Dependencies', 'Build re-usable functional components and manage packages.', ?)",
                    (c1, json.dumps(["Define pure functions with type annotations", "Import custom and standard library modules", "Manage pip dependencies cleanly"]))
                )
                
                c2 = conn.execute(
                    "INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 2, 'Applied AI & Autonomous Agents')",
                    (cid,)
                ).lastrowid
                conn.execute(
                    "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) "
                    "VALUES (?, 1, 'LLM Architecture & Prompt Engineering', 'Build intelligent applications using Google Gemini API.', ?)",
                    (c2, json.dumps(["Configure Google GenAI SDK", "Construct system instructions & few-shot prompts", "Handle streaming responses & JSON mode"]))
                )
                conn.execute(
                    "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) "
                    "VALUES (?, 2, 'Tool Calling & Multi-Agent Loops', 'Equip AI agents with custom Python function calling capabilities.', ?)",
                    (c2, json.dumps(["Define tool schemas using OpenAPI/Pydantic", "Execute agent function calls safely", "Build multi-step agent execution loops"]))
                )
                
                c3 = conn.execute(
                    "INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 3, 'Capstone Project & Production Deployment')",
                    (cid,)
                ).lastrowid
                conn.execute(
                    "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) "
                    "VALUES (?, 1, 'REST APIs & Production Deployment', 'Deploy your solution as production-ready microservices.', ?)",
                    (c3, json.dumps(["Build async Flask REST endpoints", "Integrate SQLite persistence", "Deploy to cloud EC2 servers"]))
                )
        conn.commit()


init_db()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 11 â€” Gemini AI interview service (server-side only, fail-safe).
# Keys never reach the browser. Every public entry point degrades gracefully:
# Gemini failure â†’ static fallback bank; never hard-crash a request.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# â”€â”€ Static interview question bank (no LLM) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Questions are assembled locally from sectioned pools â€” instant, deterministic,
# quota-free. CAPABILITY sections (technical/applied/communication) are domain-specific.
# T5: domain-only -- the generic shared INTENT sections (learning/commitment/goals/obstacle)
# were dropped since the interview is now per-post, scoped to that post's domain. Each
# question has a stable ``key`` (so a re-take can exclude what was asked before) and a
# ``section`` (kept as the internal ``type`` for the staff dossier). Both are stripped
# before reaching the browser (see _public_questions). Grow any pool freely â€” keep each
# pool >= 2x its blueprint count so attempt 2 stays fresh.

# How an interview is assembled: (section, how_many). Sums to INTERVIEW_NUM_QUESTIONS (4).
INTERVIEW_BLUEPRINT = [
    ("technical", 2), ("applied", 1), ("communication", 1),
]
INTERVIEW_DEFAULT_DOMAIN = "Python Automation"
INTERVIEW_DOMAIN_LABELS = {
    "AI Agent Development": "AI and agent development",
    "Data Analyst":         "data analysis",
    "Full Stack Development": "web development",
    "Python Automation":    "Python and automation",
}

# Per-domain CAPABILITY pools.
INTERVIEW_DOMAIN_BANK = {
    "AI Agent Development": {
        "technical": [
            {"key": "ai_tech_01", "text": "In your own words, what is a large language model, and what does its 'context window' mean for building applications?"},
            {"key": "ai_tech_02", "text": "What is retrieval-augmented generation (RAG), and why might you use it instead of relying only on the model's built-in knowledge?"},
            {"key": "ai_tech_03", "text": "What's the difference between writing a good prompt and fine-tuning a model? When would you reach for each?"},
            {"key": "ai_tech_04", "text": "What are embeddings, and how are they useful when building an app that needs to search documents?"},
            {"key": "ai_tech_05", "text": "What does it mean for an AI agent to 'call a tool' or function, and why is that useful?"},
            {"key": "ai_tech_06", "text": "What is an LLM 'hallucination', and what are one or two practical ways to reduce it?"},
        ],
        "applied": [
            {"key": "ai_app_01", "text": "You're asked to build a support agent that answers questions from a company's PDF manuals. Outline the main steps you would take."},
            {"key": "ai_app_02", "text": "You need an agent that can read a user's email and book meetings on their calendar. How would you break that down?"},
            {"key": "ai_app_03", "text": "An AI feature you built sometimes gives confidently wrong answers. How would you investigate and improve it?"},
            {"key": "ai_app_04", "text": "You want to add a chatbot to a website that only answers questions about the product. How do you keep it on-topic?"},
        ],
        "communication": [
            {"key": "ai_comm_01", "text": "Explain, as you would to a non-technical friend, what an 'API key' is and why it must be kept secret."},
            {"key": "ai_comm_02", "text": "How would you explain to a customer, in plain language, why an AI assistant sometimes gets things wrong?"},
            {"key": "ai_comm_03", "text": "Explain what 'training data' is to someone who has never studied computer science."},
        ],
    },
    "Data Analyst": {
        "technical": [
            {"key": "da_tech_01", "text": "What is the difference between a SQL INNER JOIN and a LEFT JOIN? Give a simple example of when you'd use each."},
            {"key": "da_tech_02", "text": "How would you handle missing or null values in a dataset before analysis, and what trade-offs do your choices involve?"},
            {"key": "da_tech_03", "text": "What does GROUP BY do in SQL? Give an example of a question it helps you answer."},
            {"key": "da_tech_04", "text": "What is the difference between a primary key and a foreign key in a database?"},
            {"key": "da_tech_05", "text": "When would you use a bar chart versus a line chart versus a scatter plot to present data?"},
            {"key": "da_tech_06", "text": "What does it mean to 'clean' a dataset, and what are a few things you typically check for?"},
        ],
        "applied": [
            {"key": "da_app_01", "text": "Given a month of raw sales data, describe how you would find the top-performing products and present that insight to a manager."},
            {"key": "da_app_02", "text": "You receive a messy CSV of survey responses with inconsistent text and blanks. How do you make it analysis-ready?"},
            {"key": "da_app_03", "text": "A manager asks 'why did sales drop last week?' How would you approach answering that with data?"},
            {"key": "da_app_04", "text": "You're asked to build a simple weekly dashboard. What metrics would you include, and why?"},
        ],
        "communication": [
            {"key": "da_comm_01", "text": "Explain what a 'median' is and why it can be more useful than an 'average' in some situations, as if to someone new to data."},
            {"key": "da_comm_02", "text": "Explain the difference between correlation and causation to a manager, using a simple example."},
            {"key": "da_comm_03", "text": "How would you present a surprising finding to a team that expected the opposite result?"},
        ],
    },
    "Full Stack Development": {
        "technical": [
            {"key": "fs_tech_01", "text": "What happens, step by step, when a user types a URL into the browser and presses Enter?"},
            {"key": "fs_tech_02", "text": "What is the difference between client-side and server-side code? Give one example of work best done on each."},
            {"key": "fs_tech_03", "text": "What is the difference between a GET and a POST request, and when would you use each?"},
            {"key": "fs_tech_04", "text": "What is an API, and how does a front-end typically talk to a back-end?"},
            {"key": "fs_tech_05", "text": "What's the difference between a cookie, localStorage, and sessionStorage for keeping a user logged in?"},
            {"key": "fs_tech_06", "text": "What is a database, and why might you choose one over just storing data in files?"},
        ],
        "applied": [
            {"key": "fs_app_01", "text": "You need to build a simple to-do app where tasks persist after refresh. Describe the front-end, back-end, and storage pieces you'd use."},
            {"key": "fs_app_02", "text": "Design a login that keeps a user signed in across page refreshes. What pieces do you need?"},
            {"key": "fs_app_03", "text": "A page loads very slowly. How would you figure out why, and what would you try first?"},
            {"key": "fs_app_04", "text": "You're building a contact form that emails the team. Walk through what happens from submit to delivery."},
        ],
        "communication": [
            {"key": "fs_comm_01", "text": "Explain what an HTTP status code 404 vs 500 means, as you would to a teammate from a non-technical background."},
            {"key": "fs_comm_02", "text": "Explain what an 'API' is to someone who isn't a programmer."},
            {"key": "fs_comm_03", "text": "How would you explain to a client why their website needs both a front-end and a back-end?"},
        ],
    },
    "Python Automation": {
        "technical": [
            {"key": "py_tech_01", "text": "What is the difference between a list and a dictionary in Python, and when would you choose one over the other?"},
            {"key": "py_tech_02", "text": "How would you read a CSV file in Python and process each row? Mention any libraries you'd reach for."},
            {"key": "py_tech_03", "text": "What does try/except do in Python, and why is it important when automating tasks?"},
            {"key": "py_tech_04", "text": "What is a virtual environment, and why is it useful when working on Python projects?"},
            {"key": "py_tech_05", "text": "What is the difference between a list comprehension and a regular for-loop? When would you use each?"},
            {"key": "py_tech_06", "text": "What's the difference between a function and a variable, and why do we put code into functions?"},
        ],
        "applied": [
            {"key": "py_app_01", "text": "You're asked to automate renaming and sorting 500 files into folders by date. Describe your approach."},
            {"key": "py_app_02", "text": "You need to pull a daily report from a website and email it to your team automatically. How would you set that up?"},
            {"key": "py_app_03", "text": "A script you wrote works on your machine but fails on a colleague's. How would you track down why?"},
            {"key": "py_app_04", "text": "You want to fill out the same web form 100 times with data from a spreadsheet. How would you automate it?"},
        ],
        "communication": [
            {"key": "py_comm_01", "text": "Explain what a 'function' is and why we use them, as if teaching someone writing their first script."},
            {"key": "py_comm_02", "text": "Explain why hard-coding a password directly in a script is a bad idea, in plain terms."},
            {"key": "py_comm_03", "text": "How would you explain to a non-technical manager what 'automating a task' actually means?"},
        ],
    },
}


def _interview_bank_warnings():
    """Return a list of (domain, section) pools too small to satisfy the blueprint (with
    headroom for a fresh attempt 2). Logged once at startup; never raises."""
    warns = []
    for domain, sections in INTERVIEW_DOMAIN_BANK.items():
        for section, count in INTERVIEW_BLUEPRINT:
            pool = sections.get(section, [])
            if len(pool or []) < count:
                warns.append((domain, section, "below blueprint count"))
            elif len(pool or []) < count * 2:
                warns.append((domain, section, "no headroom for fresh retake"))
    return warns


def _assemble_interview_questions(domain, exclude_keys=None):
    """Assemble one interview from the static bank: random pick per blueprint section
    (random within a section, blueprint order preserved for a natural arc), excluding
    ``exclude_keys`` (questions from a prior attempt) when there's enough headroom. Fills
    the {field} placeholder, reassigns display ids 1..N. Returns [{id,type,text,key}].
    No network, no LLM."""
    exclude = set(exclude_keys or ())
    dom = domain if domain in INTERVIEW_DOMAIN_BANK else INTERVIEW_DEFAULT_DOMAIN
    field = INTERVIEW_DOMAIN_LABELS.get(dom, "this field")
    picked = []
    for section, count in INTERVIEW_BLUEPRINT:
        pool = INTERVIEW_DOMAIN_BANK[dom].get(section, [])
        avail = [q for q in pool if q["key"] not in exclude]
        if len(avail) < count:          # not enough fresh ones â€” fall back to the full pool
            avail = list(pool)
        for q in random.sample(avail, min(count, len(avail))):
            picked.append((section, q))
    out = []
    for i, (section, q) in enumerate(picked, start=1):
        out.append({"id": i, "type": section, "key": q["key"],
                    "text": q["text"].replace("{field}", field)})
    return out


def _company_questions_for_post(conn, post_id):
    """T6: approved company-uploaded questions for a post, in sort order, shaped like
    the domain-bank output. Returns [] (â†’ fall back to the domain bank) unless there are
    enough approved questions to cover a full interview (INTERVIEW_NUM_QUESTIONS)."""
    rows = conn.execute(
        "SELECT id, text FROM post_questions WHERE post_id=? AND status='approved' "
        "ORDER BY sort_order, id", (post_id,)
    ).fetchall()
    if len(rows) < INTERVIEW_NUM_QUESTIONS:
        return []
    picked = rows[:INTERVIEW_NUM_QUESTIONS]
    return [{"id": i + 1, "type": "company", "key": f"company_{r['id']}", "text": r["text"]}
            for i, r in enumerate(picked)]


def _extract_json(text):
    """Strip ```json fences, extract the first balanced JSON object, parse defensively.
    Returns a dict/list or None."""
    if not text:
        return None
    t = text.strip()
    # remove code fences
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t).strip()
    # fast path
    try:
        return json.loads(t)
    except Exception:
        pass
    # find first balanced {...} object
    start = t.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(t)):
        c = t[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                chunk = t[start:i + 1]
                try:
                    return json.loads(chunk)
                except Exception:
                    return None
    return None


def _gemini_call(prompt, temperature=0.7, max_tokens=2048, start_ts=None, api_key=None):
    """Iterate the key list with failover. Single retry per key on 429/403/5xx/timeout
    before moving to the next key. Returns the model's text or None (never raises).

    When ``start_ts`` (a time.monotonic() reading taken at the start of the request's
    whole network phase) is given, a wall-clock budget is enforced: once
    ``time.monotonic() - start_ts > GEMINI_TOTAL_BUDGET`` we stop trying further
    keys/retries and return None (â†’ caller's static fallback). Each request's own
    timeout is also clamped to the remaining budget so a single slow call can't blow
    past it. This is what keeps /interview/start fast even when every key is dead."""
    if api_key:
        url = GEMINI_ENDPOINT.format(model=GEMINI_MODEL)
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        try:
            r = requests.post(url, params={"key": api_key}, json=body, timeout=GEMINI_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                cands = data.get("candidates") or []
                if cands:
                    parts = cands[0].get("content", {}).get("parts", []) or []
                    out = "".join(p.get("text", "") for p in parts).strip()
                    if out:
                        return out
        except Exception as e:
            log_error("gemini-byok-call", e)

    if not (INTERVIEW_ENABLED and GEMINI_API_KEYS):
        return None
    url = GEMINI_ENDPOINT.format(model=GEMINI_MODEL)
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
            "responseMimeType": "application/json",
        },
    }
    for idx, key in enumerate(GEMINI_API_KEYS):
        for attempt in range(2):  # original try + single retry per key
            # Wall-clock budget: stop spending time across keys/retries once exhausted.
            if start_ts is not None:
                remaining = GEMINI_TOTAL_BUDGET - (time.monotonic() - start_ts)
                if remaining <= 0:
                    log_error("gemini", f"total budget {GEMINI_TOTAL_BUDGET}s exhausted -> static fallback")
                    return None
                call_timeout = max(1, min(GEMINI_TIMEOUT, int(remaining)))
            else:
                call_timeout = GEMINI_TIMEOUT
            try:
                r = requests.post(url, params={"key": key}, json=body, timeout=call_timeout)
                if r.status_code == 200:
                    data = r.json()
                    cands = data.get("candidates") or []
                    if cands:
                        parts = cands[0].get("content", {}).get("parts", []) or []
                        out = "".join(p.get("text", "") for p in parts).strip()
                        if out:
                            return out
                    log_error("gemini", f"empty 200 key#{idx + 1}")
                    break  # empty body won't improve on retry â†’ next key
                if r.status_code in (429, 403) or r.status_code >= 500:
                    log_error("gemini", f"HTTP {r.status_code} key#{idx + 1} attempt{attempt + 1}")
                    if attempt == 0:
                        continue  # retry same key once
                    break         # then failover to next key
                # other 4xx (e.g. 400) â€” failover anyway in case key/quota specific
                log_error("gemini", f"HTTP {r.status_code} key#{idx + 1}: {r.text[:200]}")
                break
            except requests.RequestException as e:
                log_error("gemini", f"request error key#{idx + 1} attempt{attempt + 1}: {e}")
                if attempt == 0:
                    continue
                break
    return None


def _extract_github_username(github_url):
    """Return the username from a github.com profile URL, else None. No scraping."""
    u = clean_text(github_url)
    if not u:
        return None
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    try:
        from urllib.parse import urlparse
        p = urlparse(u)
        if "github.com" not in (p.netloc or "").lower():
            return None
        seg = [s for s in (p.path or "").split("/") if s]
        if not seg:
            return None
        name = seg[0]
        if re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", name):
            return name
    except Exception:
        return None
    return None


def build_github_summary(github_url):
    """Compact text summary of a GitHub profile via REST. Returns 'not provided'
    on any failure / invalid URL. Optional GITHUB_TOKEN raises the rate limit."""
    username = _extract_github_username(github_url)
    if not username:
        return "not provided"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "dbert-internship"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        r = requests.get(
            f"https://api.github.com/users/{username}/repos",
            params={"per_page": 100, "sort": "pushed"},
            headers=headers, timeout=GITHUB_TIMEOUT,
        )
        if r.status_code != 200:
            return "not provided"
        repos = r.json()
        if not isinstance(repos, list) or not repos:
            return "not provided"
        own = [x for x in repos if not x.get("fork")] or repos
        n_public = len(own)
        # language mix (by repo count)
        lang_counts = {}
        for x in own:
            lg = x.get("language")
            if lg:
                lang_counts[lg] = lang_counts.get(lg, 0) + 1
        total_lang = sum(lang_counts.values()) or 1
        top_langs = sorted(lang_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
        lang_str = ", ".join(f"{k} {round(v * 100 / total_lang)}%" for k, v in top_langs) or "n/a"
        # topics
        topics = []
        for x in own:
            for t in (x.get("topics") or []):
                if t not in topics:
                    topics.append(t)
        topics_str = ", ".join(topics[:6]) if topics else "none listed"
        # recent push (most recent pushed_at across repos)
        pushes = [x.get("pushed_at") for x in own if x.get("pushed_at")]
        recent_str = "unknown"
        if pushes:
            try:
                latest = max(datetime.strptime(p[:10], "%Y-%m-%d") for p in pushes)
                days = (datetime.now() - latest).days
                if days <= 0:
                    recent_str = "today"
                elif days < 14:
                    recent_str = f"{days}d ago"
                elif days < 60:
                    recent_str = f"{days // 7}w ago"
                else:
                    recent_str = f"{days // 30}mo ago"
            except Exception:
                recent_str = "unknown"
        # top repo by stars
        top = sorted(own, key=lambda x: x.get("stargazers_count", 0), reverse=True)[0]
        top_name = top.get("name", "")
        top_lang = top.get("language") or "mixed"
        top_desc = clean_text(top.get("description") or "")[:80]
        top_str = f"top repo '{top_name}' ({top_lang}"
        top_str += f", {top_desc})" if top_desc else ")"
        return (f"{n_public} public repos; langs {lang_str}; topics: {topics_str}; "
                f"recent push {recent_str}; {top_str}.")
    except Exception as e:
        log_error("github_summary", e)
        return "not provided"


def generate_interview_questions(profile, start_ts=None, exclude_keys=None):
    """Assemble the interview from the static sectioned bank (no LLM, no network â€” instant
    and quota-free). Returns INTERVIEW_NUM_QUESTIONS dicts {id,type,text,key}: a capability
    screen PLUS indirect probes of willingness + need (learning/commitment/goals/obstacle),
    none of which mention the paid program. ``type``/``key`` are interviewer-internal and are
    stripped before the questions reach the browser (see _public_questions). ``start_ts`` is
    accepted for signature compatibility and ignored. ``exclude_keys`` (question keys from a
    prior attempt) keeps a re-take fresh.
    NOTE: AI generation is intentionally deferred â€” _gemini_call/_extract_json remain in the
    file for the future self-hosted-LLM phase but are not used by the live interview path."""
    return _assemble_interview_questions(profile.get("domain", ""), exclude_keys)


def assess_interview(profile, questions, answers):
    """Return {'mentor_assessment':{...}, 'candidate_focus':{...}} WITHOUT any LLM call.
    Phase-1 policy: a human reviews answers in the admin dossier / CSV export, so the
    mentor_assessment is flagged ``pending_manual_review`` and the candidate sees a static,
    warm acknowledgement. The richer AI read (readiness, paid_program_fit, intent_signals,
    paid_pitch_angle) is deferred to the future self-hosted-LLM phase â€” those keys are kept
    here (as 'unknown'/empty) so the staff dossier and a later AI pass stay schema-compatible."""
    return {
        "mentor_assessment": {
            "status": "pending_manual_review",
            "summary": "Pending manual review â€” read the candidate's questions & answers below.",
            "strengths": [], "gaps": [], "recommended_training": [], "recommended_skills": [],
            "readiness": "unknown",
            "paid_program_fit": "unknown",
            "intent_signals": {"willingness": "", "capability_gap": "", "need": ""},
            "paid_pitch_angle": "",
            "notes_for_mentor": "Automated assessment is disabled in this phase; review answers manually.",
        },
        "candidate_focus": {
            "message": "Thank you for completing your interview! Your application is now under review, "
                       "and our team will get back to you soon. While you wait, keep building on your strengths.",
            "focus_areas": [
                "Strengthen the core fundamentals of your chosen domain.",
                "Practise explaining your thinking clearly and concisely.",
                "Build or polish a small hands-on project.",
            ],
        },
    }


def _relative_time(ts):
    try:
        diff = int((datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")).total_seconds())
        if diff < 60: return "just now"
        if diff < 3600: return f"{diff // 60} mins ago"
        if diff < 86400: return f"{diff // 3600} hours ago"
        return f"{diff // 86400} days ago"
    except:
        return "recently"


AUTH_COOKIE        = "dbert_auth"
LEGACY_AUTH_COOKIE = "dbert_session"   # pre-NF1 name; drop after one release


def get_session_token_from_request():
    return (request.cookies.get(AUTH_COOKIE)
            or request.cookies.get(LEGACY_AUTH_COOKIE)
            or request.headers.get("X-Session-Token"))


def get_current_user():
    token = get_session_token_from_request()
    if not token: return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM user_sessions WHERE session_token=? AND expires_at>?",
            (token, now_str())
        ).fetchone()
    return row_to_dict(row) if row else None


def create_session(email, role):
    token = secrets.token_hex(32)
    expires_at = (datetime.now() + timedelta(days=SESSION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO user_sessions (email,role,session_token,expires_at) VALUES (?,?,?,?)",
            (email.lower(), role, token, expires_at)
        )
        conn.commit()
    return token


def _set_session_cookie(resp, token):
    """The ONE place the auth cookie is issued (spec Â§5.1)."""
    resp.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=SESSION_DAYS * 86400,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Lax",
        path="/"
    )
    return resp


def _clear_session_cookie(resp):
    """The ONE place auth cookies are cleared. Clears the legacy name too, so a
    user holding a pre-NF1 cookie is genuinely logged out rather than silently
    re-authenticated by the read-fallback in get_session_token_from_request()."""
    resp.delete_cookie(AUTH_COOKIE, path="/")
    resp.delete_cookie(LEGACY_AUTH_COOKIE, path="/")
    return resp


# â”€â”€ F8: CSRF protection (spec Â§5.2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Per-session token, required on every state-changing request. Delivered to the
# browser two ways: a hidden field for real <form> posts, and a <meta> tag that
# the fetch wrapper in _head.html attaches as X-CSRF-Token â€” so the ~73 existing
# fetch() call sites are covered without editing each one.

CSRF_HEADER      = "X-CSRF-Token"
CSRF_FIELD       = "_csrf_token"
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
# Endpoints that legitimately cannot carry a token. Keep this list empty unless
# there is a genuine server-to-server caller â€” every browser-originated POST
# must be protected.
CSRF_EXEMPT_ENDPOINTS = set()


def _csrf_token():
    """Current session's CSRF token, minted on first use."""
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


def _csrf_field():
    """Hidden input for classic form posts. Used as {{ csrf_field() }}."""
    return Markup(
        f'<input type="hidden" name="{CSRF_FIELD}" value="{escape(_csrf_token())}">'
    )


@app.context_processor
def _inject_csrf():
    return {"csrf_token": _csrf_token, "csrf_field": _csrf_field}


@app.before_request
def _enforce_csrf():
    if request.method in CSRF_SAFE_METHODS:
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None

    # P0-7: Server-to-server CSRF exemption with strong auth
    cron_key = request.headers.get("X-Cron-Key") or request.args.get("key", "")
    if request.path.startswith("/cron/") and CRON_SECRET and cron_key == CRON_SECRET:
        return None

    expected = session.get("_csrf")
    supplied = request.headers.get(CSRF_HEADER) or request.form.get(CSRF_FIELD)
    if not supplied and request.is_json:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            supplied = body.get(CSRF_FIELD)

    if expected and supplied and secrets.compare_digest(str(supplied), str(expected)):
        return None

    _ip = get_client_ip()
    log_abuse(_ip, request.path, f"csrf:{_ip}", "csrf_reject")
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "error", "message": "Invalid or missing CSRF token."}), 403
    return "Invalid or missing CSRF token.", 403


def invalidate_session(token):
    if not token: return
    with get_db() as conn:
        conn.execute("DELETE FROM user_sessions WHERE session_token=?", (token,))
        conn.commit()

def cleanup_expired_sessions():
    """Opportunistic cleanup of expired sessions. Called periodically."""
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM user_sessions WHERE expires_at < ?", (now_str(),))
            conn.commit()
    except Exception as e:
        log_error("session-cleanup", e)


def require_role(role):
    user = get_current_user()
    if not user or user.get("role") != role: return None
    return user


def is_admin_request():
    """Legacy key-based check removed for security (SEC-004). Uses session now."""
    user = get_current_user()
    return bool(user and user.get("role") == "admin")


def require_admin():
    """Session-based admin check for protected pages/APIs."""
    user = get_current_user()
    if user and user.get("role") == "admin":
        return user
    if session.get("admin_id") or session.get("staff_id"):
        return {
            "id": session.get("admin_id") or session.get("staff_id"),
            "role": "admin",
            "email": session.get("staff_email", "admin@dbert.online")
        }
    return None


def calculate_intent_score(data):
    """P2-1: Clamp client-controlled analytics fields to safe bounds."""
    try:
        vc = max(0, min(10000, int(data.get("visit_count", 1) or 1)))
    except (ValueError, TypeError):
        vc = 1
    try:
        top = max(0, min(86400, int(data.get("time_on_page", 0) or 0)))
    except (ValueError, TypeError):
        top = 0
    score = min(35, vc * 7)
    score += 15 if data.get("return_visit") else 0
    score += min(30, top // 20)
    score += 5 if clean_text(str(data.get("referrer") or "")[:500]) else 0
    score += 10 if str(data.get("device_type") or "")[:20].lower() == "desktop" else 0
    return min(100, score)


# -- P1-1: Centralised application state-transition helper --
VALID_APP_TRANSITIONS = {
    "Apply Pending":       {"Under Review", "Rejected"},
    "Under Review":        {"On Hold", "Selected", "Rejected"},
    "On Hold":             {"Under Review", "Selected", "Rejected"},
    "Selected":            {"Enrollment Pending", "Rejected"},
    "Enrollment Pending":  {"Enrolled", "Selected", "Rejected"},
    "Enrolled":            {"Accepted", "Enrollment Pending", "Rejected"},
    "Accepted":            {"Enrolled", "Rejected"},
    "Paid - Enrolled":     {"Accepted", "Rejected"},
}

def transition_application_status(conn, app_id, new_status, actor="system"):
    """Enforce valid state transitions. Returns (ok, old_status).
    Rejects illegal jumps and logs every transition for auditability."""
    row = conn.execute("SELECT status FROM applications WHERE id=?", (app_id,)).fetchone()
    if not row:
        return False, None
    old = row["status"]
    allowed = VALID_APP_TRANSITIONS.get(old, set())
    if new_status not in allowed and old != new_status:
        log_info("state_transition_denied",
                 f"app={app_id} {old!r}->{new_status!r} by {actor}")
        return False, old
    conn.execute("UPDATE applications SET status=?,updated_at=? WHERE id=?",
                 (new_status, now_str(), app_id))
    log_info("state_transition",
             f"app={app_id} {old!r}->{new_status!r} by {actor}")
    return True, old


# -- P1-2: Centralised payment / entitlement helper --
def can_access_program(email, feature="tutor"):
    """Single source of truth: does this intern have verified-payment access?
    Checks enrollment.payment_status AND application.status == Accepted."""
    with get_db() as conn:
        enr = conn.execute(
            "SELECT payment_status FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()
        app_row = conn.execute(
            "SELECT status FROM applications WHERE email=? ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()
    if not enr or not app_row:
        return False
    return (enr["payment_status"] in ("Accepted", "Verified")
            and app_row["status"] in ("Accepted",))


def assign_mentor_email(domain):
    with get_db() as conn:
        rows = conn.execute("""
            SELECT m.email,
                   (SELECT COUNT(*) FROM applications a WHERE a.mentor_email=m.email
                    AND a.status IN (?,?,?,?,?,?,?,?)) AS cnt
            FROM mentors m WHERE m.domain=? AND m.is_active=1 ORDER BY cnt ASC, m.id ASC
        """, (STATUS_APPLY_PENDING, STATUS_UNDER_REVIEW, STATUS_ON_HOLD, STATUS_SELECTED,
              STATUS_ENROLLMENT_PENDING, STATUS_ENROLLED, STATUS_ACCEPTED, STATUS_PAID_ENROLLED, domain)).fetchall()
    return rows[0]["email"] if rows else None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# EMAIL HELPERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# â”€â”€ Email deliverability + analytics helpers (Phase 13) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Applied centrally in send_email_async so EVERY email gains: a plain-text part,
# proper headers (Reply-To/Date/Message-ID/List-Unsubscribe), a CAN-SPAM footer with
# a working unsubscribe link, an open-tracking pixel, and UTM-tagged site links.
EMAIL_SITE = "https://internship.dbert.online"

def _email_sig(purpose, value):
    return hmac.new(app.secret_key.encode(), f"{purpose}:{value.lower()}".encode(), hashlib.sha256).hexdigest()[:32]

def _email_unsub_url(to_email):
    return f"{EMAIL_SITE}/unsubscribe?e={quote(to_email)}&t={_email_sig('unsub', to_email)}"

def _email_pixel_url(to_email):
    return f"{EMAIL_SITE}/e/o.gif?e={quote(to_email)}&t={_email_sig('open', to_email)}"

def _email_add_utm(html, campaign):
    """Append UTM params to internship.dbert.online links that don't already carry them."""
    def _repl(m):
        url = m.group(1)
        if "utm_" in url:
            return m.group(0)
        sep = "&" if "?" in url else "?"
        return f'href="{url}{sep}utm_source=email&utm_medium=email&utm_campaign={campaign}"'
    return re.sub(r'href="(https://internship\.dbert\.online[^"]*)"', _repl, html or "")

def _email_to_text(html):
    """Best-effort HTMLâ†’plain-text for the multipart/alternative text part."""
    import html as _html
    t = re.sub(r"(?is)<(script|style|head).*?</\1>", "", html or "")
    t = re.sub(r"(?i)<br\s*/?>", "\n", t)
    t = re.sub(r"(?i)</(p|div|h[1-6]|tr|li)>", "\n", t)
    t = re.sub(r"(?i)<a [^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>", r"\2 (\1)", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = _html.unescape(t)
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip() or "Open your DBERT portal: " + EMAIL_SITE

def _email_footer(to_email):
    return (
        "<div style='max-width:580px;margin:0 auto 26px;padding:0 20px;text-align:center;'>"
        "<p style='color:#5a6577;font-size:11px;line-height:1.8;margin:14px 0 0;'>"
        "DBERT &middot; MSME Registered &middot; India<br/>"
        "You're receiving this because you signed up at internship.dbert.online.<br/>"
        f"<a href='{_email_unsub_url(to_email)}' style='color:#7a8699;text-decoration:underline;'>Unsubscribe</a>"
        " &middot; <a href='" + EMAIL_SITE + "/privacy' style='color:#7a8699;text-decoration:underline;'>Privacy</a>"
        "</p></div>"
    )

def _build_email_message(to_email, subject, html_body, campaign):
    """Build the full multipart/alternative message (text + html) with deliverability
    headers, the CAN-SPAM footer, open pixel, and UTM-tagged links. Transport-agnostic â€”
    used by both the SES and SMTP send paths."""
    html = _email_add_utm(html_body, campaign)
    inject = _email_footer(to_email) + f"<img src='{_email_pixel_url(to_email)}' width='1' height='1' alt='' style='display:none;width:1px;height:1px;'/>"
    html = html.replace("</body>", inject + "</body>") if "</body>" in html else html + inject
    text = _email_to_text(html_body)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Reply-To"] = FROM_EMAIL
    msg["Date"] = formatdate(localtime=True)
    try: msg["Message-ID"] = make_msgid(domain=FROM_EMAIL.split("@")[-1])
    except Exception: pass
    msg["List-Unsubscribe"] = f"<{_email_unsub_url(to_email)}>, <mailto:{FROM_EMAIL}?subject=unsubscribe>"
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    msg["Auto-Submitted"] = "auto-generated"
    msg.attach(MIMEText(text, "plain", "utf-8"))      # text part first (RFC: leastâ†’most rich)
    msg.attach(MIMEText(html, "html", "utf-8"))
    return msg

def _ses_send_raw(msg, to_email):
    """Send a pre-built MIME message via the Amazon SES HTTPS API (port 443). SES signs
    DKIM automatically for a verified domain. Raises on failure (caller logs)."""
    import boto3  # optional dep; only needed when EMAIL_PROVIDER=ses
    boto3.client("ses", region_name=AWS_SES_REGION).send_raw_email(
        Source=FROM_EMAIL, Destinations=[to_email], RawMessage={"Data": msg.as_string()})

def _smtp_send_raw(msg, to_email):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo(); s.starttls(); s.ehlo()
        if SMTP_USER and SMTP_PASS:
            s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(FROM_EMAIL, to_email, msg.as_string())

def _cpanel_api_send(msg, to_email):
    """T17: relay a pre-built MIME message through the dbert-mailer microservice (T18) --
    it just forwards to the cPanel mailbox over localhost SMTP. The portal sends the
    already-rendered HTML+text (footer/unsubscribe/pixel already baked in by
    _build_email_message); the mailer app does no rendering of its own. Raises on a
    non-2xx/network failure so send_email_async's try/except logs email_sent=NO."""
    if not CPANEL_EMAIL_API_URL:
        raise RuntimeError("CPANEL_EMAIL_API_URL not configured")
    html_part = text_part = None
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_part = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
        elif part.get_content_type() == "text/plain":
            text_part = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
    r = requests.post(
        CPANEL_EMAIL_API_URL,
        headers={"X-API-Key": CPANEL_EMAIL_API_KEY, "Content-Type": "application/json"},
        json={
            "to": to_email,
            "subject": msg["Subject"],
            "html": html_part or "",
            "text": text_part or "",
            "from_name": FROM_NAME,
            "from_email": FROM_EMAIL,
        },
        timeout=10,
    )
    if r.status_code < 200 or r.status_code >= 300:
        raise RuntimeError(f"cpanel_api mailer http_{r.status_code}: {r.text[:200]}")

def send_email_async(to_email, subject, html_body, name="", campaign="transactional"):
    # Master kill-switch: emails suppressed for now (push notifications still fire separately).
    if not EMAILS_ENABLED:
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO email_log (timestamp,email,name,subject,email_sent) VALUES (?,?,?,?,?)",
                    (now_str(), to_email, name, subject, "SKIPPED")); conn.commit()
        except Exception:
            pass
        return
    def _send():
        sent = "YES"
        try:
            msg = _build_email_message(to_email, subject, html_body, campaign)
            if EMAIL_PROVIDER == "ses":
                _ses_send_raw(msg, to_email)
            elif EMAIL_PROVIDER == "cpanel_api":
                _cpanel_api_send(msg, to_email)
            else:
                _smtp_send_raw(msg, to_email)
        except Exception as e:
            sent = "NO"; log_error("EMAIL[" + EMAIL_PROVIDER + "]", e)
        finally:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO email_log (timestamp,email,name,subject,email_sent) VALUES (?,?,?,?,?)",
                        (now_str(), to_email, name, subject, sent)
                    ); conn.commit()
            except: pass
    threading.Thread(target=_send, daemon=True).start()


def _onesignal_post(to_email, title, message, url):
    """Synchronous OneSignal v2 push POST â†’ returns the requests.Response.

    v2 "rich" keys (prefix ``os_v...``) authenticate with ``Authorization: Key <key>``;
    legacy keys still use ``Basic <key>`` (rollback-safe). Targeting uses the modern
    ``include_aliases`` + ``target_channel`` form (replaces the deprecated
    ``include_external_user_ids`` / ``channel_for_external_user_ids``).
    """
    scheme = "Key" if ONESIGNAL_REST_API_KEY.startswith("os_v") else "Basic"
    return requests.post(
        "https://api.onesignal.com/notifications",
        headers={
            "Authorization": f"{scheme} {ONESIGNAL_REST_API_KEY}",
            "Content-Type":  "application/json",
        },
        json={
            "app_id":          ONESIGNAL_APP_ID,
            "include_aliases": {"external_id": [to_email]},
            "target_channel":  "push",
            "headings":  {"en": title},
            "contents":  {"en": message},
            "url":       url,
            "web_url":   url,
        },
        timeout=8,
    )


def add_notification(intern_id, title, body="", *, kind="general", link=""):
    """UAT #26: persist a durable in-app notification for the Notifications tab.
    Best-effort â€” never raises into the caller."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO notifications (intern_id, kind, title, body, link) VALUES (?,?,?,?,?)",
                (intern_id, kind, title, body or "", link or ""))
            conn.commit()
    except Exception as e:
        log_error("add-notification", e)


def _persist_notification_for_email(to_email, title, message, url):
    """Resolve an email â†’ intern_accounts.id and store an in-app notification, so
    every push (#26) is also reviewable in the portal. Best-effort."""
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (to_email,)
            ).fetchone()
        if row:
            # keep links relative to the portal where possible
            link = url or ""
            add_notification(row["id"], title, message, kind="push", link=link)
    except Exception as e:
        log_error("persist-notification", e)


def send_push_notification(to_email, title, message, url="https://internship.dbert.online"):
    """
    Fire-and-forget OneSignal push notification (v2 API).
    Uses external_id alias = intern email (set by frontend on login).
    Also persists a durable in-app notification (#26), regardless of push creds.
    """
    _persist_notification_for_email(to_email, title, message, url)
    if not ONESIGNAL_APP_ID or not ONESIGNAL_REST_API_KEY:
        return
    def _push():
        try:
            resp = _onesignal_post(to_email, title, message, url)
            if not (200 <= resp.status_code < 300):
                # Surface 4xx/5xx in the error log instead of failing silently.
                log_error("onesignal-push", f"HTTP {resp.status_code}: {resp.text}")
        except Exception as e:
            log_error("onesignal-push", e)
    threading.Thread(target=_push, daemon=True).start()


_PUSH_STATUS_MSGS = {
    "Apply Pending":       ("ðŸ“¥ Application Received",          "We've received your application. Our team will review it soon."),
    "Under Review":        ("ðŸ“„ Application Under Review",      "Our mentors are reviewing your profile. Typically takes 3â€“5 business days."),
    "On Hold":             ("â³ Application On Hold",           "Your review has been paused. We'll notify you when it resumes."),
    "Selected":            ("ðŸŽ‰ You're Selected!",              "Complete your payment enrollment on the portal to secure your seat."),
    "Enrollment Pending":  ("ðŸªª Enrollment Pending",            "Please complete enrollment and upload your payment proof."),
    "Enrolled":            ("âœ… Enrollment Received",           "Payment verification in progress. We'll confirm within 24 hours."),
    "Accepted":            ("ðŸ† Welcome to DBERT!",        "Your enrollment is confirmed. Log in to access your dashboard."),
    "Rejected":            ("Application Update",               "Your application was not selected this time. You may re-apply after 30 days."),
}


def _email_shell(eyebrow, heading, body_html, cta_text=None, cta_url=None, preheader=""):
    """Branded, email-client-safe HTML body matching the DBERT site: TABLE layout +
    inline CSS only (renders in Outlook/Gmail), 600px card, gold logo mark + accent rule,
    and a bulletproof (table-based) CTA button. send_email_async appends the footer + open
    pixel and UTM-tags the links â€” so do NOT add a footer here."""
    cta = ""
    if cta_text and cta_url:
        cta = (
            '<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:26px auto 0;">'
            '<tr><td align="center" bgcolor="#E2B96F" style="border-radius:999px;">'
            f'<a href="{cta_url}" style="display:inline-block;padding:14px 38px;font-family:Inter,Arial,Helvetica,sans-serif;'
            f'font-size:14px;font-weight:800;color:#0B0F17;text-decoration:none;border-radius:999px;">{cta_text}</a>'
            '</td></tr></table>'
        )
    eyebrow_html = (f'<p style="margin:0 0 8px;color:#E2B96F;font-size:11px;font-weight:800;'
                    f'letter-spacing:1px;text-transform:uppercase;">{eyebrow}</p>') if eyebrow else ''
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark"/><meta name="supported-color-schemes" content="dark"/>
<title>{heading}</title></head>
<body style="margin:0;padding:0;background-color:#0B0F17;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;mso-hide:all;">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0B0F17;">
<tr><td align="center" style="padding:26px 14px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;background-color:#141821;border:1px solid #232a36;border-radius:18px;overflow:hidden;">
<tr><td bgcolor="#0F1A2E" style="background-color:#0F1A2E;padding:26px 32px;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
    <td width="40" align="center" valign="middle" bgcolor="#E2B96F" style="width:40px;height:40px;background-color:#E2B96F;border-radius:10px;font-family:Inter,Arial,sans-serif;font-size:19px;font-weight:900;color:#0B0F17;">D</td>
    <td style="padding-left:12px;font-family:Inter,Arial,Helvetica,sans-serif;">
      <div style="color:#FFFFFF;font-size:16px;font-weight:800;line-height:1.2;">DBERT</div>
      <div style="color:#8a9ab5;font-size:11px;">Internship 2026</div>
    </td>
  </tr></table>
</td></tr>
<tr><td height="3" bgcolor="#E2B96F" style="height:3px;line-height:3px;font-size:0;background-color:#E2B96F;">&nbsp;</td></tr>
<tr><td style="padding:34px 34px 36px;font-family:Inter,Arial,Helvetica,sans-serif;">
  {eyebrow_html}
  <h1 style="margin:0 0 16px;color:#FFFFFF;font-size:22px;font-weight:800;line-height:1.35;">{heading}</h1>
  <div style="color:#c9d3dd;font-size:14.5px;line-height:1.75;">{body_html}</div>
  {cta}
</td></tr>
</table>
</td></tr></table>
</body></html>"""


def _email_info_box(html, accent="#E2B96F"):
    """Reusable inline-styled callout box for inside an email body."""
    return (f'<div style="background-color:#1b2230;border:1px solid {accent}33;border-radius:12px;'
            f'padding:16px 18px;margin:18px 0;">{html}</div>')


def send_password_reset_email(name, to_email, reset_url):
    first = (name or "Candidate").split()[0]
    subject = "Reset your DBERT password"
    body = (
        "<p style='margin:0 0 4px;'>We received a request to reset your DBERT portal password. "
        "Tap the button below to choose a new one.</p>"
        + _email_info_box(
            "<p style='margin:0 0 6px;color:#E2B96F;font-weight:700;font-size:13px;'>This link expires in 1 hour.</p>"
            "<p style='margin:0;color:#8a9ab5;font-size:12.5px;line-height:1.7;'>If you didn't request this, you can safely "
            "ignore this email â€” your password won't change.</p>")
        + f"<p style='margin:14px 0 0;color:#5a6577;font-size:12px;word-break:break-all;'>Or paste this link into your browser:<br/>"
          f"<span style='color:#7a8699;'>{reset_url}</span></p>"
    )
    html = _email_shell("Password Reset", f"Hi {first}, reset your password", body,
                        cta_text="Reset Password", cta_url=reset_url,
                        preheader="Reset your DBERT password â€” link expires in 1 hour.")
    send_email_async(to_email, subject, html, name, campaign="password_reset")


def send_application_received_email(name, to_email, domain):
    first = (name or "Candidate").split()[0]
    subject = "Application received â€” DBERT Internship 2026"
    body = (
        f"<p style='margin:0 0 4px;'>Your application for <strong style='color:#E2B96F;'>{domain}</strong> is now "
        f"<strong style='color:#FFFFFF;'>Under Review</strong>.</p>"
        + _email_info_box(
            "<p style='margin:0 0 8px;color:#E2B96F;font-weight:700;font-size:13px;'>What happens next</p>"
            "<ul style='color:#aebacb;margin:0;padding-left:18px;line-height:2;font-size:13px;'>"
            "<li>Our mentors review your profile (typically 3â€“5 business days)</li>"
            "<li>If selected, you'll be invited to complete enrollment</li>"
            "<li>Track your status anytime in your portal</li></ul>")
    )
    html = _email_shell("Application Received", f"Hi {first}, we've got your application!", body,
                        cta_text="Open your portal", cta_url="https://internship.dbert.online/portal",
                        preheader=f"Your application for {domain} is under review.")
    send_email_async(to_email, subject, html, name, campaign="application_received")
    send_push_notification(
        to_email,
        "ðŸ“‹ Application Received â€” DBERT",
        f"Hi {first}! Your application for {domain} is under review. We'll keep you posted.",
    )


def send_status_update_email(name, to_email, domain, status, note="", joining_date=None):
    first = (name or "Candidate").split()[0]
    note_block = _email_info_box(
        "<p style='margin:0 0 8px;color:#E2B96F;font-size:13px;font-weight:700;'>Note from our team</p>"
        f"<p style='margin:0;color:#c9d3dd;font-size:13px;line-height:1.7;'>{note}</p>"
    ) if note else ""

    batch_info = ""
    if joining_date and status == STATUS_ACCEPTED:
        bl = make_batch_label(joining_date)
        batch_info = f"<p style='color:#E2B96F;font-size:14px;font-weight:800;margin:18px 0 0;'>Your batch starts: {bl}</p>"

    sc = {
        STATUS_UNDER_REVIEW:       ("ðŸ“„", "Your application is under review.", "Our mentors are reviewing your profile. Typically takes 3â€“5 business days."),
        STATUS_ON_HOLD:            ("â³", "Your application is on hold.", "We'll notify you when review resumes."),
        STATUS_SELECTED:           ("ðŸŽ‰", "Congratulations, you're selected!", "Log in to your portal and complete payment enrollment to secure your seat."),
        STATUS_ENROLLMENT_PENDING: ("ðŸªª", "Awaiting enrollment.", "Please complete enrollment and upload payment proof."),
        STATUS_ENROLLED:           ("âœ…", "Enrollment received.", "Our team will verify your payment within 24 hours."),
        STATUS_ACCEPTED:           ("ðŸ†", "Enrollment accepted!", "You're officially confirmed. Welcome to DBERT!"),
        STATUS_REJECTED:           ("ðŸ’Œ", "Not moving forward this time.", "You may re-apply after 30 days."),
        STATUS_APPLY_PENDING:      ("ðŸ“¥", "Application saved.", "Our team will move it into review soon."),
        STATUS_PAID_ENROLLED:      ("ðŸ’³", "Paid program enrolment received.", "We're verifying your payment â€” you'll be confirmed within 24 hours."),
    }
    icon, title, body = sc.get(status, ("ðŸ“Œ", f"Status: {status}.", "Check portal for details."))

    # Phase 12.4 Moment A â€” empathetic paid fast-track block on rejection (solid-bg, Outlook-safe).
    fasttrack_block = ""
    if status == STATUS_REJECTED:
        fasttrack_block = (
            "<div style='background-color:#10241a;border:1px solid #2e6b45;border-radius:12px;padding:18px 20px;margin:18px 0 0;'>"
            "<p style='margin:0 0 8px;color:#7ed492;font-size:14px;font-weight:800;'>A faster path is open to you</p>"
            "<p style='margin:0 0 14px;color:#c9d3dd;font-size:13px;line-height:1.7;'>This isn't the end of the road. Our "
            "<strong style='color:#E2B96F;'>Paid Program</strong> gives you 15 days of training, a 45-day production role, and a "
            "<strong style='color:#FFFFFF;'>guaranteed placement opportunity</strong> with our hiring partners on completion + certification â€” no waiting to be shortlisted.</p>"
            "<table role='presentation' cellpadding='0' cellspacing='0' border='0'><tr><td bgcolor='#E2B96F' style='border-radius:999px;'>"
            "<a href='https://internship.dbert.online/program' style='display:inline-block;padding:11px 26px;"
            "color:#0B0F17;text-decoration:none;font-weight:800;font-size:13px;border-radius:999px;'>Explore the Paid Program</a>"
            "</td></tr></table></div>"
        )

    subject = f"DBERT â€” {title}"
    body_html = (
        f"<p style='margin:0 0 14px;'>{title}</p>"
        f"<p style='margin:0 0 16px;color:#aebacb;'>Domain: <strong style='color:#E2B96F;'>{domain}</strong> &nbsp;&middot;&nbsp; "
        f"Status: <strong style='color:#FFFFFF;'>{status}</strong></p>"
        f"<p style='margin:0;'>{body}</p>{batch_info}{note_block}{fasttrack_block}"
    )
    html = _email_shell(status, f"Hi {first},", body_html,
                        cta_text="Open Portal", cta_url="https://internship.dbert.online/portal",
                        preheader=title)
    send_email_async(to_email, subject, html, name, campaign="status_update")
    push_title, push_body = _PUSH_STATUS_MSGS.get(status, ("ðŸ“Œ Application Update", f"Your status has changed to: {status}. Check your portal."))
    if joining_date and status == STATUS_ACCEPTED:
        push_body = f"Your enrollment is confirmed. Batch starts {make_batch_label(joining_date)}. Log in to access your dashboard."
    send_push_notification(to_email, push_title, push_body)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# T10 â€” Track 2 board notifications (dashboard + push + email at every funnel event).
# send_push_notification() already persists the dashboard row (#26) for every push,
# so each helper below only needs to call send_email_async() + send_push_notification().
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def notify_post_application_received(name, to_email, post_title, company_name):
    """Fires when an intern applies to a specific post (Track 2 board)."""
    first = (name or "Candidate").split()[0]
    body_html = (
        f"<p style='margin:0 0 14px;'>Your application for "
        f"<strong style='color:#FFFFFF;'>{post_title}</strong> at "
        f"<strong style='color:#E2B96F;'>{company_name}</strong> has been received.</p>"
        "<p style='margin:0;color:#c9d3dd;'>You can take its post-specific interview anytime "
        "from your dashboard's My Applications tab. We'll notify you the moment the company "
        "reviews your application.</p>"
    )
    html = _email_shell("Applied", f"Hi {first},", body_html,
                        cta_text="View in My Applications", cta_url="https://internship.dbert.online/portal",
                        preheader=f"Application received for {post_title}")
    send_email_async(to_email, f"DBERT â€” Application received for {post_title}", html, name,
                     campaign="post_application_received")
    send_push_notification(to_email, "âœ… Application received",
                           f"Your application for {post_title} at {company_name} was received.")


def notify_post_comment_reply(name, to_email, post_title, post_path):
    """Fires for every OTHER applicant on a post when a new public comment lands on it
    (T4 thread) -- they're 'in the thread' because they applied. ``post_path`` is the
    relative /internships|/jobs path; absolute URLs are built here (push/email convention)."""
    first = (name or "Candidate").split()[0]
    post_url = f"https://internship.dbert.online{post_path}"
    body_html = (
        f"<p style='margin:0 0 14px;'>There's a new comment on "
        f"<strong style='color:#FFFFFF;'>{post_title}</strong>, a post you applied to.</p>"
        "<p style='margin:0;color:#c9d3dd;'>Open the post to read it and join the discussion.</p>"
    )
    html = _email_shell("New comment", f"Hi {first},", body_html,
                        cta_text="View the post", cta_url=post_url,
                        preheader=f"New comment on {post_title}")
    send_email_async(to_email, f"DBERT â€” New comment on {post_title}", html, name,
                     campaign="post_comment_reply")
    send_push_notification(to_email, "ðŸ’¬ New comment",
                           f"New comment on {post_title} â€” a post you applied to.", post_url)


_POST_STATUS_PUSH = {
    "Shortlisted": ("ðŸ‘€ You've been shortlisted!", "{company} shortlisted you for {post}."),
    "Hired":       ("ðŸŽ‰ You're hired!", "{company} hired you for {post}. Congratulations!"),
    "Rejected":    ("ðŸ“‹ Application update", "Your application for {post} at {company} was not selected this time."),
}


def notify_post_status_change(name, to_email, post_title, company_name, new_status):
    """Fires on a company status change for a Track 2 application: Shortlisted, Hired,
    or Rejected. The cert-gate transition (Selected - Pending Certifications) has its own
    richer notice -- send_post_selection_email -- and is not handled here."""
    first = (name or "Candidate").split()[0]
    heading_map = {
        "Shortlisted": "You've been shortlisted!",
        "Hired": "You're hired â€” congratulations!",
        "Rejected": "An update on your application",
    }
    body_map = {
        "Shortlisted": f"Great news â€” <strong style='color:#E2B96F;'>{company_name}</strong> has "
                       f"shortlisted you for <strong style='color:#FFFFFF;'>{post_title}</strong>. "
                       "They'll be in touch with next steps.",
        "Hired": f"<strong style='color:#E2B96F;'>{company_name}</strong> has hired you for "
                 f"<strong style='color:#FFFFFF;'>{post_title}</strong>. Congratulations!",
        "Rejected": f"<strong style='color:#E2B96F;'>{company_name}</strong> has decided not to move "
                    f"forward with your application for <strong style='color:#FFFFFF;'>{post_title}</strong> "
                    "this time. Keep applying â€” new posts go live every day.",
    }
    body_html = f"<p style='margin:0;color:#c9d3dd;'>{body_map.get(new_status, f'Status: {new_status}.')}</p>"
    html = _email_shell(new_status, f"Hi {first},", body_html,
                        cta_text="View in My Applications", cta_url="https://internship.dbert.online/portal",
                        preheader=heading_map.get(new_status, new_status))
    send_email_async(to_email, f"DBERT â€” {heading_map.get(new_status, new_status)}", html, name,
                     campaign="post_status_change")
    push_title, push_body_tpl = _POST_STATUS_PUSH.get(
        new_status, ("ðŸ“Œ Application update", "Your application for {post} at {company} was updated."))
    send_push_notification(to_email, push_title, push_body_tpl.format(post=post_title, company=company_name))


def notify_course_payment_verified(name, to_email, course_title, is_portal_course, link_url):
    """T10: course payment verified -- email + push. The push call also persists the
    dashboard notification (#26) with ``link_url``, so callers must NOT also call
    add_notification() themselves (that would create a duplicate row)."""
    first = (name or "Candidate").split()[0]
    if is_portal_course:
        body_html = (
            f"<p style='margin:0 0 14px;'>Your payment for <strong style='color:#FFFFFF;'>{course_title}</strong> "
            "is verified.</p>"
            "<p style='margin:0;color:#c9d3dd;'>Course access and certificate issuance are pending â€” "
            "we'll notify you the moment they're live.</p>"
        )
        push_body = f"Your payment for {course_title} is verified. Access/certificate issuance is pending."
    else:
        body_html = (
            f"<p style='margin:0 0 14px;'>Your payment for <strong style='color:#FFFFFF;'>{course_title}</strong> "
            "is verified â€” the course is now unlocked.</p>"
        )
        push_body = f"Your payment for {course_title} is verified â€” the course is now unlocked."
    html = _email_shell("Payment verified", f"Hi {first},", body_html,
                        cta_text="Open Portal", cta_url="https://internship.dbert.online/portal",
                        preheader=f"Payment verified for {course_title}")
    send_email_async(to_email, f"DBERT â€” Payment verified for {course_title}", html, name,
                     campaign="course_payment_verified")
    send_push_notification(to_email, "âœ… Payment verified", push_body, link_url)


def notify_course_payment_rejected(name, to_email, course_title, pay_url):
    first = (name or "Candidate").split()[0]
    body_html = (
        f"<p style='margin:0 0 14px;'>We couldn't verify your payment for "
        f"<strong style='color:#FFFFFF;'>{course_title}</strong>. Please re-submit a clear payment screenshot.</p>"
    )
    html = _email_shell("Action needed", f"Hi {first},", body_html,
                        cta_text="Re-upload payment proof", cta_url=pay_url,
                        preheader=f"Payment could not be verified for {course_title}")
    send_email_async(to_email, f"DBERT â€” Action needed for {course_title}", html, name,
                     campaign="course_payment_rejected")
    send_push_notification(to_email, "âš ï¸ Payment could not be verified",
                           f"We couldn't verify your payment for {course_title}. Please re-submit.", pay_url)


def notify_cert_issued(name, to_email, course_title, cert_url):
    """T7/T10 âš ï¸ tutor-dependent: cert issuance itself happens on the tutor side (not
    built yet), so nothing calls this function today -- it's wired ahead of time so the
    tutor webhook only has to call it, never simulate the issuance itself. ``cert_url``
    must be absolute (push/email convention -- see send_enrollment_reminder)."""
    first = (name or "Candidate").split()[0]
    body_html = (
        f"<p style='margin:0 0 14px;'>Your dual-verified certificate for "
        f"<strong style='color:#FFFFFF;'>{course_title}</strong> is ready.</p>"
        "<p style='margin:0;color:#c9d3dd;'>Companies reviewing your applications can now see it.</p>"
    )
    html = _email_shell("Certified", f"Hi {first},", body_html,
                        cta_text="View certificate", cta_url=cert_url,
                        preheader=f"Certificate issued for {course_title}")
    send_email_async(to_email, f"DBERT â€” Certificate issued for {course_title}", html, name,
                     campaign="cert_issued")
    send_push_notification(to_email, "ðŸ† Certificate issued", f"Your certificate for {course_title} is ready.", cert_url)


def send_post_selection_email(name, to_email, post_title, company_name, needed_certs, note=""):
    """Track 2 Â§B (UAT #4): a company has selected this applicant but needs them to
    complete one or more certifications first. needed_certs = [{course_id,title}]."""
    first = (name or "Candidate").split()[0]
    if needed_certs:
        items = "".join(
            f"<li style='margin:0 0 6px;'><a href='{TUTOR_BASE_URL}/courses/{c.get('course_id')}' "
            f"style='color:#E2B96F;font-weight:700;'>{(c.get('title') or 'Certification')}</a></li>"
            for c in needed_certs
        )
        certs_block = (
            "<p style='margin:16px 0 6px;color:#FFFFFF;font-weight:700;'>Certifications to complete:</p>"
            f"<ul style='margin:0 0 8px;padding-left:18px;color:#c9d3dd;font-size:13px;'>{items}</ul>"
        )
    else:
        certs_block = ""
    note_block = _email_info_box(
        "<p style='margin:0 0 8px;color:#E2B96F;font-size:13px;font-weight:700;'>Note from the company</p>"
        f"<p style='margin:0;color:#c9d3dd;font-size:13px;line-height:1.7;'>{note}</p>"
    ) if note else ""
    subject = f"DBERT â€” You've been selected for {post_title}"
    body_html = (
        f"<p style='margin:0 0 14px;'>Great news â€” <strong style='color:#E2B96F;'>{company_name}</strong> "
        f"has selected you for <strong style='color:#FFFFFF;'>{post_title}</strong>.</p>"
        "<p style='margin:0 0 4px;color:#c9d3dd;'>To proceed, please complete the required "
        "certification(s) below on the DBERT AI Tutor. Once done, the company will continue your application.</p>"
        f"{certs_block}{note_block}"
    )
    html = _email_shell("Selected", f"Hi {first},", body_html,
                        cta_text="View in My Applications",
                        cta_url="https://internship.dbert.online/portal",
                        preheader=f"Selected for {post_title} â€” certifications needed")
    send_email_async(to_email, subject, html, name, campaign="post_selection")
    cert_count = len(needed_certs or [])
    push_body = (
        f"{company_name} selected you for {post_title}. Complete {cert_count} certification(s) to proceed."
        if cert_count else f"{company_name} selected you for {post_title}. Open the portal for next steps."
    )
    send_push_notification(to_email, "ðŸŽ‰ You've been selected!", push_body)


def send_post_hire_deposit_status_email(name, to_email, post_title, new_status):
    """Track 5: notify the intern once admin verifies or rejects their â‚¹499
    job-hire deposit screenshot."""
    first = (name or "Candidate").split()[0]
    if new_status == "verified":
        subject = f"DBERT â€” Deposit confirmed for {post_title}"
        body_html = (
            f"<p style='margin:0 0 14px;'>Your â‚¹499 refundable security deposit for "
            f"<strong style='color:#FFFFFF;'>{post_title}</strong> has been verified. "
            "You're all set â€” the deposit is fully refundable on successful completion "
            "of the internship.</p>"
        )
        preheader = f"Deposit verified for {post_title}"
    else:
        subject = f"DBERT â€” Deposit payment could not be verified"
        body_html = (
            f"<p style='margin:0 0 14px;'>We couldn't verify your â‚¹499 deposit payment for "
            f"<strong style='color:#FFFFFF;'>{post_title}</strong>. Please re-upload a clear "
            "payment screenshot from your portal.</p>"
        )
        preheader = f"Deposit payment needs to be re-uploaded for {post_title}"
    html = _email_shell("Deposit Update", f"Hi {first},", body_html,
                        cta_text="Open your portal", cta_url="https://internship.dbert.online/portal",
                        preheader=preheader)
    send_email_async(to_email, subject, html, name, campaign="post_hire_deposit_status")
    push_body = (f"Your â‚¹499 deposit for {post_title} is confirmed." if new_status == "verified"
                 else f"Your â‚¹499 deposit payment for {post_title} needs to be re-uploaded.")
    send_push_notification(to_email, "ðŸ’³ Deposit update", push_body)


def send_enrollment_confirmation_email(name, to_email, domain, joining_date):
    first = (name or "Candidate").split()[0]
    batch_label = make_batch_label(joining_date)
    subject = "Enrollment received â€” DBERT"
    body = (
        f"<p style='margin:0 0 4px;'>We've received your enrollment for <strong style='color:#E2B96F;'>{domain}</strong> "
        f"and your payment proof.</p>"
        + _email_info_box(
            "<ul style='color:#aebacb;margin:0;padding-left:18px;line-height:2;font-size:13px;'>"
            "<li>We verify your payment within 24 hours</li>"
            f"<li>Your chosen batch: <strong style='color:#FFFFFF;'>{batch_label}</strong></li>"
            "<li>Your offer letter is shared once approved</li></ul>")
    )
    html = _email_shell("Enrollment Received", f"Hi {first}, enrollment received!", body,
                        cta_text="Open your portal", cta_url="https://internship.dbert.online/portal",
                        preheader=f"We've received your enrollment for {domain} and payment proof.")
    send_email_async(to_email, subject, html, name, campaign="enrollment_received")
    send_push_notification(
        to_email,
        "âœ… Enrollment Received â€” DBERT",
        f"Hi {first}! Your payment proof for {domain} has been received. Verification within 24 hours.",
    )


def send_enrollment_reminder(name, to_email, domain):
    """Reminder nudge for Selected-but-not-yet-enrolled candidates (sent by the daily cron)."""
    first = (name or "Candidate").split()[0]
    subject = "Your DBERT seat is waiting â€” complete enrollment"
    portal = "https://internship.dbert.online/portal"
    body = (
        f"<p style='margin:0 0 4px;'>You've been <strong style='color:#E2B96F;'>Selected</strong> for "
        f"<strong style='color:#E2B96F;'>{domain}</strong>, but your enrollment isn't complete yet. "
        f"Secure your seat before your batch fills up.</p>"
        + _email_info_box(
            "<p style='margin:0;color:#aebacb;font-size:13px;line-height:1.8;'>Log in, pick your joining Monday, "
            "and upload your payment proof to lock in your seat.</p>")
        + "<p style='margin:18px 0 0;color:#8a9ab5;font-size:12.5px;line-height:1.7;'>Prefer a faster path? "
          "Our <a href='https://internship.dbert.online/program' style='color:#E2B96F;font-weight:700;'>Paid Program</a> "
          "includes training, a production role, and a guaranteed placement opportunity with our hiring partners "
          "on completion + certification.</p>"
    )
    html = _email_shell("Enrollment Reminder", f"Hi {first}, your seat is waiting!", body,
                        cta_text="Complete Enrollment", cta_url=portal,
                        preheader="Complete your enrollment before your batch fills up.")
    send_email_async(to_email, subject, html, name, campaign="enrollment_reminder")
    send_push_notification(
        to_email,
        "â³ Complete Your Enrollment",
        f"Hi {first}! Your seat for {domain} is waiting. Complete enrollment before your batch fills.",
        portal,
    )


def send_paid_payment_rejected_email(name, to_email, domain):
    """Phase 12 / F4 â€” paid-program payment could not be verified; ask to re-upload (NOT the â‚¹499 flow)."""
    first = (name or "Candidate").split()[0]
    subject = "Action needed â€” re-upload your Paid Program payment"
    prog = "https://internship.dbert.online/program"
    body = (
        f"<p style='margin:0 0 12px;'>We couldn't verify your payment for the <strong style='color:#E2B96F;'>Paid Program</strong> "
        f"({domain}). This is usually just a blurry or partial screenshot â€” <strong style='color:#FFFFFF;'>your seat is still held</strong>.</p>"
        "<p style='margin:0;'>Please re-upload a clear payment screenshot on the program page to confirm your enrolment.</p>"
    )
    html = _email_shell("Action Needed", f"Hi {first}, re-upload your payment", body,
                        cta_text="Re-upload payment proof", cta_url=prog,
                        preheader="We couldn't verify your Paid Program payment â€” your seat is still held.")
    send_email_async(to_email, subject, html, name, campaign="paid_payment_rejected")
    send_push_notification(to_email, "ðŸ’³ Re-upload your payment", f"Hi {first}! We couldn't verify your Paid Program payment for {domain}. Please re-upload your proof.", prog)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE ROUTES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/")
def index():
    try:
        return render_template(
            "index.html",
            job_openings=live_openings_total(),
            domain_tiles=_domain_tile_counts(),
            trust_stats=_trust_stats(),
        )
    except Exception as e:
        log_error("/index", e)
        return "Server error", 500


@app.route("/program")
def program_page():
    """Phase 12.3 â€” public, indexable paid-program landing page (terms shown before any CTA)."""
    try:
        return render_template("program.html", paid_amount=PAID_PROGRAM_AMOUNT, upi_id=UPI_ID)
    except Exception as e:
        log_error("/program", e)
        return "Server error", 500


@app.route("/robots.txt")
def robots_txt():
    """Phase 12.6 â€” public/JD/program indexable; private surfaces disallowed."""
    body = (
        "User-agent: *\n"
        "Allow: /$\n"
        "Allow: /program\n"
        "Allow: /terms\n"
        "Allow: /privacy\n"
        # Track 2 Â§7: public job board + CVs are indexable (canonical on this origin).
        "Allow: /jobs\n"
        "Allow: /internships\n"
        "Allow: /cv/\n"
        "Disallow: /admin\n"
        "Disallow: /admin-login\n"
        "Disallow: /mentor\n"
        "Disallow: /profile\n"
        "Disallow: /dashboard\n"
        "Disallow: /portal\n"
        "Disallow: /messages\n"
        "Disallow: /interview\n"
        # No-SEO-value endpoints (auth, actions, tracking) â€” keep out of the index.
        "Disallow: /reset\n"
        "Disallow: /signin\n"
        "Disallow: /signup\n"
        "Disallow: /apply\n"
        "Disallow: /unsubscribe\n"
        "Disallow: /e/\n"
        "Disallow: /cron\n"
        f"Sitemap: {SITE_ORIGIN}/sitemap.xml\n"
    )
    return Response(body, mimetype="text/plain")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 7 routes â€” intern Ambassador tab (spec Â§6.6) + admin payouts (Â§6.5)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

RL_UPI_UPDATE  = _rl("UPI_UPDATE",  5, 3600)    # 5 / hour per intern
RL_WITHDRAWAL  = _rl("WITHDRAWAL",  3, 3600)    # 3 / hour per intern


@app.route("/ambassador")
def ambassador_page():
    """Intern-facing College Ambassador tab (Â§6.6)."""
    if not current_intern():
        return redirect("/#signin")
    return render_template("ambassador.html")


@app.route("/r/click")
def referral_click():
    """Anonymous click beacon for /?ref=<code> (Â§6.1). Always 204 â€” a bad or
    unknown code must never reveal whether it exists."""
    try:
        code = clean_text(request.args.get("ref"))
        if code:
            with get_db() as conn:
                record_referral_click(conn, code)
                conn.commit()
    except Exception as e:
        log_error("referral-click", e)
    return ("", 204)


@app.route("/intern/ambassador")
def intern_ambassador():
    """Funnel stats, referral link, referral-coin balance, masked UPI (Â§6.6)."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            acct = conn.execute(
                "SELECT id, name, referral_code, upi_id_encrypted FROM intern_accounts WHERE id=?",
                (intern["id"],)).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found"}), 404

            code = acct["referral_code"] or ensure_referral_code(conn, acct["id"], acct["name"])
            conn.commit()

            funnel = {"clicked": 0, "signed_up": 0, "converted": 0}
            for r in conn.execute(
                    "SELECT status, COUNT(*) c FROM referrals WHERE referrer_intern_id=? GROUP BY status",
                    (acct["id"],)).fetchall():
                funnel[r["status"]] = r["c"]
            # a signup is also a click, a conversion is also a signup
            funnel["clicked"]   += funnel["signed_up"] + funnel["converted"]
            funnel["signed_up"] += funnel["converted"]

            referrals = [row_to_dict(r) for r in conn.execute(
                "SELECT r.status, r.created_at, r.flagged, a.name AS referred_name "
                "FROM referrals r LEFT JOIN intern_accounts a ON a.id = r.referred_intern_id "
                "WHERE r.referrer_intern_id=? AND r.referred_intern_id IS NOT NULL "
                "ORDER BY r.id DESC LIMIT 50", (acct["id"],)).fetchall()]

            balances = get_coin_balances(conn, acct["id"])
            pending = conn.execute(
                "SELECT COALESCE(SUM(amount),0) v FROM ambassador_withdrawals "
                "WHERE intern_id=? AND status IN ('pending','approved')", (acct["id"],)
            ).fetchone()["v"]
            withdrawals = [row_to_dict(r) for r in conn.execute(
                "SELECT id, amount, status, requested_at, admin_note FROM ambassador_withdrawals "
                "WHERE intern_id=? ORDER BY id DESC LIMIT 20", (acct["id"],)).fetchall()]

        # never send the UPI itself â€” only whether one exists, and its mask
        upi_plain = decrypt_upi(acct["upi_id_encrypted"]) if acct["upi_id_encrypted"] else None
        return jsonify({
            "status": "success",
            "enabled": AMBASSADOR_ENABLED,
            "code": code,
            "link": referral_link(code),
            "funnel": funnel,
            "referrals": referrals,
            "referral_balance": balances["referral"],
            "pending_withdrawal": pending,
            "available": max(0, balances["referral"] - pending),
            "upi_masked": mask_upi(upi_plain) if upi_plain else "",
            "has_upi": bool(acct["upi_id_encrypted"]),
            "withdrawals": withdrawals,
        })
    except Exception as e:
        log_error("intern-ambassador", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/ambassador/upi", methods=["POST"])
def intern_ambassador_upi():
    """Store the payout UPI id â€” encrypted at rest, never returned in clear."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ip = get_client_ip()
        allowed, retry_after = rate_check(f"upi:{intern['id']}", *RL_UPI_UPDATE)
        if not allowed:
            log_abuse(ip, "/intern/ambassador/upi", f"upi:{intern['id']}", "rate_limit")
            return jsonify({"status": "error", "message": "Too many updates. Try again later.",
                            "retry_after": retry_after}), 429

        upi = clean_text((request.get_json(silent=True) or {}).get("upi_id"))
        if not is_valid_upi(upi):
            return jsonify({"status": "error", "message": "Enter a valid UPI id, e.g. name@bank."}), 400

        cipher = encrypt_upi(upi)
        if not cipher:
            # Â§5.4 â€” refuse rather than fall back to plaintext.
            log_error("upi-encrypt", RuntimeError("FERNET_KEY missing or invalid"))
            return jsonify({"status": "error",
                            "message": "Payouts are temporarily unavailable. Please try later."}), 503

        with get_db() as conn:
            conn.execute("UPDATE intern_accounts SET upi_id_encrypted=? WHERE id=?",
                         (cipher, intern["id"]))
            conn.commit()
        return jsonify({"status": "success", "message": "UPI id saved.",
                        "upi_masked": mask_upi(upi)})
    except Exception as e:
        log_error("intern-ambassador-upi", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/ambassador/withdraw", methods=["POST"])
def intern_ambassador_withdraw():
    """Request a payout. Draws ONLY on the referral ledger (Â§6.5)."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ip = get_client_ip()
        allowed, retry_after = rate_check(f"wd:{intern['id']}", *RL_WITHDRAWAL)
        if not allowed:
            log_abuse(ip, "/intern/ambassador/withdraw", f"wd:{intern['id']}", "rate_limit")
            return jsonify({"status": "error", "message": "Too many requests. Try again later.",
                            "retry_after": retry_after}), 429

        try:
            amount = int((request.get_json(silent=True) or {}).get("amount") or 0)
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0:
            return jsonify({"status": "error", "message": "Enter an amount."}), 400

        with get_db() as conn:
            acct = conn.execute(
                "SELECT upi_id_encrypted FROM intern_accounts WHERE id=?", (intern["id"],)).fetchone()
            if not acct or not acct["upi_id_encrypted"]:
                return jsonify({"status": "error",
                                "message": "Add your UPI id before requesting a withdrawal."}), 400

            balance = get_coin_balances(conn, intern["id"])["referral"]
            pending = conn.execute(
                "SELECT COALESCE(SUM(amount),0) v FROM ambassador_withdrawals "
                "WHERE intern_id=? AND status IN ('pending','approved')", (intern["id"],)
            ).fetchone()["v"]
            available = balance - pending
            if amount > available:
                return jsonify({"status": "error",
                                "message": f"You can withdraw at most â‚¹{available}."}), 400

            conn.execute(
                "INSERT INTO ambassador_withdrawals (intern_id, amount, status) VALUES (?,?, 'pending')",
                (intern["id"], amount))
            conn.commit()
        return jsonify({"status": "success",
                        "message": "Withdrawal requested. We'll review it shortly."})
    except Exception as e:
        log_error("intern-ambassador-withdraw", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/ambassador-payouts")
def admin_ambassador_payouts():
    """Payout queue (Â§6.5) â€” mirrors /admin/post-hire-deposits."""
    if not (is_admin_request() or current_staff()):
        return redirect("/admin/login")
    with get_db() as conn:
        rows = [row_to_dict(r) for r in conn.execute(
            "SELECT w.*, a.name AS intern_name, a.email AS intern_email "
            "FROM ambassador_withdrawals w JOIN intern_accounts a ON a.id = w.intern_id "
            "ORDER BY CASE w.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, w.id DESC"
        ).fetchall()]
    # UPI is deliberately absent here: it is never rendered in a list view (Â§5.4).
    return render_template("admin_ambassador_payouts.html", rows=rows,
                           fernet_ready=bool(FERNET_KEY))


@app.route("/admin/ambassador-payouts/<int:wid>/upi", methods=["POST"])
def admin_ambassador_reveal_upi(wid):
    """Decrypt and return the UPI id ONCE, logging who looked and when (Â§6.5)."""
    if not (is_admin_request() or current_staff()):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    who = (session.get("staff_email") or session.get("admin_id") or "admin")
    with get_db() as conn:
        row = conn.execute(
            "SELECT w.id, a.upi_id_encrypted FROM ambassador_withdrawals w "
            "JOIN intern_accounts a ON a.id = w.intern_id WHERE w.id=?", (wid,)).fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Not found"}), 404
        upi = decrypt_upi(row["upi_id_encrypted"])
        if not upi:
            return jsonify({"status": "error",
                            "message": "Could not decrypt â€” check FERNET_KEY."}), 503
        conn.execute("UPDATE ambassador_withdrawals SET upi_viewed_by=?, upi_viewed_at=? WHERE id=?",
                     (str(who), now_str(), wid))
        conn.commit()
    log_abuse(get_client_ip(), "/admin/ambassador-payouts", f"upi_view:{wid}", "upi_revealed")
    return jsonify({"status": "success", "upi_id": upi})


@app.route("/admin/ambassador-payouts/<int:wid>/decision", methods=["POST"])
def admin_ambassador_decision(wid):
    """Mark a payout Paid or Rejected. On Paid, debit the referral ledger."""
    if not (is_admin_request() or current_staff()):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    decision = clean_text(data.get("decision"))
    note = clean_text(data.get("note")) or ""
    if decision not in ("paid", "rejected"):
        return jsonify({"status": "error", "message": "decision must be paid|rejected"}), 400

    who = session.get("staff_id") or session.get("admin_id")
    with get_db() as conn:
        w = conn.execute("SELECT * FROM ambassador_withdrawals WHERE id=?", (wid,)).fetchone()
        if not w:
            return jsonify({"status": "error", "message": "Not found"}), 404
        if w["status"] in ("paid", "rejected"):
            return jsonify({"status": "error", "message": "Already reviewed."}), 409

        if decision == "paid":
            # The debit is the guard: it refuses to overdraw and refuses to run
            # twice for the same withdrawal id.
            new_bal = debit_referral_coins(
                conn, w["intern_id"], w["amount"],
                f"Ambassador payout #{wid}", withdrawal_id=wid)
            if new_bal is None:
                return jsonify({"status": "error",
                                "message": "Balance no longer covers this payout."}), 409

        conn.execute(
            "UPDATE ambassador_withdrawals SET status=?, reviewed_by_admin_id=?, reviewed_at=?, "
            "admin_note=? WHERE id=?", (decision, who, now_str(), note, wid))
        conn.commit()
    return jsonify({"status": "success", "message": f"Marked {decision}."})


@app.route("/ads.txt")
def ads_txt():
    """Spec Â§7 â€” AdSense authorised-sellers file.

    Must be served from the DOMAIN ROOT as text/plain; Google's crawler will not
    follow a redirect to a subdirectory. The publisher id comes from the env so
    it is not baked into the source, and the route 404s when unset rather than
    publishing a placeholder â€” an ads.txt naming the wrong seller is worse than
    no ads.txt, because it actively de-authorises your own inventory.
    """
    if not ADSENSE_PUB_ID:
        return Response("", status=404, mimetype="text/plain")
    body = f"google.com, {ADSENSE_PUB_ID}, DIRECT, f08c47fec0942fa0\n"
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    """Phase 12.6 / 13 â€” only the public, indexable URLs (homepage, program, legal)."""
    today = date.today().strftime("%Y-%m-%d")
    # (loc, lastmod, changefreq, priority)
    pages = [
        (f"{SITE_ORIGIN}/",        today, "weekly",  "1.0"),
        (f"{SITE_ORIGIN}/program", today, "weekly",  "0.9"),
        (f"{SITE_ORIGIN}/jobs",        today, "daily",   "0.8"),
        (f"{SITE_ORIGIN}/internships", today, "daily",   "0.8"),
        (f"{SITE_ORIGIN}/terms",   today, "yearly",  "0.3"),
        (f"{SITE_ORIGIN}/privacy", today, "yearly",  "0.3"),
    ]
    # Track 2 Â§7: live posts (published & non-expired auto-drop) + public CVs.
    with get_db() as conn:
        for r in conn.execute(
            f"SELECT id, post_type, slug, updated_at FROM posts WHERE {_LIVE_SQL} "
            "ORDER BY published_at DESC").fetchall():
            lm = (r["updated_at"] or "")[:10] or today
            pages.append((f"{SITE_ORIGIN}{_post_path(r)}", lm, "weekly", "0.7"))
        # T8: location landing pages, only once a (post_type, city) has >=3 live posts
        # (thin pages stay noindex + out of the sitemap -- they light up as inventory lands).
        for r in conn.execute(
            f"SELECT post_type, location, MAX(updated_at) AS lm FROM posts WHERE {_LIVE_SQL} "
            "AND location != '' GROUP BY post_type, location HAVING COUNT(*) >= 3").fetchall():
            base = "/internships" if r["post_type"] == "internship" else "/jobs"
            lm = (r["lm"] or "")[:10] or today
            pages.append((f"{SITE_ORIGIN}{base}/{_city_slugify(r['location'])}", lm, "weekly", "0.6"))
        for r in conn.execute(
            "SELECT slug, updated_at FROM cvs WHERE is_public=1 AND slug IS NOT NULL").fetchall():
            lm = (r["updated_at"] or "")[:10] or today
            pages.append((f"{SITE_ORIGIN}/cv/{r['slug']}", lm, "monthly", "0.4"))
    items = "".join(
        f"<url><loc>{loc}</loc><lastmod>{lm}</lastmod>"
        f"<changefreq>{cf}</changefreq><priority>{pr}</priority></url>"
        for loc, lm, cf, pr in pages
    )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           f"{items}</urlset>")
    return Response(xml, mimetype="application/xml")


@app.route("/signin")
def signin_page():
    """Redirect to index with hash â€” index.html handles the panel."""
    return redirect("/#signin")


@app.route("/signup")
def signup_page():
    return redirect("/#signup")


@app.route("/terms")
def terms_page():
    """Phase 13 â€” Terms & Conditions (public, indexable). Linked from the signup consent."""
    return render_template("terms.html")


@app.route("/privacy")
def privacy_page():
    """Phase 13 â€” Privacy Policy (public, indexable). Linked from the signup consent."""
    return render_template("privacy.html")


@app.route("/unsubscribe")
def unsubscribe():
    """Phase 13 â€” one-click newsletter unsubscribe (signed link from email footer /
    List-Unsubscribe header). Clears newsletter_opt_in; transactional status emails are
    unaffected (those are service messages, not marketing)."""
    email = clean_text(request.args.get("e") or "").lower()
    token = clean_text(request.args.get("t") or "")
    ok = bool(email) and hmac.compare_digest(token, _email_sig("unsub", email))
    if ok:
        try:
            with get_db() as conn:
                conn.execute("UPDATE intern_accounts SET newsletter_opt_in=0, updated_at=? WHERE email=?",
                             (now_str(), email)); conn.commit()
        except Exception as e:
            log_error("unsubscribe", e)
    if request.method == "POST":   # RFC 8058 one-click
        return ("", 200)
    msg = ("You've been unsubscribed from DBERT marketing emails."
           if ok else "This unsubscribe link is invalid or expired.")
    return Response(
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Unsubscribe â€” DBERT</title></head>"
        f"<body style='margin:0;background:#0B0F17;color:#fff;font-family:Inter,Arial,sans-serif;'>"
        f"<div style='max-width:520px;margin:80px auto;padding:32px;text-align:center;background:rgba(20,24,33,.6);"
        f"border:1px solid rgba(255,255,255,.08);border-radius:16px;'>"
        f"<div style='font-size:40px;'>{'âœ…' if ok else 'âš ï¸'}</div>"
        f"<h1 style='font-size:20px;margin:12px 0;'>{msg}</h1>"
        f"<p style='color:#94A3B8;font-size:13px;'>You'll still receive essential messages about your application.</p>"
        f"<a href='{EMAIL_SITE}/' style='color:#E2B96F;font-weight:700;'>Back to DBERT</a></div></body></html>",
        mimetype="text/html")


# 1x1 transparent GIF for email open-tracking.
_PIXEL_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04"
              b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;")

@app.route("/e/o.gif")
def email_open_pixel():
    """Phase 13 â€” email open tracking. Verifies the signed token, stamps opened_at on the
    candidate's most recent un-opened email_log row, and always returns a 1x1 GIF."""
    try:
        email = clean_text(request.args.get("e") or "").lower()
        token = clean_text(request.args.get("t") or "")
        if email and hmac.compare_digest(token, _email_sig("open", email)):
            with get_db() as conn:
                conn.execute(
                    "UPDATE email_log SET opened_at=? WHERE id=(SELECT id FROM email_log "
                    "WHERE email=? AND opened_at IS NULL ORDER BY id DESC LIMIT 1)",
                    (now_str(), email)); conn.commit()
    except Exception as e:
        log_error("email-open-pixel", e)
    resp = make_response(_PIXEL_GIF)
    resp.headers["Content-Type"] = "image/gif"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.route("/reset")
def reset_password_page():
    """Render the reset-password page; JS reads ?token= from the URL."""
    try:
        return render_template("reset_password.html")
    except Exception as e:
        log_error("/reset", e)
        return "Server error", 500


@app.route("/portal")
def portal_page():
    """Phase 13 â€” unified tabbed portal (merges the old /profile + /dashboard).
    Intern session; same light client-side auth as profile_page (the client's
    /intern/me call redirects to sign-in on 401). All status views, account
    settings, interview, paid program, and learning live here as tabs."""
    try:
        return render_template("portal.html")
    except Exception as e:
        log_error("/portal", e)
        return "Server error", 500


@app.route("/enrollment-count")
def enrollment_count():
    try:
        with get_db() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM enrollments").fetchone()["c"]
        return jsonify({"status": "success", "total_enrolled": n})
    except Exception as e:
        log_error("/enrollment-count", e)
        return jsonify({"status": "error", "total_enrolled": 0}), 500


# /profile and /dashboard now redirect into the unified portal so existing links
# and bookmarks keep working (both route names stay registered). 302 by default.
@app.route("/profile")
def profile_page():
    return redirect("/portal")


@app.route("/dashboard")
def dashboard_page():
    return redirect("/portal")


@app.route("/interview")
def interview_page():
    """Phase 11.6 â€” candidate-initiated AI interview page. Intern session required."""
    try:
        user = require_role("intern")
        if not user:
            return redirect("/#signin")
        return render_template("interview.html")
    except Exception as e:
        log_error("/interview", e)
        return "Server error", 500


@app.route("/mentor")
def mentor_page():
    try:
        return render_template("mentor.html")
    except Exception as e:
        log_error("/mentor", e)
        return "Server error", 500


# â”€â”€ Admin Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/admin-login")
def admin_login_page():
    if require_admin():
        return redirect("/admin")
    try:
        return render_template("admin_login.html")
    except Exception as e:
        log_error("/admin-login", e)
        return "Server error", 500


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if require_admin():
            return redirect("/admin")
        return render_template("admin_login.html")

    try:
        data = request.get_json(force=True, silent=True) or {}
        username = (request.form.get("email") or request.form.get("username") or data.get("username") or data.get("email") or "").strip().lower()
        password = (request.form.get("password") or data.get("password") or "").strip()
        if not username or not password:
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"status": "error", "message": "Username/Email and password required."}), 400
            return render_template("admin_login.html", error="Email and password are required")
            
        ip = get_client_ip()
        allowed, ra = rate_check(f"login:admin:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/admin/login", f"login:admin:ip:{ip}", "rate_limit", username)
            return too_many(ra)
            
        # Check 1: staff_accounts database table
        staff = None
        with get_db() as conn:
            staff = conn.execute("SELECT * FROM staff_accounts WHERE (email=? OR name=?) AND is_active=1", (username, username)).fetchone()
            
        auth_valid = False
        staff_id = 1
        staff_name = "Admin Staff"
        staff_email = username
        
        if staff and verify_password(staff["password_hash"], password):
            auth_valid = True
            staff_id = staff["id"]
            staff_name = staff["name"]
            staff_email = staff["email"]
            
        if not auth_valid and ADMIN_PASSWORD and username in (ADMIN_USERNAME.lower(), "admin@dbert.online", "admin", "dbert_admin") and hmac.compare_digest(password, ADMIN_PASSWORD):
            auth_valid = True
            staff_id = staff["id"] if staff else 1
            staff_name = staff["name"] if staff else "Admin Staff"
            staff_email = staff["email"] if staff else username
            
        if not auth_valid:
            record_login_fail(username)
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"status": "error", "message": "Invalid credentials."}), 401
            return render_template("admin_login.html", error="Invalid admin credentials")
            
        clear_login_fails(username)
        session["admin_id"] = staff_id
        session["staff_id"] = staff_id
        session["staff_email"] = staff_email
        session["staff_name"] = staff_name
        
        token = create_session(staff_email, "admin")
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            resp = make_response(jsonify({"status": "success", "message": "Login successful.", "redirect": "/admin"}))
        else:
            resp = make_response(redirect("/admin"))
            
        return _set_session_cookie(resp, token)
    except Exception as e:
        log_error("admin-login", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin")
def admin_page():
    try:
        user = require_admin()
        if not user:
            return redirect("/admin-login")
        return render_template("admin.html")
    except Exception as e:
        log_error("/admin", e)
        return "Server error", 500


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    try:
        invalidate_session(get_session_token_from_request())
        resp = make_response(jsonify({"status": "success"}))
        _clear_session_cookie(resp)
        return resp
    except Exception as e:
        log_error("admin-logout", e)
        return jsonify({"status": "error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TUTOR SSO
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _intern_payment_verified(email):
    """T9 âš ï¸ security fix: true once admin has verified payment and the intern's
    application is Accepted (see admin_update_enrollment_status, the only place that
    sets STATUS_ACCEPTED -- it's the unified payment-verified terminal state for both
    the free and paid_program enrollment tracks). This is the server-side gate for
    minting a tutor SSO token; before this it was a front-end-only check, so any
    logged-in intern (paid or not) could mint a real token -- the paywall bypass."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM applications WHERE email=? AND status=? LIMIT 1",
            (email, STATUS_ACCEPTED),
        ).fetchone()
    return row is not None


@app.route('/generate-tutor-token', methods=['POST'])
def generate_tutor_token():
    user = get_current_user()
    if not user:
        return jsonify({"status": "error", "message": "Not logged in"}), 401
    if not TUTOR_SSO_SECRET:
        return jsonify({"status": "error", "message": "Tutor SSO not configured"}), 503
    if not _intern_payment_verified(user['email']):
        return jsonify({"status": "error", "message": "Your enrollment payment hasn't been verified yet."}), 403
    try:
        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1",
                (user['email'],)
            ).fetchone()
            enr = conn.execute(
                "SELECT * FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
                (user['email'],)
            ).fetchone()
        if not acct:
            return jsonify({"status": "error", "message": "Account not found"}), 404
        acct = row_to_dict(acct)
        enr  = row_to_dict(enr) if enr else {}

        # Joining date guard â€” cannot launch tutor before joining date at 18:00
        joining_date_str = enr.get('joining_date', '')
        if not joining_unlocked(joining_date_str):
            try:
                joining_dt = datetime.strptime(joining_date_str, "%Y-%m-%d").date()
                pretty = joining_dt.strftime('%-d %b %Y')
            except ValueError:
                pretty = joining_date_str
            return jsonify({
                "status":        "error",
                "before_joining": True,
                "joining_date":  joining_date_str,
                "message":       f"Classes start on {pretty} at 6:00 PM",
            }), 403

        payload = {
            "jti":        str(uuid.uuid4()),
            "iss":        "internship.dbert.online",
            "iat":        int(time.time()),
            "exp":        int(time.time()) + 90,
            "intern_id":  str(acct['id']),
            "name":       acct.get('name', ''),
            "email":      acct.get('email', ''),
            "phone":      acct.get('phone', ''),
            "city":       acct.get('city', ''),
            "college":    acct.get('college', ''),
            "course":     acct.get('course', ''),
            "semester":   acct.get('semester', ''),
            "domain": {
                "Full Stack Development": "full_stack",
                "AI Agent Development":   "ai_agent",
                "Data Analyst":           "data_science",
                "Python Automation":      "python_automation",
            }.get(acct.get('domain', ''), acct.get('domain', '')),
            "batch_start": joining_date_str,
            "batch_end":   '',
            "is_admin": False,
            "applications": [],
        }
        token = jwt.encode(payload, TUTOR_SSO_SECRET, algorithm="HS256")
        return jsonify({"status": "success", "redirect_url": f"{TUTOR_BASE_URL}/sso?token={token}"})
    except Exception as e:
        log_error("generate-tutor-token", e)
        return jsonify({"status": "error", "message": "Failed to generate token"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# P17 â€” MOBILE AUTH (parallel path beside generate_tutor_token; that 90s SSO
# mint and tutor_progress_update are intentionally left untouched). The Flutter
# app logs in here and receives a long-lived access JWT (same shape/secret the
# tutor backend already verifies) + a rotating opaque refresh token.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# Domain slug map shared with the tutor backend. Mirrors the inline map inside
# generate_tutor_token exactly; this is the single reusable copy for the mobile path.
TUTOR_DOMAIN_SLUGS = {
    "Full Stack Development": "full_stack",
    "AI Agent Development":   "ai_agent",
    "Data Analyst":           "data_science",
    "Python Automation":      "python_automation",
}


def tutor_domain_slug(domain):
    return TUTOR_DOMAIN_SLUGS.get(domain or "", domain or "")


# â”€â”€ Track 1 Â§3 â€” web tutor login fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# An intern who opens the AI Tutor on the web without a session is bounced to
# the portal login (passwords live only here); on success we mint the same 90s
# SSO token generate_tutor_token uses and 302 them back. generate_tutor_token
# itself is left unmodified â€” this is the reusable mint for the login path.
def mint_tutor_sso_token(acct, joining_date_str):
    now = int(time.time())
    payload = {
        "jti":        str(uuid.uuid4()),
        "iss":        "internship.dbert.online",
        "iat":        now,
        "exp":        now + 90,
        "intern_id":  str(acct["id"]),
        "name":       acct.get("name", ""),
        "email":      acct.get("email", ""),
        "phone":      acct.get("phone", ""),
        "city":       acct.get("city", ""),
        "college":    acct.get("college", ""),
        "course":     acct.get("course", ""),
        "semester":   acct.get("semester", ""),
        "domain":     tutor_domain_slug(acct.get("domain", "")),
        "batch_start": joining_date_str or "",
        "batch_end":  "",
        "is_admin":   False,
        "applications": [],
    }
    return jwt.encode(payload, TUTOR_SSO_SECRET, algorithm="HS256")


def _safe_tutor_next(raw):
    """Open-redirect guard for the tutor deep-link: only a single-slash
    site-relative path is honored; anything else falls back to the dashboard."""
    nxt = (raw or "").strip()
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return "/dashboard"
    return nxt


def _joining_pretty(joining_date_str):
    # Cross-platform (no Linux-only %-d): zero-pad then strip the leading zero.
    try:
        return datetime.strptime(joining_date_str, "%Y-%m-%d").date().strftime("%d %b %Y").lstrip("0")
    except (ValueError, TypeError):
        return ""


@app.route("/login", methods=["GET"])
def portal_login_entry():
    """Login entry for external return-flows (Track 1 Â§3). The AI Tutor sends an
    unauthenticated intern to ``/login?return_to=tutor&next=<relative>``. We
    allowlist return_to to 'tutor' only, validate next is relative, stash both
    in the session, then open the sign-in overlay. intern_login() reads them
    back on success and bounces to the tutor (gate open) or holds on the portal
    with the 6 PM message (gate closed)."""
    if (request.args.get("return_to") or "").strip() == "tutor":
        session["post_login_return_to"] = "tutor"
        session["post_login_next"] = _safe_tutor_next(request.args.get("next"))
    else:
        session.pop("post_login_return_to", None)
        session.pop("post_login_next", None)
    return redirect("/#signin")


def _hash_refresh_token(raw):
    """Refresh tokens are high-entropy opaque strings; store only their SHA-256.
    Never log or persist the plaintext. (Unlike passwords, no salt/KDF needed â€”
    these are 384-bit random, not user-chosen.)"""
    return hashlib.sha256((raw or "").encode()).hexdigest()


def mint_mobile_access_token(acct, joining_date_str):
    """HS256 access JWT signed with TUTOR_SSO_SECRET. Claims match what the tutor
    backend verifies (iss/jti/exp/intern_id + domain slug) so it is accepted on
    the Bearer path unchanged; token_use marks it as a mobile access token."""
    now = int(time.time())
    payload = {
        "jti":         str(uuid.uuid4()),
        "iss":         "internship.dbert.online",
        "iat":         now,
        "exp":         now + ACCESS_TTL,
        "intern_id":   str(acct["id"]),
        "name":        acct.get("name", ""),
        "email":       acct.get("email", ""),
        # P1-6: Removed phone, city, college, course, semester for PII reduction
        "domain":      tutor_domain_slug(acct.get("domain", "")),
        "batch_start": joining_date_str or "",
        "batch_end":   "",
        "is_admin":    False,
        "applications": [],
        "token_use":   "mobile_access",
    }
    return jwt.encode(payload, TUTOR_SSO_SECRET, algorithm="HS256")


def issue_refresh_token(intern_id, email):
    """Create + persist a new refresh token; return the plaintext ONCE (only the
    hash is stored). Caller returns it to the client and never logs it."""
    raw = secrets.token_urlsafe(48)
    expires_at = (datetime.now() + timedelta(seconds=REFRESH_TTL)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO mobile_refresh_tokens "
            "(token_hash, intern_id, email, issued_at, expires_at, revoked) "
            "VALUES (?,?,?,?,?,0)",
            (_hash_refresh_token(raw), str(intern_id), email.lower(), now_str(), expires_at),
        )
        conn.commit()
    return raw


@app.route('/api/tutor/mobile/login', methods=['POST'])
def mobile_login():
    """Mobile login â€” mirrors the intern_login security flow, then mints an
    access JWT + refresh token. Adds the joining-date gate."""
    try:
        if not TUTOR_SSO_SECRET:
            return jsonify({"error": "server_misconfigured"}), 503
        data     = request.get_json(force=True, silent=True) or {}
        email    = clean_text(data.get("email")).lower()
        password = clean_text(data.get("password"))
        if not email or not password:
            return jsonify({"error": "missing_fields"}), 400
        ip = get_client_ip()
        allowed, ra = rate_check(f"login:intern:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/api/tutor/mobile/login", f"login:intern:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        locked, _ = login_locked(email)
        if locked:
            log_abuse(ip, "/api/tutor/mobile/login", _login_fail_bucket(email), "login_lockout", email)
            return jsonify({"error": "invalid_credentials"}), 401
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
            enr = conn.execute(
                "SELECT joining_date FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
            ).fetchone()
        if not user:
            record_login_fail(email)
            return jsonify({"error": "invalid_credentials"}), 401
        if int(user["password_set"] or 0) != 1:
            return jsonify({"error": "password_not_set"}), 400
        if not verify_password(user["password_hash"], password):
            record_login_fail(email)
            return jsonify({"error": "invalid_credentials"}), 401
        if is_legacy_hash(user["password_hash"]):
            migrate_password_hash("intern_accounts", email, password)  # P17.0 lazy upgrade
        clear_login_fails(email)
        acct = row_to_dict(user)
        if not _intern_payment_verified(email):
            return jsonify({"error": "payment_not_verified"}), 403
        joining_date_str = (enr["joining_date"] if enr and enr["joining_date"] else "")
        if not joining_unlocked(joining_date_str):
            return jsonify({"error": "before_joining"}), 403
        access  = mint_mobile_access_token(acct, joining_date_str)
        refresh = issue_refresh_token(acct["id"], email)
        return jsonify({
            "access_token":  access,
            "refresh_token": refresh,
            "expires_in":    ACCESS_TTL,
            "user": {
                "intern_id": str(acct["id"]),
                "name":      acct.get("name", ""),
                "email":     acct.get("email", ""),
                "domain":    tutor_domain_slug(acct.get("domain", "")),
            },
        })
    except Exception as e:
        log_error("mobile-login", e)
        return jsonify({"error": "server_error"}), 500


@app.route('/api/tutor/mobile/refresh', methods=['POST'])
def mobile_refresh():
    """Validate a non-revoked, unexpired refresh token; ROTATE it (revoke old,
    issue new) and mint a fresh access JWT."""
    try:
        if not TUTOR_SSO_SECRET:
            return jsonify({"error": "server_misconfigured"}), 503
        data = request.get_json(force=True, silent=True) or {}
        raw  = clean_text(data.get("refresh_token"))
        ip = get_client_ip()
        allowed, ra = rate_check(f"mobilerefresh:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/api/tutor/mobile/refresh", f"mobilerefresh:ip:{ip}", "rate_limit")
            return too_many(ra)
        if not raw:
            return jsonify({"error": "invalid_refresh"}), 401
        token_hash = _hash_refresh_token(raw)
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM mobile_refresh_tokens WHERE token_hash=? LIMIT 1", (token_hash,)
            ).fetchone()
            if (not row) or int(row["revoked"] or 0) == 1 or (row["expires_at"] <= now_str()):
                return jsonify({"error": "invalid_refresh"}), 401
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE id=? AND is_active=1 LIMIT 1", (row["intern_id"],)
            ).fetchone()
            if not acct:
                return jsonify({"error": "invalid_refresh"}), 401
            enr = conn.execute(
                "SELECT joining_date FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1", (row["email"],)
            ).fetchone()
            # Rotation: revoke the presented refresh token before issuing a new one.
            conn.execute(
                "UPDATE mobile_refresh_tokens SET revoked=1, last_used_at=? WHERE id=?",
                (now_str(), row["id"]),
            )
            conn.commit()
        acct = row_to_dict(acct)
        joining_date_str = (enr["joining_date"] if enr and enr["joining_date"] else "")
        new_refresh = issue_refresh_token(acct["id"], row["email"])
        access      = mint_mobile_access_token(acct, joining_date_str)
        return jsonify({
            "access_token":  access,
            "refresh_token": new_refresh,
            "expires_in":    ACCESS_TTL,
        })
    except Exception as e:
        log_error("mobile-refresh", e)
        return jsonify({"error": "server_error"}), 500


@app.route('/api/tutor/mobile/logout', methods=['POST'])
def mobile_logout():
    """Revoke the presented refresh token (idempotent). With {"all_devices":true}
    and a valid Bearer access token, revoke every refresh token for that intern."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        raw  = clean_text(data.get("refresh_token"))
        all_devices = bool(data.get("all_devices"))
        intern_id = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and TUTOR_SSO_SECRET:
            try:
                payload = jwt.decode(auth.split(" ", 1)[1], TUTOR_SSO_SECRET, algorithms=["HS256"])
                intern_id = str(payload.get("intern_id") or "") or None
            except Exception:
                intern_id = None
        with get_db() as conn:
            if all_devices and intern_id:
                conn.execute(
                    "UPDATE mobile_refresh_tokens SET revoked=1, last_used_at=? WHERE intern_id=?",
                    (now_str(), intern_id),
                )
            elif raw:
                conn.execute(
                    "UPDATE mobile_refresh_tokens SET revoked=1, last_used_at=? WHERE token_hash=?",
                    (now_str(), _hash_refresh_token(raw)),
                )
            conn.commit()
        return jsonify({"ok": True})
    except Exception as e:
        log_error("mobile-logout", e)
        return jsonify({"error": "server_error"}), 500


@app.route('/api/tutor/progress-update', methods=['POST'])
def tutor_progress_update():
    """DEPRECATED: External tutor push removed. Progress is calculated locally."""
    return jsonify({'status': 'gone', 'message': 'External progress push is disabled.'}), 410


@app.route('/api/tutor/coin-event', methods=['POST'])
def tutor_coin_event():
    """DEPRECATED: Coins are managed locally."""
    return jsonify({'status': 'gone', 'message': 'External coin events disabled.'}), 410


@app.route('/api/tutor/certificate-event', methods=['POST'])
def tutor_certificate_event():
    """DEPRECATED: Certificates are issued locally via staff decisions."""
    return jsonify({'status': 'gone', 'message': 'External certificate events disabled.'}), 410


@app.route("/portal/ledger")
def portal_ledger():
    """Intern's own combined ad+task coin ledger + certificates (Track 1 Â§6).

    STRICTLY READ-ONLY â€” the tutor owns the economy; this only displays mirrored
    rows. Current balance per kind = the latest event's balance_after."""
    try:
        user = require_role("intern")
        if not user:
            return redirect("/portal")
        with get_db() as conn:
            acct = conn.execute(
                "SELECT id, name FROM intern_accounts WHERE email=?", (user["email"],)
            ).fetchone()
            if not acct:
                return redirect("/portal")
            rows = [row_to_dict(r) for r in conn.execute(
                "SELECT ledger_kind, delta, balance_after, reason, event_ts "
                "FROM coin_ledger_mirror WHERE intern_id=? ORDER BY event_ts, id",
                (acct["id"],),
            ).fetchall()]
            certs = [row_to_dict(r) for r in conn.execute(
                "SELECT course_title, cert_id, issued_at, url FROM intern_certificates "
                "WHERE intern_id=? ORDER BY issued_at DESC, id DESC",
                (acct["id"],),
            ).fetchall()]
            # NF2 fix: computed per ledger from SUM(delta), not from the newest
            # balance_after (a running total across all kinds, so the old
            # per-kind lookup showed â‚¹0 on both cards).
            balances = get_coin_balances(conn, acct["id"])
        rows.reverse()  # newest first for display
        return render_template(
            "portal_ledger.html", name=acct["name"], rows=rows, certs=certs,
            balances=balances,
        )
    except Exception as e:
        log_error("/portal/ledger", e)
        return "Server error", 500


@app.route("/intern/coins")
def intern_coins():
    """JSON for the portal Coins tab â€” the two independent ledger balances
    (spec Â§4) plus full history."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = [row_to_dict(r) for r in conn.execute(
                "SELECT ledger_kind, delta, balance_after, reason, event_ts "
                "FROM coin_ledger_mirror WHERE intern_id=? ORDER BY event_ts, id",
                (intern["id"],),
            ).fetchall()]
            balances = get_coin_balances(conn, intern["id"])
        rows.reverse()  # newest first for display
        return jsonify({"status": "success", "balances": balances, "rows": rows})
    except Exception as e:
        log_error("intern-coins", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/certificates")
def intern_certificates_api():
    """UAT #7: JSON for the portal Certificate tab â€” earned certs (mirror) + a link
    to the tutor's sample-certificate preview (supersedes #3 discoverability)."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            certs = [row_to_dict(r) for r in conn.execute(
                "SELECT course_title, cert_id, issued_at, url FROM intern_certificates "
                "WHERE intern_id=? ORDER BY issued_at DESC, id DESC",
                (intern["id"],),
            ).fetchall()]
        # UAT #20: resolve the download link against the ACTIVE tutor base at request
        # time (the mirror stores a relative path; the test launcher repoints
        # TUTOR_BASE_URL). Tolerate a legacy absolute url too.
        for c in certs:
            u = c.get("url") or ""
            c["download_url"] = u
        return jsonify({"status": "success", "certificates": certs,
                        "sample_url": "/portal/sample-certificate"})
    except Exception as e:
        log_error("intern-certificates", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/portal/sample-certificate")
def portal_sample_certificate():
    """UAT #19: a portal-side sample certificate preview, visible to ANY logged-in
    intern (every lifecycle stage) the moment their account exists â€” no tutor session
    needed. Renders the same printed-paper artifact as the tutor sample, marked
    SAMPLE / preview-only."""
    intern = current_intern()
    if not intern:
        return redirect("/#signin")
    name = intern.get("name") or "Your Name"
    domain = (intern.get("domain") or "your domain")
    return render_template("sample_certificate.html", name=name, domain=domain)


@app.route("/verify/<cert_id>")
def verify_certificate(cert_id):
    """UAT #22: PUBLIC certificate verification (the target of the QR on the official
    certificate). Reads the mirrored intern_certificates. No auth, noindex."""
    cert = None
    with get_db() as conn:
        row = conn.execute(
            "SELECT c.course_title, c.cert_id, c.issued_at, a.name "
            "FROM intern_certificates c JOIN intern_accounts a ON a.id=c.intern_id "
            "WHERE c.cert_id=? LIMIT 1", (cert_id,)).fetchone()
        if row:
            cert = row_to_dict(row)
    return render_template("cert_verify.html", cert=cert, cert_id=cert_id), (200 if cert else 404)


# â”€â”€ UAT #25: paid-course payment (QR + screenshot) â†’ admin verify â†’ tutor unlock â”€â”€
def _catalogue_course(course_id):
    """Find a published course (id/title/is_paid/price_inr) from the tutor catalogue
    proxy (cached). Returns a dict or None."""
    courses, _ = _public_courses()
    for c in courses:
        if c.get("id") == course_id:
            return c
    return None


def _course_payment_status(intern_id, course_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT status FROM course_payments WHERE intern_id=? AND course_id=? "
            "ORDER BY id DESC LIMIT 1", (intern_id, course_id)).fetchone()
    return row["status"] if row else None


@app.route("/courses/<int:course_id>/pay", methods=["GET"])
def course_pay_page(course_id):
    intern = current_intern()
    if not intern:
        return redirect("/#signin")
    course = _catalogue_course(course_id)
    if not course or not course.get("is_paid"):
        return redirect("/portal")
    # T7: industrial-certification is an attribute on the course page -- shown only for
    # approved, company-authored portal courses (co-signed by DBERT + that company).
    cert_company_name = None
    if course.get("source") == "custom" and course.get("company_id") and course.get("industrial_certification"):
        with get_db() as conn:
            row = conn.execute("SELECT name FROM companies WHERE id=?", (course["company_id"],)).fetchone()
        cert_company_name = row["name"] if row else None
    return render_template(
        "course_pay.html", course=course,
        status=_course_payment_status(intern["id"], course_id),
        upi_id=UPI_ID, tutor_base=TUTOR_BASE_URL,
        cert_company_name=cert_company_name)


@app.route("/courses/<int:course_id>/pay", methods=["POST"])
def course_pay_submit(course_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    course = _catalogue_course(course_id)
    if not course or not course.get("is_paid"):
        return jsonify({"status": "error", "message": "Course is not payable."}), 400
    if _course_payment_status(intern["id"], course_id) in ("pending", "verified"):
        return jsonify({"status": "error", "message": "A payment for this course is already on file."}), 409
    file = request.files.get("payment_screenshot")
    if not file or not file.filename or not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Allowed: png, jpg, jpeg, pdf"}), 400
    sniffed = sniff_upload_type(file)
    if sniffed is None:
        log_abuse(get_client_ip(), "/courses/pay", "course:upload", "bad_magic", intern["email"])
        return jsonify({"status": "error", "message": "File must be a real PNG, JPEG, or PDF."}), 400
    filename = f"{uuid.uuid4().hex}.{sniffed}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    with get_db() as conn:
        conn.execute(
            "INSERT INTO course_payments (intern_id, course_id, course_title, amount, payment_screenshot, status) "
            "VALUES (?,?,?,?,?,'pending')",
            (intern["id"], course_id, course.get("title", ""), course.get("price_inr", 0), filename))
        conn.commit()
    return jsonify({"status": "success", "message": "Payment submitted â€” we'll verify it within 24 hours."})


def _signal_tutor_course_unlock(intern_id, course_id):
    """Tell the tutor to grant the intern access to a paid course (UAT #25).
    Server-to-server, secret-gated. Best-effort â€” never raises into the caller."""
    if not TUTOR_SSO_SECRET:
        return False
    try:
        resp = requests.post(
            f"{TUTOR_BASE_URL}/internal/course-access",
            json={"intern_id": str(intern_id), "course_id": course_id},
            headers={"X-Internal-Key": TUTOR_SSO_SECRET}, timeout=5)
        return resp.status_code == 200
    except Exception as e:
        log_error("course-unlock-signal", e)
        return False


def _tutor_has_course_access(intern_id, course_id):
    """UAT #41: ask the tutor whether the intern already has access to a course
    (free, or a verified paid unlock). Returns True/False, or None if the tutor
    is unreachable (caller then defaults to the SSO handoff â€” the tutor's own
    #25 lock screen will gate paid content)."""
    if not TUTOR_SSO_SECRET:
        return None
    try:
        resp = requests.get(
            f"{TUTOR_BASE_URL}/internal/course-access",
            params={"intern_id": str(intern_id), "course_id": course_id},
            headers={"X-Internal-Key": TUTOR_SSO_SECRET}, timeout=5)
        if resp.status_code == 200:
            return bool(resp.json().get("has_access"))
        log_error("course-access-check", Exception(f"tutor http_{resp.status_code}"))
    except Exception as e:
        log_error("course-access-check", e)
    return None


@app.route("/course/<int:course_id>/start")
def course_start(course_id):
    """UAT #41: route an intern to a required tutor course WITHOUT the auth bounce.
    Decision: has access (free / paid-unlocked) â†’ mint an SSO token and hand off
    into the course; no access â†’ the #25 course-payment gate (QR + admin approval
    â†’ unlock â†’ SSO). If the access check is unreachable, default to the SSO
    handoff (the tutor's #25 lock screen then routes paid content to the pay
    page), so the link is never a dead-end."""
    intern = current_intern()
    if not intern:
        # Not signed in â†’ portal sign-in overlay (preserve nothing sensitive).
        return redirect("/#signin")
    access = _tutor_has_course_access(intern["id"], course_id)
    if access is False:
        return redirect(f"/courses/{course_id}/pay")
    # access True (enrolled/free/unlocked) or unknown â†’ SSO handoff into the course.
    if not TUTOR_SSO_SECRET:
        return redirect(f"/courses/{course_id}/pay")
    with get_db() as conn:
        enr = conn.execute(
            "SELECT joining_date FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
            (intern["email"],)).fetchone()
    joining_date_str = (enr["joining_date"] if enr and enr["joining_date"] else "")
    token = mint_tutor_sso_token(intern, joining_date_str)
    return redirect(
        f"{TUTOR_BASE_URL}/sso?token={token}&next={quote(f'/courses/{course_id}', safe='')}")


# â”€â”€ UP1.3: Guided Learning Core Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/courses", methods=["GET"])
def courses_catalog():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    with get_db() as conn:
        q = ("SELECT c.*, "
             "COALESCE(cmp.name, 'DBERT Platform') AS author_name, "
             "(SELECT COUNT(*) FROM course_chapters WHERE course_id = c.id) AS total_days "
             "FROM courses c "
             "LEFT JOIN companies cmp ON c.company_id = cmp.id "
             "WHERE c.is_active = 1 AND (c.content_status = 'approved' OR c.company_id IS NULL) "
             "ORDER BY c.id DESC")
        pagination = paginate(conn, q, page=page, per_page=per_page)
    return render_template("courses_catalog.html", courses=pagination["items"], pagination=pagination)


@app.route("/courses/<int:course_id>", methods=["GET"])
def course_detail(course_id):
    intern = current_intern()
    with get_db() as conn:
        course = conn.execute("""
            SELECT c.*, COALESCE(cmp.name, 'DBERT Platform') AS author_name
            FROM courses c
            LEFT JOIN companies cmp ON c.company_id = cmp.id
            WHERE c.id = ?
        """, (course_id,)).fetchone()
        if not course:
            abort(404)
        
        chapters = conn.execute("""
            SELECT * FROM course_chapters WHERE course_id = ? ORDER BY day_number ASC
        """, (course_id,)).fetchall()
        
        chapters_data = []
        for ch in chapters:
            subtopics = conn.execute("""
                SELECT * FROM course_subtopics WHERE chapter_id = ? ORDER BY sort_order ASC
            """, (ch["id"],)).fetchall()
            ch_dict = dict(ch)
            ch_dict["subtopics"] = [dict(st) for st in subtopics]
            chapters_data.append(ch_dict)
            
        enrollment = None
        if intern:
            enrollment = conn.execute("""
                SELECT * FROM course_enrollments WHERE intern_id = ? AND course_id = ?
            """, (intern["id"], course_id)).fetchone()

    return render_template(
        "course_detail.html", 
        course=dict(course), 
        chapters=chapters_data,
        enrollment=dict(enrollment) if enrollment else None,
        flag_paid_1999_live=(get_config("FLAG_PAID_1999_LIVE", "0") == "1")
    )


@app.route("/courses/<int:course_id>/enroll", methods=["POST"])
def course_enroll(course_id):
    intern = current_intern()
    if not intern:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return redirect("/#signin")
        
    with get_db() as conn:
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            return jsonify({"status": "error", "message": "Course not found"}), 404
            
        if course["is_paid"]:
            return jsonify({"status": "error", "message": "Course requires payment"}), 400
            
        existing = conn.execute(
            "SELECT id FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not existing:
            # UP8.1: Free Course Quota Enforcement
            free_quota = int(get_config("FREE_COURSE_QUOTA", "5"))
            min_price_inr = int(get_config("POST_QUOTA_MIN_PRICE_INR", "99"))

            enrolled_count = conn.execute(
                "SELECT COUNT(*) as count FROM course_enrollments WHERE intern_id = ?",
                (intern["id"],)
            ).fetchone()["count"]

            if enrolled_count >= free_quota:
                return jsonify({
                    "status": "quota_exceeded",
                    "message": f"Free course enrollment quota ({free_quota} courses) reached. Additional course enrollments require minimum â‚¹{min_price_inr} price or paid track.",
                    "min_price_inr": min_price_inr,
                    "free_quota": free_quota
                }), 402
        
        if not existing:
            conn.execute(
                "INSERT INTO course_enrollments (intern_id, course_id, enrolled_at, last_accessed_at, current_day) "
                "VALUES (?, ?, datetime('now','localtime'), datetime('now','localtime'), 1)",
                (intern["id"], course_id)
            )
            conn.commit()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"status": "success", "message": "Enrolled successfully", "redirect": f"/courses/{course_id}/learn"})
    return redirect(f"/courses/{course_id}/learn")


@app.route("/courses/<int:course_id>/subtopic/<int:subtopic_id>", methods=["GET"])
def course_subtopic_detail(course_id, subtopic_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
        
    with get_db() as conn:
        enrollment = conn.execute(
            "SELECT id FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not enrollment:
            return jsonify({"status": "error", "message": "Not enrolled in this course"}), 403
            
        subtopic = conn.execute(
            "SELECT s.*, c.day_number FROM course_subtopics s JOIN course_chapters c ON c.id = s.chapter_id WHERE s.id = ?", (subtopic_id,)
        ).fetchone()
        
        if not subtopic:
            return jsonify({"status": "error", "message": "Subtopic not found"}), 404
            
        chats = conn.execute(
            "SELECT role, message, created_at FROM course_subtopic_chats "
            "WHERE enrollment_id = ? AND subtopic_id = ? ORDER BY id ASC",
            (enrollment["id"], subtopic_id)
        ).fetchall()

        user_key_row = conn.execute(
            "SELECT validated_at, available_models_json FROM user_api_keys WHERE intern_id = ?",
            (intern["id"],)
        ).fetchone()

    subtopic_dict = dict(subtopic)
    if subtopic_dict.get("key_takeaways_json"):
        try:
            subtopic_dict["key_takeaways"] = json.loads(subtopic_dict["key_takeaways_json"])
        except Exception:
            subtopic_dict["key_takeaways"] = []
    else:
        subtopic_dict["key_takeaways"] = []

    return jsonify({
        "status": "success",
        "subtopic": subtopic_dict,
        "chats": [dict(c) for c in chats],
        "has_gemini_key": bool(user_key_row),
        "available_models_count": len(json.loads(user_key_row["available_models_json"])) if (user_key_row and user_key_row["available_models_json"]) else 0
    })


@app.route("/courses/<int:course_id>/subtopic/<int:subtopic_id>/chat", methods=["POST"])
def course_subtopic_chat(course_id, subtopic_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
        
    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"status": "error", "message": "Message body is required"}), 400
        
    with get_db() as conn:
        enrollment = conn.execute(
            "SELECT id FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not enrollment:
            return jsonify({"status": "error", "message": "Not enrolled in this course"}), 403
            
        subtopic = conn.execute(
            "SELECT * FROM course_subtopics WHERE id = ?", (subtopic_id,)
        ).fetchone()
        
        if not subtopic:
            return jsonify({"status": "error", "message": "Subtopic not found"}), 404
            
        conn.execute(
            "INSERT INTO course_subtopic_chats (enrollment_id, subtopic_id, role, message) "
            "VALUES (?, ?, 'user', ?)",
            (enrollment["id"], subtopic_id, user_message)
        )
        conn.commit()

        past_chats = conn.execute(
            "SELECT role, message FROM course_subtopic_chats "
            "WHERE enrollment_id = ? AND subtopic_id = ? ORDER BY id DESC LIMIT 6",
            (enrollment["id"], subtopic_id)
        ).fetchall()
        
        history_formatted = "\n".join([f"{c['role'].capitalize()}: {c['message']}" for c in reversed(past_chats)])
        
        prompt = (
            f"You are a friendly, expert AI tutor explaining '{subtopic['title']}'.\n"
            f"Topic Context: {subtopic['brief']}\n"
            f"Prompt Seed / Guidelines: {subtopic['prompt_seed'] or 'Explain clearly with practical Python examples.'}\n\n"
            f"Recent Conversation:\n{history_formatted}\n\n"
            f"Provide a helpful, direct, clear response to the student's question."
        )

        # Check BYOK key first (UP2.5)
        user_key_row = conn.execute(
            "SELECT encrypted_key FROM user_api_keys WHERE intern_id = ?",
            (intern["id"],)
        ).fetchone()

        ai_response = None
        used_byok = False

        if user_key_row and user_key_row["encrypted_key"]:
            raw_user_key = _decrypt_gemini_key(user_key_row["encrypted_key"])
            if raw_user_key:
                ai_response = _gemini_call(prompt, temperature=0.7, max_tokens=1024, api_key=raw_user_key)
                if ai_response:
                    used_byok = True

        if not used_byok:
            if not can_use_fallback(intern["id"]):
                return jsonify({
                    "status": "quota_exceeded",
                    "message": "Daily free AI session fallback limit reached. Please connect your free Gemini API key to continue learning.",
                    "redirect": "/account/gemini-key",
                    "requires_key": True
                }), 429
            
            ai_response = _gemini_call(prompt, temperature=0.7, max_tokens=1024)
            increment_daily_fallback_usage(intern["id"])

        if not ai_response:
            ai_response = (
                f"Great question! Regarding '{subtopic['title']}': {subtopic['brief']}. "
                "Let's practice writing code for this step by step."
            )
            
        conn.execute(
            "INSERT INTO course_subtopic_chats (enrollment_id, subtopic_id, role, message) "
            "VALUES (?, ?, 'assistant', ?)",
            (enrollment["id"], subtopic_id, ai_response)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": ai_response,
        "used_byok": used_byok
    })


@app.route("/courses/<int:course_id>/learn", methods=["GET"])
def course_learn_page(course_id):
    intern = current_intern()
    if not intern:
        return redirect("/#signin")
        
    with get_db() as conn:
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            abort(404)
            
        enrollment = conn.execute(
            "SELECT * FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not enrollment:
            return redirect(f"/courses/{course_id}")
            
        conn.execute(
            "UPDATE course_enrollments SET last_accessed_at = datetime('now','localtime') WHERE id = ?",
            (enrollment["id"],)
        )
        conn.commit()

        user_key_row = conn.execute(
            "SELECT validated_at, available_models_json FROM user_api_keys WHERE intern_id = ?",
            (intern["id"],)
        ).fetchone()
        has_gemini_key = bool(user_key_row)
        available_models = json.loads(user_key_row["available_models_json"]) if (user_key_row and user_key_row["available_models_json"]) else []

        fallback_used = get_daily_fallback_usage(intern["id"])
        fallback_limit = int(get_config("GEMINI_FALLBACK_DAILY_LIMIT", "5"))
        
        chapters = conn.execute(
            "SELECT * FROM course_chapters WHERE course_id = ? ORDER BY day_number ASC",
            (course_id,)
        ).fetchall()
        
        chapters_data = []
        for ch in chapters:
            subtopics = conn.execute(
                "SELECT * FROM course_subtopics WHERE chapter_id = ? ORDER BY sort_order ASC",
                (ch["id"],)
            ).fetchall()
            ch_dict = dict(ch)
            ch_dict["subtopics"] = [dict(st) for st in subtopics]
            chapters_data.append(ch_dict)

    return render_template(
        "course_learn.html",
        course=dict(course),
        enrollment=dict(enrollment),
        chapters=chapters_data,
        has_gemini_key=has_gemini_key,
        available_models=available_models,
        fallback_used=fallback_used,
        fallback_limit=fallback_limit
    )


@app.route("/courses/<int:course_id>/quiz/<int:day_number>", methods=["GET"])
def course_quiz_page(course_id, day_number):
    intern = current_intern()
    if not intern:
        return redirect("/#signin")
        
    with get_db() as conn:
        enrollment = conn.execute(
            "SELECT * FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not enrollment:
            return redirect(f"/courses/{course_id}")
            
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            abort(404)
            
        chapter = conn.execute(
            "SELECT * FROM course_chapters WHERE course_id = ? AND day_number = ?",
            (course_id, day_number)
        ).fetchone()
        
        if not chapter:
            return jsonify({"status": "error", "message": "Chapter not found"}), 404
            
        quiz = conn.execute(
            "SELECT * FROM course_day_quizzes WHERE course_id = ? AND day_number = ?",
            (course_id, day_number)
        ).fetchone()
        
        if not quiz:
            subtopics = conn.execute(
                "SELECT title, brief FROM course_subtopics WHERE chapter_id = ?",
                (chapter["id"],)
            ).fetchall()
            
            topics_summary = "; ".join([f"{st['title']}: {st['brief']}" for st in subtopics])
            
            prompt = (
                f"Generate a 5-question multiple choice quiz for Day {day_number} of '{course['title']}'.\n"
                f"Topics Covered: {topics_summary}\n\n"
                "Return ONLY a valid JSON array of 5 objects, with NO markdown surrounding it. "
                "Each object MUST have this schema:\n"
                "{\n"
                '  "id": 1,\n'
                '  "question": "What is ...?",\n'
                '  "options": ["Option A", "Option B", "Option C", "Option D"],\n'
                '  "correct_index": 0\n'
                "}"
            )
            
            raw_res = _gemini_call(prompt, temperature=0.3, max_tokens=1500)
            questions_json = None
            if raw_res:
                try:
                    cleaned = raw_res.strip()
                    if cleaned.startswith("```"):
                        cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                    json.loads(cleaned)
                    questions_json = cleaned
                except Exception:
                    questions_json = None

            if not questions_json:
                fallback = [
                    {
                        "id": 1,
                        "question": f"What is the main topic covered in Day {day_number}?",
                        "options": [chapter["title"], "General Overview", "Advanced Topics", "None of these"],
                        "correct_index": 0
                    },
                    {
                        "id": 2,
                        "question": "What is the primary benefit of Python automation?",
                        "options": ["Saves time & reduces human error", "Slows down code execution", "Requires extra hardware", "Increases manual data entry"],
                        "correct_index": 0
                    }
                ]
                questions_json = json.dumps(fallback)
                
            conn.execute(
                "INSERT INTO course_day_quizzes (course_id, day_number, questions_json) VALUES (?, ?, ?)",
                (course_id, day_number, questions_json)
            )
            conn.commit()
            
            quiz = conn.execute(
                "SELECT * FROM course_day_quizzes WHERE course_id = ? AND day_number = ?",
                (course_id, day_number)
            ).fetchone()

    quiz_dict = dict(quiz)
    questions = json.loads(quiz_dict["questions_json"])
    client_questions = []
    for q in questions:
        client_questions.append({
            "id": q["id"],
            "question": q["question"],
            "options": q["options"]
        })

    return render_template(
        "course_quiz.html",
        course=dict(course),
        chapter=dict(chapter),
        day_number=day_number,
        quiz_id=quiz_dict["id"],
        questions=client_questions
    )


@app.route("/courses/<int:course_id>/quiz/<int:day_number>/submit", methods=["POST"])
def course_quiz_submit(course_id, day_number):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
        
    data = request.get_json(silent=True) or {}
    answers = data.get("answers") or {}
    tab_switches = int(data.get("tab_switches") or 0)
    time_taken_sec = int(data.get("time_taken_sec") or 0)
    
    with get_db() as conn:
        enrollment = conn.execute(
            "SELECT * FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()
        
        if not enrollment:
            return jsonify({"status": "error", "message": "Not enrolled"}), 403
            
        quiz = conn.execute(
            "SELECT * FROM course_day_quizzes WHERE course_id = ? AND day_number = ?",
            (course_id, day_number)
        ).fetchone()
        
        if not quiz:
            return jsonify({"status": "error", "message": "Quiz not found"}), 404
            
        questions = json.loads(quiz["questions_json"])
        max_score = len(questions)
        score = 0
        
        for idx, q in enumerate(questions):
            q_id = str(q.get("id", idx + 1))
            submitted_idx = answers.get(q_id)
            if submitted_idx is not None and int(submitted_idx) == q.get("correct_index"):
                score += 1

        pass_threshold = max(1, int(max_score * 0.7))
        passed = 1 if score >= pass_threshold else 0
        
        conn.execute(
            "INSERT INTO day_quiz_attempts "
            "(enrollment_id, day_quiz_id, score, max_score, passed, tab_switches, time_taken_sec) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (enrollment["id"], quiz["id"], score, max_score, passed, tab_switches, time_taken_sec)
        )
        
        if passed and enrollment["current_day"] <= day_number:
            conn.execute(
                "UPDATE course_enrollments SET current_day = ? WHERE id = ?",
                (day_number + 1, enrollment["id"])
            )
        conn.commit()

    return jsonify({
        "status": "success",
        "score": score,
        "max_score": max_score,
        "passed": bool(passed),
        "next_day": day_number + 1 if passed else day_number
    })


# â”€â”€ UP2.3: BYOK Gemini Key Save & Validation Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/account/gemini-key", methods=["GET", "POST"])
def account_gemini_key():
    intern = current_intern()
    if not intern:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return redirect("/#signin")

    if request.method == "GET":
        with get_db() as conn:
            key_row = conn.execute(
                "SELECT validated_at, available_models_json, created_at FROM user_api_keys WHERE intern_id = ?",
                (intern["id"],)
            ).fetchone()
            
        fallback_used = get_daily_fallback_usage(intern["id"])
        fallback_limit = int(get_config("GEMINI_FALLBACK_DAILY_LIMIT", "5"))
        
        return render_template(
            "account_gemini_key.html",
            has_key=bool(key_row),
            key_info=dict(key_row) if key_row else None,
            fallback_used=fallback_used,
            fallback_limit=fallback_limit
        )

    # POST - Save / Validate Key
    data = request.get_json(silent=True) or {}
    raw_key = (data.get("api_key") or request.form.get("api_key") or "").strip()
    
    if not raw_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400

    key_hash = _hash_gemini_key(raw_key)

    with get_db() as conn:
        existing = conn.execute(
            "SELECT intern_id FROM user_api_keys WHERE key_hash = ? AND intern_id != ?",
            (key_hash, intern["id"])
        ).fetchone()

        if existing:
            return jsonify({"status": "error", "message": "This Gemini API key is already registered by another user."}), 409

    is_valid, models = _validate_gemini_key_live(raw_key)
    if not is_valid:
        return jsonify({"status": "error", "message": "Invalid Gemini API key or Google API verification failed."}), 400

    enc_key = _encrypt_gemini_key(raw_key)
    models_json = json.dumps(models or [])
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        conn.execute(
            "INSERT INTO user_api_keys (intern_id, encrypted_key, key_hash, validated_at, available_models_json) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(key_hash) DO UPDATE SET encrypted_key = excluded.encrypted_key, "
            "validated_at = excluded.validated_at, available_models_json = excluded.available_models_json",
            (intern["id"], enc_key, key_hash, now_str, models_json)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "Gemini API key validated and saved securely!",
        "models_count": len(models or [])
    })


# â”€â”€ UP3.3: Staff Auth & Dashboard Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "GET":
        if current_staff():
            return redirect("/staff/dashboard")
        return render_template("admin_login.html")

    json_data = request.get_json(force=True, silent=True) or {}
    email = (request.form.get("email") or json_data.get("email") or "").strip().lower()
    password = (request.form.get("password") or json_data.get("password") or "").strip()

    if not email or not password:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "error", "message": "Email and password are required"}), 400
        return render_template("admin_login.html", error="Email and password are required")

    with get_db() as conn:
        staff = conn.execute("SELECT * FROM staff_accounts WHERE email = ? AND is_active = 1", (email,)).fetchone()

    if staff and verify_password(staff["password_hash"], password):
        session["staff_id"] = staff["id"]
        session["staff_email"] = staff["email"]
        session["staff_name"] = staff["name"]
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"status": "success", "redirect": "/staff/dashboard"})
        return redirect("/staff/dashboard")

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"status": "error", "message": "Invalid staff credentials"}), 401
    return render_template("admin_login.html", error="Invalid staff credentials")


@app.route("/staff/logout")
def staff_logout():
    session.pop("staff_id", None)
    session.pop("staff_email", None)
    session.pop("staff_name", None)
    return redirect("/staff/login")


@app.route("/staff/dashboard", methods=["GET"])
def staff_dashboard():
    staff = current_staff()
    if not staff:
        return redirect("/staff/login")

    with get_db() as conn:
        roles = conn.execute(
            "SELECT queue_name FROM staff_queue_roles WHERE staff_id = ?",
            (staff["id"],)
        ).fetchall()
        
        queue_names = [r["queue_name"] for r in roles]
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        
        queues_summary = []
        
        if "courses" in queue_names:
            c_row = conn.execute(
                "SELECT COUNT(*) as count, MIN(created_at) as oldest FROM courses WHERE content_status = 'pending'"
            ).fetchone()
            queues_summary.append({"name": "courses", "title": "Course Submissions", "count": c_row["count"], "oldest": c_row["oldest"], "url": "/staff/projects"})
            
        if "payments" in queue_names:
            p_row = conn.execute(
                "SELECT COUNT(*) as count, MIN(created_at) as oldest FROM course_payments WHERE status = 'pending'"
            ).fetchone()
            queues_summary.append({"name": "payments", "title": "Course Payments", "count": p_row["count"], "oldest": p_row["oldest"], "url": "/admin/course-payments"})
            
        if "projects" in queue_names:
            pr_row = conn.execute(
                "SELECT COUNT(*) as count, MIN(created_at) as oldest FROM project_submissions WHERE status = 'pending'"
            ).fetchone() if "project_submissions" in tables else {"count": 0, "oldest": None}
            queues_summary.append({"name": "projects", "title": "Capstone Projects", "count": pr_row["count"], "oldest": pr_row["oldest"], "url": "/staff/projects"})

        if "tasks" in queue_names:
            t_row = conn.execute(
                "SELECT COUNT(*) as count, MIN(created_at) as oldest FROM task_submissions WHERE status = 'pending'"
            ).fetchone() if "task_submissions" in tables else {"count": 0, "oldest": None}
            queues_summary.append({"name": "tasks", "title": "Task Submissions", "count": t_row["count"], "oldest": t_row["oldest"], "url": "/staff/tasks"})

    return render_template(
        "staff_dashboard.html",
        staff=staff,
        assigned_queues=queues_summary
    )


@app.route("/staff/courses")
def staff_courses_redirect():
    if not current_staff() and not require_admin():
        return redirect("/staff/login")
    return redirect("/staff/projects")


@app.route("/staff/payments")
def staff_payments_redirect():
    if not current_staff() and not require_admin():
        return redirect("/staff/login")
    return redirect("/admin/course-payments")


# â”€â”€ UP4.3: Capstone Project Submission Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/courses/<int:course_id>/submit-project", methods=["GET", "POST"])
def course_submit_project(course_id):
    intern = current_intern()
    if not intern:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return redirect("/#signin")

    with get_db() as conn:
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            abort(404)
            
        if not course["requires_project"]:
            return jsonify({"status": "error", "message": "This course does not require a capstone project."}), 400

        enrollment = conn.execute(
            "SELECT * FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()

        if not enrollment:
            return jsonify({"status": "error", "message": "You must be enrolled in this course."}), 403

        total_quizzes = conn.execute(
            "SELECT COUNT(*) as count FROM course_day_quizzes WHERE course_id = ?",
            (course_id,)
        ).fetchone()["count"]

        passed_quizzes = conn.execute(
            "SELECT COUNT(DISTINCT day_quiz_id) as count FROM day_quiz_attempts "
            "WHERE enrollment_id = ? AND passed = 1",
            (enrollment["id"],)
        ).fetchone()["count"]

        if total_quizzes > 0 and passed_quizzes < total_quizzes:
            return jsonify({
                "status": "error", 
                "message": f"You must complete and pass all {total_quizzes} day quizzes before submitting the capstone project. ({passed_quizzes}/{total_quizzes} completed)"
            }), 400

        project = conn.execute("SELECT * FROM course_projects WHERE course_id = ?", (course_id,)).fetchone()

    if request.method == "GET":
        with get_db() as conn:
            existing_sub = conn.execute(
                "SELECT * FROM project_submissions WHERE enrollment_id = ? ORDER BY id DESC LIMIT 1",
                (enrollment["id"],)
            ).fetchone()
        return render_template(
            "course_submit_project.html",
            course=dict(course),
            project=dict(project) if project else None,
            submission=dict(existing_sub) if existing_sub else None
        )

    data = request.get_json(silent=True) or {}
    github_url = (data.get("github_repo_url") or request.form.get("github_repo_url") or "").strip()
    title = (data.get("project_title") or request.form.get("project_title") or "").strip()
    desc = (data.get("project_description") or request.form.get("project_description") or "").strip()

    if not github_url or "github.com" not in github_url.lower():
        return jsonify({"status": "error", "message": "A valid GitHub repository URL is required."}), 400

    if not title or not desc:
        return jsonify({"status": "error", "message": "Project title and description are required."}), 400

    with get_db() as conn:
        conn.execute(
            "INSERT INTO project_submissions (enrollment_id, intern_id, course_id, github_repo_url, project_title, project_description, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'pending')",
            (enrollment["id"], intern["id"], course_id, github_url, title, desc)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "Capstone project submitted successfully! DBERT reviewers will evaluate your submission."
    })


# â”€â”€ UP6.2: Auto-Promote Pending Applications Helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_and_promote_pending_applications(intern_id, course_id):
    try:
        with get_db() as conn:
            course = conn.execute("SELECT company_id FROM courses WHERE id = ?", (course_id,)).fetchone()
            if not course or not course["company_id"]:
                return

            company_id = course["company_id"]

            pending_apps = conn.execute(
                "SELECT pa.id FROM post_applications pa "
                "JOIN posts p ON pa.post_id = p.id "
                "WHERE pa.intern_id = ? AND pa.status = 'PENDING_CERTS' AND p.company_id = ?",
                (intern_id, company_id)
            ).fetchall()

            for app_row in pending_apps:
                conn.execute(
                    "UPDATE post_applications SET status = 'Applied' WHERE id = ?",
                    (app_row["id"],)
                )
            conn.commit()
    except Exception as e:
        log_error("promote_pending_apps", e)


# â”€â”€ UP4.5: Staff Project Evaluation Decision Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/staff/projects", methods=["GET"])
def staff_project_queue():
    staff = current_staff()
    if not staff:
        return redirect("/staff/login")

    with get_db() as conn:
        status_filter = request.args.get("status", "pending")
        submissions = conn.execute(
            "SELECT ps.*, c.title AS course_title, a.name AS intern_name, a.email AS intern_email "
            "FROM project_submissions ps "
            "JOIN courses c ON ps.course_id = c.id "
            "JOIN intern_accounts a ON ps.intern_id = a.id "
            "WHERE ps.status = ? "
            "ORDER BY ps.created_at ASC",
            (status_filter,)
        ).fetchall()

    return render_template(
        "staff_project_queue.html",
        staff=staff,
        submissions=[dict(s) for s in submissions],
        current_status=status_filter
    )


@app.route("/staff/projects/<int:submission_id>/decision", methods=["POST"])
def staff_project_decision(submission_id):
    staff = current_staff()
    if not staff:
        return jsonify({"status": "error", "message": "Staff authentication required"}), 401

    data = request.get_json(silent=True) or {}
    decision = (data.get("decision") or request.form.get("decision") or "").strip().lower()
    reason_code = (data.get("reason_code") or request.form.get("reason_code") or "").strip()

    if decision not in ("approved", "rejected", "changes_requested"):
        return jsonify({"status": "error", "message": "Invalid decision"}), 400

    with get_db() as conn:
        sub = conn.execute(
            "SELECT ps.*, c.title AS course_title, a.name AS intern_name, a.email AS intern_email "
            "FROM project_submissions ps "
            "JOIN courses c ON ps.course_id = c.id "
            "JOIN intern_accounts a ON ps.intern_id = a.id "
            "WHERE ps.id = ?",
            (submission_id,)
        ).fetchone()

        if not sub:
            return jsonify({"status": "error", "message": "Submission not found"}), 404

        conn.execute(
            "UPDATE project_submissions SET status = ?, reviewed_by_staff_id = ? WHERE id = ?",
            (decision, staff["id"], submission_id)
        )

        log_staff_review(
            queue_name="projects",
            staff_id=staff["id"],
            subject_type="project",
            subject_id=submission_id,
            decision=decision,
            reason_code=reason_code or decision.upper(),
            reviewed_input_snapshot=dict(sub)
        )

        if decision == "approved":
            cert_uuid = f"DBERT-VERIFIED-{uuid.uuid4().hex[:8].upper()}"
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cert_url = f"/portal/certificate/{cert_uuid}"

            conn.execute(
                "INSERT INTO intern_certificates (intern_id, course_id, course_title, cert_id, issued_at, url, tier) "
                "VALUES (?, ?, ?, ?, ?, ?, 'dbert_verified') "
                "ON CONFLICT(intern_id, cert_id) DO NOTHING",
                (sub["intern_id"], sub["course_id"], sub["course_title"], cert_uuid, now_str, cert_url)
            )
            check_and_promote_pending_applications(sub["intern_id"], sub["course_id"])

            cv_row = conn.execute("SELECT id, projects_json FROM cvs WHERE intern_id = ?", (sub["intern_id"],)).fetchone()
            if cv_row:
                try:
                    projects_list = json.loads(cv_row["projects_json"]) if cv_row["projects_json"] else []
                except Exception:
                    projects_list = []

                new_proj = {
                    "project_title": sub["project_title"],
                    "github_repo_url": sub["github_repo_url"],
                    "project_description": sub["project_description"],
                    "verified_by_dbert": True,
                    "approved_at": now_str
                }
                if not any(p.get("github_repo_url") == sub["github_repo_url"] for p in projects_list if isinstance(p, dict)):
                    projects_list.append(new_proj)
                    conn.execute(
                        "UPDATE cvs SET projects_json = ? WHERE id = ?",
                        (json.dumps(projects_list), cv_row["id"])
                    )

        conn.commit()

    return jsonify({
        "status": "success",
        "message": f"Project submission {submission_id} marked as {decision}."
    })


# â”€â”€ UP5.4: Coin Credit Helper & Staff Task Decision Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â”€â”€ Phase 4: two-ledger coin model (spec Â§4) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Task Coins and Referral Coins are independent and NEVER summed together.
# Task coins are spendable in-portal; referral coins are withdrawable only.
# Mixing them is the bug class this model exists to prevent, so every balance
# read goes through get_coin_balances().

TASK_KINDS     = ("task", "spent")        # spent is negative
REFERRAL_KINDS = ("referral", "withdrawal")   # withdrawal is negative


def get_coin_balances(conn, intern_id):
    """Per-ledger balances. Never returns a single mixed total.

    Computed from SUM(delta) rather than the newest balance_after: that column
    is a running total across ALL kinds, so reading 'the latest balance_after
    for this ledger_kind' produced wrong numbers per ledger (bug NF2).
    """
    rows = conn.execute(
        "SELECT ledger_kind, COALESCE(SUM(delta),0) AS bal "
        "FROM coin_ledger_mirror WHERE intern_id=? GROUP BY ledger_kind",
        (intern_id,)
    ).fetchall()
    m = {r["ledger_kind"]: r["bal"] for r in rows}
    return {
        "task":     m.get("task", 0)     + m.get("spent", 0),
        "referral": m.get("referral", 0) + m.get("withdrawal", 0),
    }


def get_task_balance(conn, intern_id):
    """Spendable balance only. Use this anywhere coins buy something."""
    return get_coin_balances(conn, intern_id)["task"]


def credit_intern_coins(conn, intern_id, delta, reason, ref_id=None):
    """Credit TASK coins (approved micro-tasks, quiz passes, streaks)."""
    new_bal = get_task_balance(conn, intern_id) + delta
    idem_key = f"task_reward_{ref_id}_{uuid.uuid4().hex[:6]}" if ref_id else f"coin_credit_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute(
        "INSERT INTO coin_ledger_mirror "
        "(intern_id, ledger_kind, delta, balance_after, reason, event_ts, idem_key) "
        "VALUES (?, 'task', ?, ?, ?, ?, ?)",
        (intern_id, delta, new_bal, reason, now_str, idem_key)
    )
    return new_bal


def credit_referral_coins(conn, intern_id, delta, reason, ref_payment_id):
    """Credit REFERRAL coins â€” 10% commission on a referred user's verified
    payment (spec Â§6.3). Withdrawable only; never spendable in-portal.

    Idempotent on ref_payment_id: the UNIQUE idem_key means a payment can only
    ever commission once, however many times the verification hook fires.
    Returns the new referral balance, or None if this payment already paid out.
    """
    if not ref_payment_id:
        raise ValueError("credit_referral_coins requires ref_payment_id for idempotency")
    idem_key = f"referral_commission_{ref_payment_id}"

    already = conn.execute(
        "SELECT 1 FROM coin_ledger_mirror WHERE idem_key=?", (idem_key,)
    ).fetchone()
    if already:
        return None

    new_bal = get_coin_balances(conn, intern_id)["referral"] + delta
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute(
            "INSERT INTO coin_ledger_mirror "
            "(intern_id, ledger_kind, delta, balance_after, reason, event_ts, idem_key) "
            "VALUES (?, 'referral', ?, ?, ?, ?, ?)",
            (intern_id, delta, new_bal, reason, now_str, idem_key)
        )
    except sqlite3.IntegrityError:
        # lost a race on the UNIQUE idem_key â€” the other writer credited it
        return None
    return new_bal


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 7 â€” College Ambassador programme (spec Â§6)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

REFERRAL_COMMISSION_RATE = 0.10      # 10% of a referred user's verified payment
REFERRAL_COOKIE          = "dbert_ref"
REFERRAL_WINDOW_DAYS     = 30        # Â§6.1 attribution window


def ga4_server_event(name, params=None, client_id=None):
    """Server-side GA4 event via the Measurement Protocol (spec Â§8).

    `referral_signup` and `referral_conversion` happen in request handlers where
    there is no gtag, so they cannot be fired from the browser. No-ops silently
    unless GA4_API_SECRET is configured, and never raises into the caller â€” an
    analytics failure must not affect a signup or a payment.
    """
    if not (GA4_ID and GA4_API_SECRET):
        return
    try:
        requests.post(
            "https://www.google-analytics.com/mp/collect",
            params={"measurement_id": GA4_ID, "api_secret": GA4_API_SECRET},
            json={"client_id": client_id or f"server.{secrets.token_hex(8)}",
                  "events": [{"name": name, "params": params or {}}]},
            timeout=3,
        )
    except Exception as e:
        log_error("ga4-server-event", e)


def _fernet():
    """Cipher for financial PII. Returns None when unconfigured, and callers
    must treat that as 'cannot store a UPI id' â€” never as 'store it in clear'."""
    if not FERNET_KEY:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
    except Exception as e:
        log_error("fernet-init", e)
        return None


def encrypt_upi(upi_plain):
    f = _fernet()
    if not f or not upi_plain:
        return None
    return f.encrypt(upi_plain.strip().encode()).decode()


def decrypt_upi(upi_cipher):
    """Server-side only, and only at admin payout review (Â§5.4)."""
    f = _fernet()
    if not f or not upi_cipher:
        return None
    try:
        return f.decrypt(upi_cipher.encode()).decode()
    except Exception as e:
        log_error("fernet-decrypt", e)
        return None


def mask_upi(upi_plain):
    """priâ€¢â€¢â€¢â€¢â€¢@okhdfc â€” the ONLY form that may reach a browser outside the
    admin payout screen."""
    if not upi_plain or "@" in upi_plain[:1]:
        return ""
    if "@" not in upi_plain:
        return (upi_plain[:2] + "â€¢â€¢â€¢") if len(upi_plain) > 2 else "â€¢â€¢â€¢"
    user, _, bank = upi_plain.partition("@")
    head = user[:3] if len(user) > 3 else user[:1]
    return f"{head}{'â€¢' * max(3, len(user) - len(head))}@{bank}"


def is_valid_upi(upi):
    """name@bank â€” deliberately strict (Â§6.5)."""
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,48}@[A-Za-z][A-Za-z0-9.]{1,24}", (upi or "").strip()))


def ensure_referral_code(conn, intern_id, name):
    """Mint a stable `firstname-XXXX` code, collision-checked (Â§6.1).
    Idempotent: an intern who already has one keeps it."""
    row = conn.execute("SELECT referral_code FROM intern_accounts WHERE id=?", (intern_id,)).fetchone()
    if row and row["referral_code"]:
        return row["referral_code"]
    first = re.sub(r"[^a-z]", "", (name or "intern").strip().lower().split(" ")[0]) or "intern"
    first = first[:12]
    for _ in range(12):
        code = f"{first}-{secrets.token_hex(2)}"
        if not conn.execute("SELECT 1 FROM intern_accounts WHERE referral_code=?", (code,)).fetchone():
            conn.execute("UPDATE intern_accounts SET referral_code=? WHERE id=?", (code, intern_id))
            return code
    # 12 collisions on a 65k space means something is very wrong; fail loudly
    # rather than silently handing two people the same code.
    raise RuntimeError("could not allocate a unique referral code")


def referral_link(code):
    return f"{SITE_ORIGIN}/?ref={code}" if code else ""


def record_referral_click(conn, code):
    """A landing with ?ref=<code>. Cheap, anonymous, best-effort."""
    ref = conn.execute("SELECT id FROM intern_accounts WHERE referral_code=?", (code,)).fetchone()
    if not ref:
        return None
    conn.execute(
        "INSERT INTO referrals (referrer_intern_id, source_code, status) VALUES (?,?,'clicked')",
        (ref["id"], code))
    return ref["id"]


def attach_referral_on_signup(conn, new_intern_id, new_email, code, visitor_id=None):
    """Stamp referred_by_intern_id on a fresh account (Â§6.1) with the Â§6.4 guards.

    Returns (status, detail):
      'ok'          attributed
      'self'        self-referral, refused
      'unknown'     no such code
      'duplicate'   this account was already attributed
    """
    if not code:
        return ("unknown", "no code")
    ref = conn.execute(
        "SELECT id, email, phone FROM intern_accounts WHERE referral_code=?", (code,)).fetchone()
    if not ref:
        return ("unknown", code)

    new = conn.execute(
        "SELECT email, phone FROM intern_accounts WHERE id=?", (new_intern_id,)).fetchone()

    # Â§6.4 â€” block self-referral outright.
    if ref["id"] == new_intern_id:
        return ("self", "same account")
    if new and ((new["email"] or "").lower() == (ref["email"] or "").lower()
                or (new["phone"] and new["phone"] == ref["phone"])):
        return ("self", "same email/phone")

    if conn.execute("SELECT 1 FROM referrals WHERE referred_intern_id=?", (new_intern_id,)).fetchone():
        return ("duplicate", "already attributed")

    # Â§6.4 â€” device overlap is FLAGGED for human review, never auto-blocked:
    # families and shared campus machines are legitimate.
    flagged, reason = 0, None
    if visitor_id:
        try:
            shared = conn.execute(
                "SELECT 1 FROM device_profiles WHERE visitor_id=? AND intern_id=? LIMIT 1",
                (visitor_id, ref["id"])).fetchone()
            if shared:
                flagged, reason = 1, "shared device fingerprint with referrer"
        except Exception:
            pass   # device_profiles shape varies; never block signup on this

    conn.execute("UPDATE intern_accounts SET referred_by_intern_id=? WHERE id=?",
                 (ref["id"], new_intern_id))
    conn.execute(
        "INSERT INTO referrals (referrer_intern_id, referred_email, referred_intern_id, "
        "source_code, status, flagged, flag_reason, updated_at) "
        "VALUES (?,?,?,?, 'signed_up', ?, ?, ?)",
        (ref["id"], new_email, new_intern_id, code, flagged, reason, now_str()))
    return ("ok", "attributed")


def credit_referral_commission(conn, payer_intern_id, amount_inr, source, ref_payment_id):
    """Â§6.3 â€” on a VERIFIED payment, pay the referrer 10% of the gross.

    Called from the existing verification hooks, not a parallel system.
    Idempotent on ref_payment_id (enforced by credit_referral_coins' UNIQUE
    idem_key), so a replayed webhook cannot pay twice.
    Returns the commission credited, or 0 if there was nothing to pay.
    """
    if not payer_intern_id or not amount_inr or amount_inr <= 0:
        return 0
    payer = conn.execute(
        "SELECT referred_by_intern_id FROM intern_accounts WHERE id=?", (payer_intern_id,)).fetchone()
    if not payer or not payer["referred_by_intern_id"]:
        return 0
    referrer_id = payer["referred_by_intern_id"]
    commission = int(round(float(amount_inr) * REFERRAL_COMMISSION_RATE))
    if commission <= 0:
        return 0

    new_bal = credit_referral_coins(
        conn, referrer_id, commission,
        f"Referral commission â€” {source}", ref_payment_id=ref_payment_id)
    if new_bal is None:
        return 0      # already commissioned for this payment

    conn.execute(
        "UPDATE referrals SET status='converted', updated_at=? "
        "WHERE referred_intern_id=? AND status!='converted'",
        (now_str(), payer_intern_id))
    # Â§8 â€” emitted here so every commission path reports it exactly once.
    ga4_server_event("referral_conversion",
                     {"commission": commission, "amount": int(amount_inr), "source": source})
    return commission


def debit_referral_coins(conn, intern_id, amount, reason, withdrawal_id):
    """Debit REFERRAL coins on an admin-approved payout (spec Â§6.5).
    Guarded: can never overdraw, and can never touch the task balance.
    """
    bal = get_coin_balances(conn, intern_id)["referral"]
    if amount <= 0 or amount > bal:
        return None
    idem_key = f"referral_withdrawal_{withdrawal_id}"
    if conn.execute("SELECT 1 FROM coin_ledger_mirror WHERE idem_key=?", (idem_key,)).fetchone():
        return None
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute(
            "INSERT INTO coin_ledger_mirror "
            "(intern_id, ledger_kind, delta, balance_after, reason, event_ts, idem_key) "
            "VALUES (?, 'withdrawal', ?, ?, ?, ?, ?)",
            (intern_id, -amount, bal - amount, reason, now_str, idem_key)
        )
    except sqlite3.IntegrityError:
        return None
    return bal - amount


@app.route("/staff/tasks", methods=["GET"])
def staff_task_queue():
    staff = current_staff()
    if not staff:
        return redirect("/staff/login")

    with get_db() as conn:
        status_filter = request.args.get("status", "pending")
        submissions = conn.execute(
            "SELECT ts.*, t.title AS task_title, t.coin_reward, t.task_type, t.target_domain, t.payment_type, t.submission_type, a.name AS intern_name, a.email AS intern_email "
            "FROM task_submissions ts "
            "JOIN tasks t ON ts.task_id = t.id "
            "JOIN intern_accounts a ON ts.intern_id = a.id "
            "WHERE ts.status = ? "
            "ORDER BY ts.created_at ASC",
            (status_filter,)
        ).fetchall()

    return render_template(
        "staff_task_queue.html",
        staff=staff,
        submissions=[dict(s) for s in submissions],
        current_status=status_filter,
        valid_domains=VALID_DOMAINS
    )


@app.route("/staff/tasks/create", methods=["POST"])
def staff_create_task():
    staff = current_staff()
    admin_id = session.get("admin_id") if not staff else None
    if not staff and not admin_id:
        return jsonify({"status": "error", "message": "Staff or Admin auth required"}), 401
    
    actor_id = staff["id"] if staff else admin_id
    actor_type = "staff" if staff else "admin"

    data = request.get_json(silent=True) or request.form
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    task_type = (data.get("task_type") or "general").strip().lower()
    target_domain = (data.get("target_domain") or "").strip()
    payment_type = (data.get("payment_type") or "paid").strip().lower()
    submission_type = (data.get("submission_type") or "url").strip().lower()
    
    if payment_type == "unpaid":
        coin_reward = 0
    else:
        coin_reward = int(data.get("coin_reward") or 50)

    instructions = (data.get("instructions") or description or "Follow project instructions.").strip()
    rubric = (data.get("rubric") or "Submit working solution.").strip()

    if not title or not description:
        return jsonify({"status": "error", "message": "Title and description are required"}), 400

    now_s = now_str()
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO tasks (title, description, coin_reward, is_active, author_type, author_id, task_type, target_domain, payment_type, submission_type, created_at) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
            (title, description, coin_reward, actor_type, actor_id, task_type, target_domain, payment_type, submission_type, now_s)
        )
        task_id = cursor.lastrowid
        conn.execute(
            "INSERT INTO task_versions (task_id, version_number, instructions, rubric, created_at) "
            "VALUES (?, 1, ?, ?, ?)",
            (task_id, instructions, rubric, now_s)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": f"Task '{title}' created successfully!",
        "task_id": task_id
    })


@app.route("/staff/tasks/<int:submission_id>/decision", methods=["POST"])
def staff_task_decision(submission_id):
    staff = current_staff()
    if not staff:
        return jsonify({"status": "error", "message": "Staff authentication required"}), 401

    data = request.get_json(silent=True) or {}
    decision = (data.get("decision") or request.form.get("decision") or "").strip().lower()
    reason_code = (data.get("reason_code") or request.form.get("reason_code") or "").strip()

    if decision not in ("approved", "rejected"):
        return jsonify({"status": "error", "message": "Invalid decision"}), 400

    with get_db() as conn:
        sub = conn.execute(
            "SELECT ts.*, t.title AS task_title, t.coin_reward, t.payment_type, a.name AS intern_name "
            "FROM task_submissions ts "
            "JOIN tasks t ON ts.task_id = t.id "
            "JOIN intern_accounts a ON ts.intern_id = a.id "
            "WHERE ts.id = ?",
            (submission_id,)
        ).fetchone()

        if not sub:
            return jsonify({"status": "error", "message": "Submission not found"}), 404

        coins_awarded = sub["coin_reward"] if (decision == "approved" and (sub["payment_type"] or "paid") != "unpaid") else 0

        conn.execute(
            "UPDATE task_submissions SET status = ?, coins_awarded = ?, reviewed_by_staff_id = ? WHERE id = ?",
            (decision, coins_awarded, staff["id"], submission_id)
        )

        log_staff_review(
            queue_name="tasks",
            staff_id=staff["id"],
            subject_type="task",
            subject_id=submission_id,
            decision=decision,
            reason_code=reason_code or decision.upper(),
            reviewed_input_snapshot=dict(sub)
        )

        if decision == "approved" and coins_awarded > 0:
            credit_intern_coins(conn, sub["intern_id"], coins_awarded, f"Task Reward: {sub['task_title']}", ref_id=submission_id)

        conn.commit()

    return jsonify({
        "status": "success",
        "message": f"Task submission {submission_id} marked as {decision}. {coins_awarded} coins awarded."
    })


# â”€â”€ UP5.2: Open Tasks & Task Submissions Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/tasks", methods=["GET"])
def tasks_list():
    intern = current_intern()
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    with get_db() as conn:
        q = ("SELECT t.*, "
             "(SELECT COUNT(*) FROM task_submissions WHERE task_id = t.id AND status = 'approved') as approved_count "
             "FROM tasks t WHERE t.is_active = 1 ")
        params = []
        if intern:
            q += "AND t.id NOT IN (SELECT task_id FROM task_submissions WHERE intern_id = ?) "
            params.append(intern["id"])

        if intern and intern.get("domain"):
            q += "AND (t.task_type = 'general' OR t.task_type IS NULL OR t.task_type = '' OR (t.task_type = 'domain_specific' AND (t.target_domain = ? OR t.target_domain = '' OR t.target_domain IS NULL))) "
            params.append(intern["domain"])
        else:
            q += "AND (t.task_type = 'general' OR t.task_type IS NULL OR t.task_type = '') "

        q += "ORDER BY t.created_at DESC, t.id DESC"
        pagination = paginate(conn, q, params=params, page=page, per_page=per_page)

        user_submissions = {}
        if intern:
            subs = conn.execute(
                "SELECT task_id, status FROM task_submissions WHERE intern_id = ? ORDER BY id DESC",
                (intern["id"],)
            ).fetchall()
            for s in subs:
                if s["task_id"] not in user_submissions:
                    user_submissions[s["task_id"]] = s["status"]

    return render_template(
        "tasks_list.html",
        tasks=pagination["items"],
        pagination=pagination,
        user_submissions=user_submissions
    )


@app.route("/tasks/<int:task_id>", methods=["GET"])
def task_detail(task_id):
    intern = current_intern()
    with get_db() as conn:
        task = conn.execute("SELECT * FROM tasks WHERE id = ? AND is_active = 1", (task_id,)).fetchone()
        if not task:
            abort(404)

        latest_version = conn.execute(
            "SELECT * FROM task_versions WHERE task_id = ? ORDER BY version_number DESC LIMIT 1",
            (task_id,)
        ).fetchone()

        my_submission = None
        if intern:
            sub = conn.execute(
                "SELECT * FROM task_submissions WHERE intern_id = ? AND task_id = ? ORDER BY id DESC LIMIT 1",
                (intern["id"], task_id)
            ).fetchone()
            if sub:
                my_submission = dict(sub)

    return jsonify({
        "status": "success",
        "task": dict(task),
        "version": dict(latest_version) if latest_version else None,
        "my_submission": my_submission
    })


@app.route("/tasks/<int:task_id>/submit", methods=["POST"])
def task_submit(task_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    with get_db() as conn:
        # Enforce single-submission constraint
        existing = conn.execute(
            "SELECT id, status FROM task_submissions WHERE intern_id = ? AND task_id = ?",
            (intern["id"], task_id)
        ).fetchone()
        if existing:
            return jsonify({
                "status": "error",
                "message": f"You have already submitted this task (Status: {existing['status']}). Multiple submissions are not allowed."
            }), 400

        task = conn.execute("SELECT * FROM tasks WHERE id = ? AND is_active = 1", (task_id,)).fetchone()
        if not task:
            return jsonify({"status": "error", "message": "Task not found"}), 404

        data = request.get_json(silent=True) or {}
        content = (
            data.get("submission_content") or request.form.get("submission_content") or
            data.get("submission_url") or request.form.get("submission_url") or
            data.get("submission_text") or request.form.get("submission_text") or
            data.get("github_url") or request.form.get("github_url") or
            data.get("notes") or request.form.get("notes") or ""
        ).strip()

        sub_file = ""
        file = request.files.get("submission_file")
        if file and file.filename:
            if allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else 'dat'
                sniffed = sniff_upload_type(file) or ext
                filename = f"task_{intern['id']}_{task_id}_{uuid.uuid4().hex[:8]}.{sniffed}"
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                sub_file = f"/uploads/{filename}"

        if not content and not sub_file:
            return jsonify({"status": "error", "message": "Submission content (URL/text) or uploaded file is required."}), 400

        latest_version = conn.execute(
            "SELECT id FROM task_versions WHERE task_id = ? ORDER BY version_number DESC LIMIT 1",
            (task_id,)
        ).fetchone()

        if not latest_version:
            cursor = conn.execute(
                "INSERT INTO task_versions (task_id, version_number, instructions, rubric) VALUES (?, 1, ?, ?)",
                (task_id, task["description"] if "description" in task.keys() and task["description"] else "Initial version", "Standard submission evaluation rubric")
            )
            version_id = cursor.lastrowid
        else:
            version_id = latest_version["id"]

        conn.execute(
            "INSERT INTO task_submissions (intern_id, task_id, task_version_id, submission_content, submission_file, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            (intern["id"], task_id, version_id, content or sub_file, sub_file)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "Task submission received successfully! DBERT staff reviewers will evaluate your work."
    })


# â”€â”€ UP5.6: Coin Discount Calculation Engine & Coin Enrollment Route â”€â”€â”€â”€â”€â”€â”€
def calculate_coin_discount(intern_id, course_price):
    if course_price <= 0:
        return 0, 0, 0

    rate = float(get_config("COIN_TO_INR_RATE", "1"))
    with get_db() as conn:
        # Spec Â§4: portal redemption may draw ONLY from the task balance.
        # Referral coins are cash owed to the ambassador and must never become
        # a course discount â€” this previously summed every ledger_kind.
        bal = get_task_balance(conn, intern_id)

    max_discount_inr = int(course_price * 0.5)
    available_discount_inr = int(bal * rate)
    
    discount_inr = min(max_discount_inr, available_discount_inr)
    coins_used = int(discount_inr / rate) if rate > 0 else 0
    final_price_inr = course_price - discount_inr

    return discount_inr, coins_used, final_price_inr


@app.route("/courses/<int:course_id>/enroll-coins", methods=["POST"])
def course_enroll_coins(course_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    with get_db() as conn:
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            return jsonify({"status": "error", "message": "Course not found"}), 404

        existing = conn.execute(
            "SELECT id FROM course_enrollments WHERE intern_id = ? AND course_id = ?",
            (intern["id"], course_id)
        ).fetchone()

        if existing:
            return jsonify({"status": "error", "message": "Already enrolled in this course."}), 400

        price = int(course["price_inr"] or 0)
        discount_inr, coins_used, final_price = calculate_coin_discount(intern["id"], price)

        if coins_used <= 0:
            return jsonify({"status": "error", "message": "No DBERT coins available to redeem."}), 400

        if final_price > 0:
            return jsonify({"status": "error", "message": f"Coin balance covers â‚¹{discount_inr} discount. Remaining balance of â‚¹{final_price} must be paid via Razorpay/UPI."}), 402

        conn.execute(
            "INSERT INTO course_enrollments (intern_id, course_id, current_day) VALUES (?, ?, 1)",
            (intern["id"], course_id)
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # task balance only â€” see calculate_coin_discount
        cur_bal = get_task_balance(conn, intern["id"])

        conn.execute(
            "INSERT INTO coin_ledger_mirror (intern_id, ledger_kind, delta, balance_after, reason, event_ts, idem_key) "
            "VALUES (?, 'spent', ?, ?, ?, ?, ?)",
            (intern["id"], -coins_used, cur_bal - coins_used, f"Redeemed on {course['title']}", now_str, f"enroll_coin_{course_id}_{uuid.uuid4().hex[:6]}")
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": f"Enrolled successfully! Redeemed {coins_used} DBERT coins."
    })


# â”€â”€ UP5.7: Account Coins Ledger Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/account/coins", methods=["GET"])
def account_coins_ledger():
    intern = current_intern()
    if not intern:
        return redirect("/#signin")

    with get_db() as conn:
        transactions = conn.execute(
            "SELECT * FROM coin_ledger_mirror WHERE intern_id = ? ORDER BY id DESC",
            (intern["id"],)
        ).fetchall()

        # Spec Â§4: the two ledgers are reported separately and never summed.
        balances = get_coin_balances(conn, intern["id"])

        task_earned = conn.execute(
            "SELECT COALESCE(SUM(delta),0) AS val FROM coin_ledger_mirror "
            "WHERE intern_id=? AND ledger_kind='task'", (intern["id"],)
        ).fetchone()["val"]
        task_spent = conn.execute(
            "SELECT COALESCE(SUM(ABS(delta)),0) AS val FROM coin_ledger_mirror "
            "WHERE intern_id=? AND ledger_kind='spent'", (intern["id"],)
        ).fetchone()["val"]
        referral_earned = conn.execute(
            "SELECT COALESCE(SUM(delta),0) AS val FROM coin_ledger_mirror "
            "WHERE intern_id=? AND ledger_kind='referral'", (intern["id"],)
        ).fetchone()["val"]
        referral_withdrawn = conn.execute(
            "SELECT COALESCE(SUM(ABS(delta)),0) AS val FROM coin_ledger_mirror "
            "WHERE intern_id=? AND ledger_kind='withdrawal'", (intern["id"],)
        ).fetchone()["val"]

    return render_template(
        "coins_ledger.html",
        transactions=[dict(t) for t in transactions],
        balances=balances,
        task_balance=balances["task"],
        referral_balance=balances["referral"],
        task_earned=task_earned,
        task_spent=task_spent,
        referral_earned=referral_earned,
        referral_withdrawn=referral_withdrawn,
        # kept so nothing downstream breaks; these now mean TASK-side only
        total_earned=task_earned,
        total_spent=task_spent,
        net_balance=balances["task"],
    )


# â”€â”€ UP7.2: Mentor Slot Management & Booking Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/staff/mentor-slots", methods=["GET", "POST"])
def staff_mentor_slots():
    staff = current_staff()
    mentor = current_mentor()
    if not staff and not mentor:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"status": "error", "message": "Authentication required (staff or mentor)"}), 401
        return redirect("/staff/login")

    actor_id = staff["id"] if staff else mentor["id"]

    if request.method == "GET":
        with get_db() as conn:
            slots = conn.execute(
                "SELECT s.*, b.intern_id, b.meeting_link, b.status as booking_status, a.name as intern_name "
                "FROM mentor_availability_slots s "
                "LEFT JOIN mentor_session_bookings b ON s.id = b.slot_id "
                "LEFT JOIN intern_accounts a ON b.intern_id = a.id "
                "WHERE s.mentor_staff_id = ? "
                "ORDER BY s.start_time ASC",
                (actor_id,)
            ).fetchall()
        return render_template(
            "mentor_availability.html",
            staff=staff or mentor,
            slots=[dict(s) for s in slots]
        )

    data = request.get_json(silent=True) or {}
    start_time_str = (data.get("start_time") or request.form.get("start_time") or "").strip()
    end_time_str = (data.get("end_time") or request.form.get("end_time") or "").strip()

    if not start_time_str or not end_time_str:
        return jsonify({"status": "error", "message": "Start and end times are required."}), 400

    try:
        start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M")

        if start_dt >= end_dt:
            return jsonify({"status": "error", "message": "End time must be after start time."}), 400

        start_hour_min = start_dt.hour * 60 + start_dt.minute
        end_hour_min = end_dt.hour * 60 + end_dt.minute

        window_start = 14 * 60
        window_end = 20 * 60 + 15

        if start_hour_min < window_start or end_hour_min > window_end:
            return jsonify({
                "status": "error",
                "message": "Mentor availability slots must be scheduled strictly within the 14:00 to 20:15 IST window."
            }), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid date format. Use YYYY-MM-DD HH:MM."}), 400

    with get_db() as conn:
        conn.execute(
            "INSERT INTO mentor_availability_slots (mentor_staff_id, start_time, end_time, is_booked) "
            "VALUES (?, ?, ?, 0)",
            (actor_id, start_time_str, end_time_str)
        )
        conn.commit()

    return jsonify({"status": "success", "message": "Mentor slot created successfully!"})


# â”€â”€ UP7.4: Mentor Booking Pacing & Capacity Warning Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_mentor_pacing(intern_id):
    with get_db() as conn:
        active_count = conn.execute(
            "SELECT COUNT(*) as count FROM mentor_session_bookings "
            "WHERE intern_id = ? AND status = 'booked'",
            (intern_id,)
        ).fetchone()["count"]
        return active_count == 0

def check_mentor_capacity_warning():
    with get_db() as conn:
        today_slots = conn.execute(
            "SELECT COUNT(*) as count FROM mentor_availability_slots "
            "WHERE is_booked = 0 AND date(start_time) = date('now','localtime')"
        ).fetchone()["count"]
        return today_slots < 3, today_slots


@app.route("/mentors/slots", methods=["GET"])
def intern_mentor_slots():
    intern = current_intern()
    if not intern:
        return redirect("/#signin")

    with get_db() as conn:
        available_slots = conn.execute(
            "SELECT s.*, st.name as mentor_name "
            "FROM mentor_availability_slots s "
            "JOIN staff_accounts st ON s.mentor_staff_id = st.id "
            "WHERE s.is_booked = 0 AND s.start_time >= datetime('now','localtime') "
            "ORDER BY s.start_time ASC"
        ).fetchall()

        my_bookings = conn.execute(
            "SELECT b.*, s.start_time, s.end_time, st.name as mentor_name "
            "FROM mentor_session_bookings b "
            "JOIN mentor_availability_slots s ON b.slot_id = s.id "
            "JOIN staff_accounts st ON s.mentor_staff_id = st.id "
            "WHERE b.intern_id = ? "
            "ORDER BY s.start_time DESC",
            (intern["id"],)
        ).fetchall()

    return render_template(
        "session_booking.html",
        available_slots=[dict(s) for s in available_slots],
        my_bookings=[dict(b) for b in my_bookings]
    )


@app.route("/mentors/slots/<int:slot_id>/book", methods=["POST"])
def intern_book_slot(slot_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    with get_db() as conn:
        if not check_mentor_pacing(intern["id"]):
            return jsonify({
                "status": "error",
                "message": "You already have an active mentor session booked. Please complete or cancel your existing session before booking another."
            }), 400

        slot = conn.execute(
            "SELECT * FROM mentor_availability_slots WHERE id = ? AND is_booked = 0",
            (slot_id,)
        ).fetchone()

        if not slot:
            return jsonify({"status": "error", "message": "Slot is no longer available."}), 400

        meeting_link = f"https://meet.google.com/dbert-mentor-slot-{slot_id}"

        conn.execute(
            "INSERT INTO mentor_session_bookings (slot_id, intern_id, meeting_link, status) "
            "VALUES (?, ?, ?, 'booked')",
            (slot_id, intern["id"], meeting_link)
        )
        conn.execute(
            "UPDATE mentor_availability_slots SET is_booked = 1 WHERE id = ?",
            (slot_id,)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "1-on-1 Mentor session booked successfully!",
        "meeting_link": meeting_link
    })


# â”€â”€ UP8.4: Mentor & Company Earnings & Settlement Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/mentor/earnings", methods=["GET"])
def mentor_earnings():
    mentor = current_mentor()
    staff = current_staff()
    actor = mentor or staff
    if not actor:
        return redirect("/mentor/login")

    author_type = 'mentor' if mentor else 'staff'
    with get_db() as conn:
        payments = conn.execute(
            "SELECT p.*, c.title as course_title, a.name as intern_name "
            "FROM course_payments p "
            "JOIN courses c ON p.course_id = c.id "
            "JOIN intern_accounts a ON p.intern_id = a.id "
            "WHERE c.author_type = ? AND c.author_id = ? AND p.status = 'verified' "
            "ORDER BY p.id DESC",
            (author_type, actor["id"])
        ).fetchall()

        gross_earnings = sum(p["amount"] for p in payments)
        platform_cut = int(gross_earnings * 0.15)
        net_payout = gross_earnings - platform_cut

    return render_template(
        "mentor_earnings.html",
        mentor=actor,
        staff=actor,
        payments=[dict(p) for p in payments],
        gross_earnings=gross_earnings,
        platform_cut=platform_cut,
        net_payout=net_payout
    )


@app.route("/company/earnings", methods=["GET"])
def company_earnings():
    company = current_company()
    if not company:
        return redirect("/company/login")

    with get_db() as conn:
        payments = conn.execute(
            "SELECT p.*, c.title as course_title, a.name as intern_name "
            "FROM course_payments p "
            "JOIN courses c ON p.course_id = c.id "
            "JOIN intern_accounts a ON p.intern_id = a.id "
            "WHERE c.company_id = ? AND p.status = 'verified' "
            "ORDER BY p.id DESC",
            (company["id"],)
        ).fetchall()

        gross_course_sales = sum(p["amount"] for p in payments)
        platform_cut = int(gross_course_sales * 0.15)
        net_course_earnings = gross_course_sales - platform_cut

    return render_template(
        "company_earnings.html",
        company=company,
        payments=[dict(p) for p in payments],
        gross_course_sales=gross_course_sales,
        platform_cut=platform_cut,
        net_course_earnings=net_course_earnings
    )


# â”€â”€ UP8.6: â‚¹1,999 Premium Internship Track Enrollment Route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/enrollment/paid-1999", methods=["POST"])
def enrollment_paid_1999():
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Authentication required"}), 401

    flag_live = get_config("FLAG_PAID_1999_LIVE", "0") == "1"
    if not flag_live:
        return jsonify({"status": "error", "message": "The â‚¹1,999 Premium Internship Track is currently not active."}), 403

    course_id = int(request.form.get("course_id") or 0)
    file = request.files.get("payment_screenshot")

    if not course_id:
        return jsonify({"status": "error", "message": "Course ID is required."}), 400
    if not file or not file.filename or not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Valid payment screenshot required (png, jpg, jpeg, pdf)."}), 400
    
    sniffed = sniff_upload_type(file)
    if sniffed is None:
        return jsonify({"status": "error", "message": "File must be a real PNG, JPEG, or PDF."}), 400
    
    screenshot_name = f"{uuid.uuid4().hex}.{sniffed}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], screenshot_name))

    amount = 1999
    commission_pct = 15.0
    author_earnings = int(amount * (1.0 - commission_pct / 100.0))

    with get_db() as conn:
        course = conn.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
        if not course:
            return jsonify({"status": "error", "message": "Course not found"}), 404

        conn.execute(
            "INSERT INTO course_payments (intern_id, course_id, amount_inr, status, payment_screenshot, platform_commission_pct, author_earnings_inr) "
            "VALUES (?, ?, ?, 'pending', ?, ?, ?)",
            (intern["id"], course_id, amount, screenshot_name, commission_pct, author_earnings)
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "â‚¹1,999 Premium Internship enrollment payment submitted! DBERT team will verify your payment proof."
    })


# â”€â”€ UP9.2: Registration OTP Generation & Verification Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/auth/send-otp", methods=["POST"])
def auth_send_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or request.form.get("email") or "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "A valid email address is required."}), 400

    ip = get_client_ip()
    allowed, ra = rate_check(f"sendotp:ip:{ip}", 5, 3600)
    if not allowed:
        return too_many(ra)
    allowed_email, ra_email = rate_check(f"sendotp:email:{email}", 3, 3600)
    if not allowed_email:
        return too_many(ra_email)

    otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    expires_dt = datetime.now() + timedelta(minutes=10)
    expires_str = expires_dt.strftime("%Y-%m-%d %H:%M:%S")

    otp_hash = set_password_hash(otp)

    with get_db() as conn:
        conn.execute("UPDATE signup_otps SET is_used = 1 WHERE email = ?", (email,))
        conn.execute(
            "INSERT INTO signup_otps (email, otp, expires_at, is_used) VALUES (?, ?, ?, 0)",
            (email, otp_hash, expires_str)
        )
        conn.commit()

    log_info("send_otp", f"OTP generated and hashed for {email}")
    send_email_async(email, "Your Verification Code", f"<p>Your OTP is <b>{otp}</b>. Valid for 10 minutes.</p>")

    resp = {
        "status": "success",
        "message": f"Verification code sent to {email}. Valid for 10 minutes."
    }
    import os
    if os.environ.get("FLASK_DEBUG", "false").lower() == "true":
        resp["dev_otp_hint"] = otp
        
    return jsonify(resp)


RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "")

def verify_recaptcha(response_token: str, min_score: float = 0.5) -> bool:
    if not RECAPTCHA_SECRET_KEY:
        import os
        if os.environ.get("FLASK_DEBUG", "false").lower() == "true":
            return True
        return False # Fail closed in prod if key is missing!
    if not response_token:
        return False
    try:
        url = "https://www.google.com/recaptcha/api/siteverify"
        r = requests.post(url, data={
            "secret": RECAPTCHA_SECRET_KEY,
            "response": response_token
        }, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("success", False) and (float(data.get("score", 0.0)) >= min_score)
        return False
    except Exception as e:
        log_error("recaptcha_verify", e)
        import os
        if os.environ.get("FLASK_DEBUG", "false").lower() == "true":
            return True # Fail open only in development
        return False # Fail closed in production


@app.route("/auth/verify-otp", methods=["POST"])
def auth_verify_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or request.form.get("email") or "").strip().lower()
    user_otp = (data.get("otp") or request.form.get("otp") or "").strip()

    if not email or not user_otp:
        return jsonify({"status": "error", "message": "Email and verification code are required."}), 400

    with get_db() as conn:
        otp_row = conn.execute(
            "SELECT * FROM signup_otps WHERE email = ? AND is_used = 0 AND expires_at >= datetime('now','localtime') ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()

        if not otp_row or otp_row["otp"] != user_otp:
            return jsonify({"status": "error", "message": "Invalid or expired verification code."}), 400

        conn.execute("UPDATE signup_otps SET is_used = 1 WHERE id = ?", (otp_row["id"],))
        conn.execute("UPDATE intern_accounts SET email_verified = 1 WHERE email = ?", (email,))
        conn.commit()

    return jsonify({
        "status": "success",
        "message": "Email address verified successfully!"
    })


# â”€â”€ UP10.1: Generic SQL Pagination Helper Engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def paginate(conn, query_str, params=(), page=1, per_page=20):
    try:
        page = max(1, int(page))
        per_page = max(1, min(100, int(per_page)))

        count_sql = f"SELECT COUNT(*) as total FROM ({query_str})"
        total_items = conn.execute(count_sql, params).fetchone()["total"]

        total_pages = max(1, (total_items + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        paginated_sql = f"{query_str} LIMIT ? OFFSET ?"
        full_params = tuple(params) + (per_page, offset)
        items = conn.execute(paginated_sql, full_params).fetchall()

        return {
            "items": [dict(row) for row in items],
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    except Exception as e:
        log_error("paginate_helper", e)
        return {
            "items": [],
            "page": 1,
            "per_page": per_page,
            "total_items": 0,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False
        }


@app.route("/post-hire/launch-tasks")
def post_hire_launch_tasks():
    """Track 6 / T6: hand a Hired + deposit-verified intern straight into the
    tutor's Task Hub via SSO -- same handoff pattern as course_start() above,
    just pointed at /tasks instead of a course page. Eligibility (Hired status +
    a verified â‚¹499 deposit) is checked here on the portal side; the tutor's
    /tasks route itself is intentionally not gated on any of this -- it only
    needs a valid SSO session, same as every other tutor page."""
    intern = current_intern()
    if not intern:
        return redirect("/#signin")
    with get_db() as conn:
        eligible = conn.execute(
            "SELECT 1 FROM post_applications pa "
            "JOIN post_hire_deposits d ON d.post_application_id = pa.id "
            "WHERE pa.intern_id=? AND pa.status='Hired' AND d.status='verified' LIMIT 1",
            (intern["id"],),
        ).fetchone()
    if not eligible:
        # Not (yet) eligible -- back to the portal rather than a dead-end page.
        return redirect("/portal?launch_tasks=ineligible#overview")
    # Track 6 / T7: graceful fallback if the tutor SSO secret is missing or the
    # handoff can't be built -- never a raw error, just back to the portal with
    # a flag the Overview card can show a friendly retry message for.
    if not TUTOR_SSO_SECRET:
        log_error("post-hire-launch-tasks", Exception("TUTOR_SSO_SECRET not configured"))
        return redirect("/portal?launch_tasks=error#overview")
    try:
        with get_db() as conn:
            enr = conn.execute(
                "SELECT joining_date FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
                (intern["email"],)).fetchone()
        joining_date_str = (enr["joining_date"] if enr and enr["joining_date"] else "")
        token = mint_tutor_sso_token(intern, joining_date_str)
        return redirect(f"{TUTOR_BASE_URL}/sso?token={token}&next={quote('/tasks', safe='')}")
    except Exception as e:
        log_error("post-hire-launch-tasks", e)
        return redirect("/portal?launch_tasks=error#overview")


@app.route("/admin/post-hire-deposits")
def admin_post_hire_deposits():
    """Track 5: admin view of â‚¹499 job-hire deposits -- verify payments and mark
    manual refunds. Entirely separate from the legacy course-payments/enrollments
    admin pages."""
    if not require_admin():
        return redirect("/admin-login")
    sf = request.args.get("status", "pending")
    with get_db() as conn:
        q = ("SELECT d.*, a.name AS intern_name, a.email AS intern_email, "
             "p.title AS post_title, co.name AS company_name "
             "FROM post_hire_deposits d "
             "JOIN intern_accounts a ON a.id = d.intern_id "
             "JOIN posts p ON p.id = d.post_id "
             "JOIN companies co ON co.id = p.company_id ")
        if sf in ("pending", "verified", "rejected", "refunded"):
            rows = conn.execute(q + "WHERE d.status=? ORDER BY d.id DESC", (sf,)).fetchall()
        else:
            rows = conn.execute(q + "ORDER BY d.id DESC").fetchall()
        counts_rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM post_hire_deposits GROUP BY status"
        ).fetchall()
    counts = {"pending": 0, "verified": 0, "rejected": 0, "refunded": 0}
    for r in counts_rows:
        if r["status"] in counts:
            counts[r["status"]] = r["n"]
    counts["total"] = sum(counts.values())
    return render_template("admin_post_hire_deposits.html",
                           deposits=[row_to_dict(r) for r in rows], active=sf, counts=counts)


@app.route("/admin/post-hire-deposits/<int:dep_id>/review", methods=["POST"])
def admin_post_hire_deposit_review(dep_id):
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    decision = clean_text((request.get_json(silent=True) or request.form).get("decision"))
    if decision not in ("verify", "reject"):
        return jsonify({"status": "error", "message": "decision must be verify|reject"}), 400
    with get_db() as conn:
        dep = conn.execute(
            "SELECT d.*, a.name AS intern_name, a.email AS intern_email, p.title AS post_title "
            "FROM post_hire_deposits d JOIN intern_accounts a ON a.id = d.intern_id "
            "JOIN posts p ON p.id = d.post_id WHERE d.id=?", (dep_id,)
        ).fetchone()
        if not dep:
            return jsonify({"status": "error", "message": "Not found"}), 404
        if dep["status"] != "pending":
            return jsonify({"status": "error", "message": "Already reviewed."}), 409
        dep = row_to_dict(dep)
        new_status = "verified" if decision == "verify" else "rejected"
        conn.execute("UPDATE post_hire_deposits SET status=?, updated_at=? WHERE id=?",
                     (new_status, now_str(), dep_id))
        conn.commit()
    send_post_hire_deposit_status_email(dep["intern_name"], dep["intern_email"],
                                         dep["post_title"], new_status)
    return jsonify({"status": "success", "deposit_status": new_status})


@app.route("/admin/post-hire-deposits/<int:dep_id>/refund", methods=["POST"])
def admin_post_hire_deposit_refund(dep_id):
    """Track 5: manual admin refund action, per your explicit call -- no auto-trigger.
    Only a verified deposit can be marked refunded."""
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        dep = conn.execute("SELECT * FROM post_hire_deposits WHERE id=?", (dep_id,)).fetchone()
        if not dep:
            return jsonify({"status": "error", "message": "Not found"}), 404
        if dep["status"] != "verified":
            return jsonify({"status": "error", "message": "Only a verified deposit can be refunded."}), 400
        conn.execute(
            "UPDATE post_hire_deposits SET status='refunded', refunded_at=?, updated_at=? WHERE id=?",
            (now_str(), now_str(), dep_id),
        )
        conn.commit()
    return jsonify({"status": "success", "deposit_status": "refunded"})


@app.route("/admin/course-payments")
def admin_course_payments():
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    sf = request.args.get("status", "pending")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    with get_db() as conn:
        q = ("SELECT cp.*, a.name AS intern_name, a.email AS intern_email "
             "FROM course_payments cp JOIN intern_accounts a ON a.id=cp.intern_id ")
        if sf in ("pending", "verified", "rejected"):
            pagination = paginate(conn, q + "WHERE cp.status=? ORDER BY cp.id DESC", (sf,), page=page, per_page=per_page)
        else:
            pagination = paginate(conn, q + "ORDER BY cp.id DESC", page=page, per_page=per_page)
    return render_template("admin_course_payments.html",
                           payments=pagination["items"], pagination=pagination, active=sf)


@app.route("/admin/course-payments/<int:pay_id>/review", methods=["POST"])
def admin_course_payment_review(pay_id):
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    decision = clean_text((request.get_json(silent=True) or request.form).get("decision"))
    if decision not in ("verify", "reject"):
        return jsonify({"status": "error", "message": "decision must be verify|reject"}), 400
    with get_db() as conn:
        pay = conn.execute(
            "SELECT cp.*, a.name AS intern_name, a.email AS intern_email FROM course_payments cp "
            "JOIN intern_accounts a ON a.id = cp.intern_id WHERE cp.id=?", (pay_id,)
        ).fetchone()
        if not pay:
            return jsonify({"status": "error", "message": "Not found"}), 404
        if pay["status"] != "pending":
            return jsonify({"status": "error", "message": "Already reviewed."}), 409
        pay = row_to_dict(pay)
    if decision == "verify":
        is_portal_course = pay["course_id"] >= _PORTAL_COURSE_ID_OFFSET
        # T7 âš ï¸ tutor dependency: portal (DBERT/company) courses have no tutor-side
        # unlock yet -- record the verified payment, but never fake an unlock signal.
        # Only tutor-catalogue courses go through the real unlock webhook.
        if not is_portal_course and not _signal_tutor_course_unlock(pay["intern_id"], pay["course_id"]):
            return jsonify({"status": "error", "message": "Could not reach the tutor to unlock. Try again."}), 502
        with get_db() as conn:
            conn.execute("UPDATE course_payments SET status='verified', updated_at=? WHERE id=?",
                         (now_str(), pay_id))
            # Â§6.3 â€” commission the referrer at the exact point the payment
            # becomes verified. Idempotent on the payment id, so a retried
            # review cannot pay twice. Never allowed to break verification.
            try:
                credit_referral_commission(
                    conn, pay["intern_id"], pay.get("amount_inr") or pay.get("amount") or 0,
                    f"course: {pay.get('course_title') or pay['course_id']}",
                    ref_payment_id=f"course_payment_{pay_id}")
            except Exception as e:
                log_error("referral-commission-course", e)
            conn.commit()
        # T10: notify_course_payment_verified's push call persists the dashboard
        # notification (#26) itself -- no separate add_notification() here (would dupe).
        link_url = ("https://internship.dbert.online/portal" if is_portal_course
                    else f"{TUTOR_BASE_URL}/courses/{pay['course_id']}")
        try:
            notify_course_payment_verified(pay["intern_name"], pay["intern_email"],
                                           pay["course_title"], is_portal_course, link_url)
        except Exception as e:
            log_error("course-payment-notify", e)
    else:
        with get_db() as conn:
            conn.execute("UPDATE course_payments SET status='rejected', updated_at=? WHERE id=?",
                         (now_str(), pay_id))
            conn.commit()
        try:
            notify_course_payment_rejected(
                pay["intern_name"], pay["intern_email"], pay["course_title"],
                f"https://internship.dbert.online/courses/{pay['course_id']}/pay")
        except Exception as e:
            log_error("course-payment-notify", e)
    return jsonify({"status": "success"})


def _tutor_leaderboard(domain_slug):
    """Local composite leaderboard â€” ranked by certs*40 + tasks*20 + lessons*10 + hours*5."""
    try:
        with get_db() as conn:
            rows = conn.execute("""
                SELECT ia.id AS intern_id, ia.name, ia.domain,
                    (SELECT COUNT(*) FROM intern_certificates WHERE intern_id = ia.id) AS cert_count,
                    (SELECT COUNT(*) FROM task_submissions WHERE intern_id = ia.id AND status = 'approved') AS task_count,
                    COALESCE((SELECT SUM(total_minutes) FROM attendance WHERE intern_id = ia.id), 0) AS att_mins,
                    COALESCE((SELECT MAX(ce.current_day) - 1 FROM course_enrollments ce WHERE ce.intern_id = ia.id), 0) AS lessons_done
                FROM intern_accounts ia
                WHERE ia.is_active = 1
                ORDER BY (
                    (SELECT COUNT(*) FROM intern_certificates WHERE intern_id = ia.id) * 40 +
                    (SELECT COUNT(*) FROM task_submissions WHERE intern_id = ia.id AND status = 'approved') * 20 +
                    COALESCE((SELECT MAX(ce.current_day) - 1 FROM course_enrollments ce WHERE ce.intern_id = ia.id), 0) * 10 +
                    COALESCE((SELECT SUM(total_minutes) FROM attendance WHERE intern_id = ia.id), 0) / 60.0 * 5
                ) DESC
                LIMIT 50
            """).fetchall()
            board = []
            for r in rows:
                d = row_to_dict(r)
                hours = round(d["att_mins"] / 60.0, 1)
                score = round(d["cert_count"] * 40 + d["task_count"] * 20 + d["lessons_done"] * 10 + hours * 5, 1)
                d["score"] = score
                d["hours"] = hours
                board.append(d)

            domain_board = []
            if domain_slug:
                domain_board = [r for r in board if (r.get("domain") or "").lower().replace(" ", "-") == domain_slug.lower()]
        return {"global": board, "domain": domain_board}
    except Exception as e:
        log_error("local-leaderboard", e)
        return {"global": [], "domain": []}


def _tutor_progress_live(intern_id):
    """DEPRECATED: Progress is tracked locally."""
    return None


@app.route("/intern/leaderboard")
def intern_leaderboard_proxy():
    """JSON for the portal Leaderboard tab â€” global + own-domain composite boards
    (UAT #11). Marks the viewer's row server-side and strips other interns' ids."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        slug = tutor_domain_slug(intern.get("domain", ""))
        data = _tutor_leaderboard(slug)
        me = str(intern["id"])

        def _mark(rows):
            out = []
            for i, r in enumerate(rows or [], start=1):
                d = dict(r)
                d["rank"] = i
                d["is_me"] = str(d.get("intern_id")) == me
                d.pop("intern_id", None)  # never expose other interns' ids to the browser
                out.append(d)
            return out

        return jsonify({
            "status": "success",
            "global": _mark(data.get("global")),
            "domain": _mark(data.get("domain")),
            "domain_label": intern.get("domain", ""),
        })
    except Exception as e:
        log_error("intern-leaderboard", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/ledger")
def admin_ledger():
    """All mirrored coin events + certificates (Track 1 Â§6). Read-only, filterable
    by ledger_kind / intern_id."""
    try:
        if not require_admin():
            return redirect("/admin-login")
        kind = clean_text(request.args.get("kind"))
        intern_filter = clean_text(request.args.get("intern_id"))
        sql = (
            "SELECT m.ledger_kind, m.delta, m.balance_after, m.reason, m.event_ts, "
            "m.intern_id, a.name AS intern_name, a.email AS intern_email "
            "FROM coin_ledger_mirror m LEFT JOIN intern_accounts a ON a.id = m.intern_id"
        )
        conds, params = [], []
        if kind in ("ad", "task"):
            conds.append("m.ledger_kind=?"); params.append(kind)
        if intern_filter:
            conds.append("m.intern_id=?"); params.append(intern_filter)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY m.event_ts DESC, m.id DESC LIMIT 500"
        with get_db() as conn:
            rows = [row_to_dict(r) for r in conn.execute(sql, params).fetchall()]
            certs = [row_to_dict(r) for r in conn.execute(
                "SELECT c.course_title, c.cert_id, c.issued_at, c.intern_id, "
                "a.name AS intern_name FROM intern_certificates c "
                "LEFT JOIN intern_accounts a ON a.id = c.intern_id "
                "ORDER BY c.received_at DESC, c.id DESC LIMIT 200"
            ).fetchall()]
        return render_template(
            "admin_ledger.html", rows=rows, certs=certs, kind=kind,
            intern_filter=intern_filter,
        )
    except Exception as e:
        log_error("/admin/ledger", e)
        return "Server error", 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PUBLIC APIs
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/jd/<domain>")
def get_jd(domain):
    try:
        jd = JOB_DESCRIPTIONS.get(domain)
        if not jd:
            return jsonify({"status": "error", "message": "Domain not found"}), 404
        return jsonify({"status": "success", "domain": domain, **jd})
    except Exception as e:
        log_error("jd", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/upcoming-mondays")
def upcoming_mondays():
    """Return list of upcoming Monday dates for the joining date picker."""
    try:
        return jsonify({"status": "success", "mondays": get_upcoming_mondays()})
    except Exception as e:
        log_error("upcoming-mondays", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/apply-token")
def apply_token():
    """Issue a fresh signed timing token for the apply / re-apply / forgot forms (8.4)."""
    try:
        return jsonify({
            "status": "success",
            "token": make_timing_token(),
            "turnstile_enabled": TURNSTILE_ENABLED,
            "turnstile_sitekey": TURNSTILE_SITEKEY if TURNSTILE_ENABLED else "",
        })
    except Exception as e:
        log_error("apply-token", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/apply", methods=["POST"])
def apply():
    """
    Unified signup+apply: creates intern_account and submits application
    in one step. Status goes directly to Under Review.
    Also handles re-apply for rejected interns (new record inserted).
    """
    try:
        data = request.get_json(force=True)
        ip = get_client_ip()
        _hp_email = clean_text(data.get("email")).lower()
        # 8.4 invisible bot checks. Honeypot/timing/turnstile return a FAKE success so
        # bots can't detect they were caught, and NO application row is created.
        fake_ok = jsonify({"status": "success", "message": "Application submitted!",
                           "redirect": "/profile"})
        if clean_text(data.get("company_website")):
            log_abuse(ip, "/apply", "apply:honeypot", "honeypot", _hp_email)
            return fake_ok
        if not verify_timing_token(clean_text(data.get("_ts"))):
            log_abuse(ip, "/apply", "apply:timing", "timing", _hp_email)
            return fake_ok
        if not verify_turnstile(data.get("cf_turnstile_response"), ip):
            log_abuse(ip, "/apply", "apply:turnstile", "turnstile", _hp_email)
            return fake_ok
        allowed, ra = rate_check(f"apply:ip:{ip}", *RL_APPLY_IP)
        if not allowed:
            log_abuse(ip, "/apply", f"apply:ip:{ip}", "rate_limit", _hp_email)
            return too_many(ra)
        name            = clean_text(data.get("name"))
        email           = clean_text(data.get("email")).lower()
        phone           = clean_text(data.get("phone"))
        city            = clean_text(data.get("city"))
        college         = clean_text(data.get("college"))
        course          = clean_text(data.get("course"))
        semester        = clean_text(data.get("semester"))
        year_of_passing = clean_text(data.get("year_of_passing"))
        domain          = clean_text(data.get("domain"))
        why_join        = clean_text(data.get("why_join"))
        portfolio       = clean_text(data.get("portfolio"))
        # Phase 11.4 â€” optional LinkedIn/GitHub captured at signup (host-validated, skippable).
        ok_li, linkedin_url = _validate_profile_url(data.get("linkedin_url"), "linkedin.com")
        ok_gh, github_url   = _validate_profile_url(data.get("github_url"), "github.com")
        password        = clean_text(data.get("password"))
        visitor_id      = clean_text(data.get("visitor_id"))
        is_reapply      = bool(data.get("is_reapply", False))

        # Validation. T9: domain is now OPTIONAL here -- the operative domain comes
        # from the post an intern applies to (Track 2 board), not from this legacy
        # program-application table (still NOT NULL on domain when one IS given).
        missing = [k for k, v in {
            "name": name, "email": email, "phone": phone, "city": city, "college": college,
            "course": course, "semester": semester, "year_of_passing": year_of_passing,
        }.items() if not v]
        if missing:
            return jsonify({"status": "error", "message": f"Missing: {', '.join(missing)}"}), 400
        if len(name) < 2 or len(name) > 80:
            return jsonify({"status": "error", "message": "Invalid name."}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Invalid email."}), 400
        if not is_valid_email_domain(email):
            return jsonify({"status": "error", "message": "Disposable emails not allowed."}), 400
        if not is_valid_phone(phone):
            return jsonify({"status": "error", "message": "Invalid 10-digit mobile number."}), 400
        if course not in VALID_COURSES:
            return jsonify({"status": "error", "message": "Invalid course."}), 400
        if semester not in VALID_SEMESTERS:
            return jsonify({"status": "error", "message": "Invalid semester."}), 400
        if year_of_passing not in VALID_YEARS:
            return jsonify({"status": "error", "message": "Invalid year."}), 400
        if domain and domain not in VALID_DOMAINS:
            return jsonify({"status": "error", "message": "Invalid domain."}), 400
        if portfolio and not is_valid_url(portfolio):
            return jsonify({"status": "error", "message": "Invalid portfolio URL."}), 400
        if not ok_li:
            return jsonify({"status": "error", "message": "Please enter a valid LinkedIn profile URL or leave it blank."}), 400
        if not ok_gh:
            return jsonify({"status": "error", "message": "Please enter a valid GitHub profile URL or leave it blank."}), 400

        # T9: no domain -> this is plain account signup, not a program application
        # (applications.domain is NOT NULL, so there's nothing domain-bound to write).
        # why_join only makes sense when actually applying to a domain program.
        if not domain:
            with get_db() as conn:
                existing_acct = conn.execute(
                    "SELECT * FROM intern_accounts WHERE email=?", (email,)
                ).fetchone()
                if existing_acct:
                    current = get_current_user()
                    if not (current and current.get("role") == "intern"
                            and (current.get("email") or "").lower() == email):
                        return jsonify({
                            "status": "error",
                            "message": "An account with this email already exists. Please sign in.",
                            "code": "account_exists",
                        }), 409
                    conn.execute("""
                        UPDATE intern_accounts SET name=?,phone=?,city=?,college=?,course=?,
                        semester=?,year_of_passing=?,updated_at=? WHERE email=?
                    """, (name, phone, city, college, course, semester, year_of_passing, now_str(), email))
                else:
                    if not password or len(password) < 8:
                        return jsonify({"status": "error", "message": "Password must be at least 8 characters."}), 400
                    conn.execute("""
                        INSERT INTO intern_accounts
                        (name,email,phone,city,college,course,semester,year_of_passing,
                        linkedin_url,github_url,password_hash,password_set,is_active,signup_stage,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,1,1,3,?,?)
                    """, (name, email, phone, city, college, course, semester, year_of_passing,
                          linkedin_url, github_url, set_password_hash(password), now_str(), now_str()))
                conn.commit()
            token = create_session(email, "intern")
            link_device_to_email(visitor_id, email)
            resp = make_response(jsonify({
                "status": "success", "message": "Account created!", "redirect": "/profile",
            }))
            _set_session_cookie(resp, token)
            return resp

        if len(why_join) < 80 or len(why_join) > 1200:
            return jsonify({"status": "error", "message": "Why join must be 80â€“1200 chars."}), 400

        with get_db() as conn:
            existing_acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=?", (email,)
            ).fetchone()

            # â”€â”€ Phase 10.2: duplicate-account guard â”€â”€
            # An account already exists for this email. Allow the request to proceed ONLY
            # if it comes from a logged-in intern whose session email matches (additional-
            # domain apply / re-apply). A public signup (no matching session) is rejected
            # with 409 BEFORE any DB write â€” closing the silent overwrite/takeover hole.
            if existing_acct:
                current = get_current_user()
                if not (current and current.get("role") == "intern"
                        and (current.get("email") or "").lower() == email):
                    return jsonify({
                        "status": "error",
                        "message": "An account with this email already exists. Please sign in to apply for another domain.",
                        "code": "account_exists",
                    }), 409

            # â”€â”€ Phase 9: cap distinct applications per person. Only blocks a brand-new
            # (email, domain) combo; updates/reapplies to an existing domain are exempt
            # (they don't increase the distinct count). Existing rules (UNIQUE(email,domain),
            # 30-day reapply cooldown) remain enforced below.
            existing_for_domain = conn.execute(
                "SELECT 1 FROM applications WHERE email=? AND domain=? LIMIT 1", (email, domain)
            ).fetchone()
            if not existing_for_domain:
                app_count = conn.execute(
                    "SELECT COUNT(*) FROM applications WHERE email=?", (email,)
                ).fetchone()[0]
                if app_count >= MAX_APPLICATIONS_PER_PERSON:
                    return jsonify({"status": "error",
                                    "message": "You can apply to at most 3 internships. Please contact us if you need to change a choice."}), 400

            # â”€â”€ New signup: password required â”€â”€
            if not existing_acct:
                if not password or len(password) < 8:
                    return jsonify({"status": "error", "message": "Password must be at least 8 characters."}), 400
                existing_app = conn.execute(
                    "SELECT * FROM applications WHERE email=? AND domain=?", (email, domain)
                ).fetchone()
                if existing_app:
                    return jsonify({"status": "error", "message": "Application already exists for this email and domain."}), 400

            # â”€â”€ Re-apply flow: check 30-day block â”€â”€
            if existing_acct or is_reapply:
                latest_app = conn.execute(
                    "SELECT * FROM applications WHERE email=? AND domain=? ORDER BY id DESC LIMIT 1",
                    (email, domain)
                ).fetchone()
                if latest_app and latest_app["status"] == STATUS_REJECTED:
                    rejected_at = latest_app["rejected_at"]
                    if rejected_at:
                        try:
                            rejected_dt = datetime.strptime(rejected_at, "%Y-%m-%d %H:%M:%S")
                            days_since  = (datetime.now() - rejected_dt).days
                            if days_since < 30:
                                days_left = 30 - days_since
                                return jsonify({
                                    "status": "error",
                                    "message": f"You can re-apply in {days_left} day(s).",
                                    "days_left": days_left
                                }), 400
                        except Exception:
                            pass

            mentor_email = assign_mentor_email(domain)

            # â”€â”€ Insert new application (always insert for re-apply, keeping history) â”€â”€
            if is_reapply and existing_acct:
                # Insert new row â€” previous rejected row stays for history
                cur = conn.execute("""
                    INSERT INTO applications
                    (name,email,phone,city,college,course,semester,year_of_passing,domain,
                    why_join,portfolio,status,mentor_email,visitor_id,source,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),?)
                """, (name, email, phone, city, college, course, semester, year_of_passing, domain,
                      why_join, portfolio, STATUS_UNDER_REVIEW, mentor_email, visitor_id, "reapply", now_str()))
                application_id = cur.lastrowid
                # Update intern account details
                conn.execute("""
                    UPDATE intern_accounts
                    SET name=?,phone=?,city=?,college=?,course=?,semester=?,year_of_passing=?,domain=?,updated_at=?
                    WHERE email=?
                """, (name, phone, city, college, course, semester, year_of_passing, domain, now_str(), email))
            elif existing_acct:
                # Existing account, existing non-rejected app â€” update it
                existing_app = conn.execute(
                    "SELECT * FROM applications WHERE email=? AND domain=? ORDER BY id DESC LIMIT 1",
                    (email, domain)
                ).fetchone()
                if existing_app:
                    conn.execute("""
                        UPDATE applications SET name=?,phone=?,city=?,college=?,course=?,semester=?,
                        year_of_passing=?,why_join=?,portfolio=?,status=?,mentor_email=?,visitor_id=?,updated_at=?
                        WHERE id=?
                    """, (name, phone, city, college, course, semester, year_of_passing,
                          why_join, portfolio, STATUS_UNDER_REVIEW, mentor_email, visitor_id, now_str(),
                          existing_app["id"]))
                    application_id = existing_app["id"]
                else:
                    cur = conn.execute("""
                        INSERT INTO applications
                        (name,email,phone,city,college,course,semester,year_of_passing,domain,
                        why_join,portfolio,status,mentor_email,visitor_id,source,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),?)
                    """, (name, email, phone, city, college, course, semester, year_of_passing, domain,
                          why_join, portfolio, STATUS_UNDER_REVIEW, mentor_email, visitor_id, "web", now_str()))
                    application_id = cur.lastrowid
            else:
                # Brand new user
                cur = conn.execute("""
                    INSERT INTO applications
                    (name,email,phone,city,college,course,semester,year_of_passing,domain,
                    why_join,portfolio,status,mentor_email,visitor_id,source,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),?)
                """, (name, email, phone, city, college, course, semester, year_of_passing, domain,
                      why_join, portfolio, STATUS_UNDER_REVIEW, mentor_email, visitor_id, "web", now_str()))
                application_id = cur.lastrowid

            # â”€â”€ Create or update intern_account â”€â”€
            if not existing_acct:
                conn.execute("""
                    INSERT INTO intern_accounts
                    (application_id,name,email,phone,city,college,course,semester,year_of_passing,
                    domain,linkedin_url,github_url,password_hash,password_set,is_active,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,?)
                """, (application_id, name, email, phone, city, college, course, semester,
                      year_of_passing, domain, linkedin_url, github_url, set_password_hash(password),
                      now_str(), now_str()))
            else:
                conn.execute("""
                    UPDATE intern_accounts SET application_id=?,name=?,phone=?,city=?,college=?,
                    course=?,semester=?,year_of_passing=?,domain=?,updated_at=? WHERE email=?
                """, (application_id, name, phone, city, college, course, semester,
                      year_of_passing, domain, now_str(), email))
                # Phase 11.4 â€” only fill LinkedIn/GitHub if provided; never wipe an existing value.
                if linkedin_url:
                    conn.execute("UPDATE intern_accounts SET linkedin_url=? WHERE email=?", (linkedin_url, email))
                if github_url:
                    conn.execute("UPDATE intern_accounts SET github_url=? WHERE email=?", (github_url, email))

            conn.commit()

        # Auto-login
        token = create_session(email, "intern")
        link_device_to_email(visitor_id, email)
        send_application_received_email(name, email, domain)
        resp = make_response(jsonify({
            "status": "success",
            "message": "Application submitted!",
            "application_id": application_id,
            "redirect": "/profile"
        }))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("apply", e)
        return jsonify({"status": "error", "message": "Server error. Please try again."}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 13 â€” multistep signup (brand-new users only). The single-step /apply above
# is kept intact for logged-in interns applying to another domain / re-applying.
#   stage1: create account (name/email/phone/password) + mandatory T&C consent +
#           optional newsletter; auto-login. No application/academics yet.
#   stage2: academic background (+ chosen domain).
#   stage3: profile URLs + indirect intent answers -> creates the application
#           (Under Review) and fires the received email/push.
# Resume: signup_stage on intern_accounts (1/2 = incomplete, 3 = done). Existing
# accounts default to 3 so they're never sent back through the wizard.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.route("/signup/stage1", methods=["POST"])
def signup_stage1():
    try:
        data = request.get_json(force=True) or {}
        ip = get_client_ip()
        _hp_email = clean_text(data.get("email")).lower()
        # Invisible bot checks (same as /apply) â€” this is the public entry point. Caught
        # bots get a FAKE success and no account is created.
        fake_ok = jsonify({"status": "success", "message": "Account created!", "stage": 1, "next": 2})
        if clean_text(data.get("company_website")):
            log_abuse(ip, "/signup/stage1", "signup:honeypot", "honeypot", _hp_email); return fake_ok
        if not verify_timing_token(clean_text(data.get("_ts"))):
            log_abuse(ip, "/signup/stage1", "signup:timing", "timing", _hp_email); return fake_ok
        if not verify_turnstile(data.get("cf_turnstile_response"), ip):
            log_abuse(ip, "/signup/stage1", "signup:turnstile", "turnstile", _hp_email); return fake_ok
        allowed, ra = rate_check(f"apply:ip:{ip}", *RL_APPLY_IP)
        if not allowed:
            log_abuse(ip, "/signup/stage1", f"apply:ip:{ip}", "rate_limit", _hp_email); return too_many(ra)

        name      = clean_text(data.get("name"))
        email     = clean_text(data.get("email")).lower()
        phone     = clean_text(data.get("phone"))
        password  = clean_text(data.get("password"))
        terms     = bool(data.get("terms_accepted"))
        newsletter = 1 if data.get("newsletter_opt_in") else 0
        visitor_id = clean_text(data.get("visitor_id"))

        if len(name) < 2 or len(name) > 80:
            return jsonify({"status": "error", "message": "Please enter your full name."}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Please enter a valid email."}), 400
        if not is_valid_email_domain(email):
            return jsonify({"status": "error", "message": "Disposable emails are not allowed."}), 400
        if not is_valid_phone(phone):
            return jsonify({"status": "error", "message": "Please enter a valid 10-digit mobile number."}), 400
        if not password or len(password) < 8:
            return jsonify({"status": "error", "message": "Password must be at least 8 characters."}), 400
        if not terms:
            return jsonify({"status": "error", "message": "Please accept the Terms & Conditions and Privacy Policy to continue."}), 400

        with get_db() as conn:
            if conn.execute("SELECT 1 FROM intern_accounts WHERE email=? LIMIT 1", (email,)).fetchone():
                return jsonify({"status": "error", "code": "account_exists",
                                "message": "An account with this email already exists. Please sign in."}), 409
            conn.execute("""
                INSERT INTO intern_accounts
                (name,email,phone,password_hash,password_set,is_active,
                 terms_accepted_at,newsletter_opt_in,signup_stage,created_at,updated_at)
                VALUES (?,?,?,?,1,1,?,?,1,?,?)
            """, (name, email, phone, set_password_hash(password), now_str(), newsletter, now_str(), now_str()))
            # Â§6.1 â€” attribute the signup to a referrer if the 30-day cookie is
            # present. Threaded through the EXISTING flow; never blocks signup.
            try:
                new_id = conn.execute("SELECT id FROM intern_accounts WHERE email=?",
                                      (email,)).fetchone()
                ref_code = clean_text(data.get("ref")) or clean_text(request.cookies.get(REFERRAL_COOKIE))
                if new_id and ref_code:
                    outcome, detail = attach_referral_on_signup(
                        conn, new_id["id"], email, ref_code, visitor_id=data.get("visitor_id"))
                    if outcome == "ok":
                        ga4_server_event("referral_signup",                    # Â§8
                                         {"source_code": ref_code},
                                         client_id=data.get("visitor_id"))
                    else:
                        log_abuse(get_client_ip(), "/signup/stage1",
                                  f"referral:{ref_code}", f"referral_{outcome}")
            except Exception as e:
                log_error("referral-attach", e)
            conn.commit()

        token = create_session(email, "intern")
        # Track 2 Â§3 funnel: a logged-out Apply-Now stashed the post URL in the flask
        # session. stage1's response replaces that cookie with the DB auth token (same
        # cookie name), so persist the resume target on the session row now â€” it's the
        # last moment the flask-session 'next' is still readable. Resumed at stage3.
        pending_next = _safe_portal_next(session.pop("next", None))
        if pending_next:
            with get_db() as conn:
                conn.execute("UPDATE user_sessions SET next_url=? WHERE session_token=?",
                             (pending_next, token))
                conn.commit()
        link_device_to_email(visitor_id, email)
        resp = make_response(jsonify({"status": "success", "message": "Account created!", "stage": 1, "next": 2}))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("signup-stage1", e)
        return jsonify({"status": "error", "message": "Server error. Please try again."}), 500


@app.route("/signup/stage2", methods=["POST"])
def signup_stage2():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        data = request.get_json(force=True) or {}
        city    = clean_text(data.get("city"))
        college = clean_text(data.get("college"))
        course  = clean_text(data.get("course"))
        semester = clean_text(data.get("semester"))
        year    = clean_text(data.get("year_of_passing"))
        # T9: domain is now OPTIONAL at signup -- the operative domain comes from
        # whichever post the intern later applies to (Track 2 board). Validate it
        # only when one is actually given.
        domain  = clean_text(data.get("domain"))
        missing = [k for k, v in {"city": city, "college": college, "course": course,
                                  "semester": semester, "year_of_passing": year}.items() if not v]
        if missing:
            return jsonify({"status": "error", "message": "Missing: " + ", ".join(missing)}), 400
        if course not in VALID_COURSES:
            return jsonify({"status": "error", "message": "Invalid course."}), 400
        if semester not in VALID_SEMESTERS:
            return jsonify({"status": "error", "message": "Invalid semester."}), 400
        if year not in VALID_YEARS:
            return jsonify({"status": "error", "message": "Invalid year."}), 400
        if domain and domain not in VALID_DOMAINS:
            return jsonify({"status": "error", "message": "Invalid domain."}), 400
        with get_db() as conn:
            conn.execute("""
                UPDATE intern_accounts SET city=?,college=?,course=?,semester=?,year_of_passing=?,domain=?,
                    signup_stage=MAX(IFNULL(signup_stage,0),2),updated_at=? WHERE email=?
            """, (city, college, course, semester, year, domain, now_str(), email))
            conn.commit()
        return jsonify({"status": "success", "stage": 2, "next": 3})
    except Exception as e:
        log_error("signup-stage2", e)
        return jsonify({"status": "error", "message": "Server error. Please try again."}), 500


@app.route("/signup/stage3", methods=["POST"])
def signup_stage3():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        data = request.get_json(force=True) or {}
        why_join  = clean_text(data.get("why_join"))
        portfolio = clean_text(data.get("portfolio"))
        ok_li, linkedin = _validate_profile_url(data.get("linkedin_url"), "linkedin.com")
        ok_gh, github   = _validate_profile_url(data.get("github_url"), "github.com")
        intent = data.get("intent_answers") or {}
        if not isinstance(intent, dict):
            intent = {}
        # keep the intent blob small/safe: at most 12 short string->string entries
        intent = {clean_text(str(k))[:40]: clean_text(str(v))[:200] for k, v in list(intent.items())[:12]}
        if portfolio and not is_valid_url(portfolio):
            return jsonify({"status": "error", "message": "Invalid portfolio URL."}), 400
        if not ok_li:
            return jsonify({"status": "error", "message": "Please enter a valid LinkedIn URL or leave it blank."}), 400
        if not ok_gh:
            return jsonify({"status": "error", "message": "Please enter a valid GitHub URL or leave it blank."}), 400

        with get_db() as conn:
            acct = row_to_dict(conn.execute("SELECT * FROM intern_accounts WHERE email=?", (email,)).fetchone())
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404
            if int(acct.get("signup_stage") or 0) < 2:
                return jsonify({"status": "error", "message": "Please complete your academic details first.", "next": 2}), 400
            # T9: domain is now OPTIONAL -- with none chosen at signup, there's no legacy
            # program application to create (applications.domain is NOT NULL); the intern
            # just finishes signup and picks up the operative domain from whichever post
            # they apply to later (Track 2 board). why_join's "applying" framing is only
            # meaningful once a domain is in play.
            domain = acct.get("domain")
            application_id = acct.get("application_id")
            if domain:
                if len(why_join) < 80 or len(why_join) > 1200:
                    return jsonify({"status": "error",
                                    "message": "Please tell us a bit more about why you're applying (80â€“1200 characters)."}), 400
                mentor_email = assign_mentor_email(domain)
                existing_app = conn.execute(
                    "SELECT * FROM applications WHERE email=? AND domain=? ORDER BY id DESC LIMIT 1", (email, domain)).fetchone()
                if existing_app:  # idempotent re-submit (e.g. retry) â€” update, don't duplicate
                    application_id = existing_app["id"]
                    conn.execute("""
                        UPDATE applications SET name=?,phone=?,city=?,college=?,course=?,semester=?,year_of_passing=?,
                            why_join=?,portfolio=?,status=?,mentor_email=?,intent_answers=?,updated_at=? WHERE id=?
                    """, (acct["name"], acct.get("phone"), acct.get("city"), acct.get("college"), acct.get("course"),
                          acct.get("semester"), acct.get("year_of_passing"), why_join, portfolio, STATUS_UNDER_REVIEW,
                          mentor_email, json.dumps(intent), now_str(), application_id))
                else:
                    cur = conn.execute("""
                        INSERT INTO applications
                        (name,email,phone,city,college,course,semester,year_of_passing,domain,why_join,portfolio,
                         status,mentor_email,visitor_id,source,intent_answers,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),?)
                    """, (acct["name"], email, acct.get("phone"), acct.get("city"), acct.get("college"), acct.get("course"),
                          acct.get("semester"), acct.get("year_of_passing"), domain, why_join, portfolio, STATUS_UNDER_REVIEW,
                          mentor_email, clean_text(data.get("visitor_id")), "web-multistep", json.dumps(intent), now_str()))
                    application_id = cur.lastrowid
            conn.execute("""
                UPDATE intern_accounts SET application_id=?,
                    linkedin_url=COALESCE(NULLIF(?,''),linkedin_url),
                    github_url=COALESCE(NULLIF(?,''),github_url),
                    signup_stage=3,updated_at=? WHERE email=?
            """, (application_id, linkedin, github, now_str(), email))
            conn.commit()

        if domain:
            send_application_received_email(acct["name"], email, domain)
        # Track 2 Â§3 acquisition funnel: resume at the Apply-Now post stashed when the
        # visitor was logged out (pitfall Â§9 â€” carried through ALL signup stages). It
        # lives on the auth-session row (stage1 persisted it; the flask-session cookie
        # can't survive the DB-token swap). Consume it once. Relative portal path only.
        resume = _safe_portal_next(user.get("next_url"))
        if resume:
            with get_db() as conn:
                conn.execute("UPDATE user_sessions SET next_url=NULL WHERE session_token=?",
                             (get_session_token_from_request(),))
                conn.commit()
        done_message = "Application submitted!" if domain else "Account created!"
        # T1 (funnel fix): when signup completes with no domain/application (the
        # normal path now that domain isn't collected at signup â€” see T9 note above),
        # send the intern straight to the job board instead of an empty /portal, with
        # a one-time interstitial flag the listings page uses to show a welcome prompt.
        # `resume` (a stashed Apply-Now post) always wins when present.
        default_redirect = "/first-run" if not domain else "/portal"
        return jsonify({"status": "success", "message": done_message, "stage": 3,
                        "redirect": resume or default_redirect})
    except Exception as e:
        log_error("signup-stage3", e)
        return jsonify({"status": "error", "message": "Server error. Please try again."}), 500

@app.route("/first-run")
def first_run():
    user = current_intern()
    if not user:
        return redirect("/#signin")
    return render_template("first_run_choice.html", intern=user)


@app.route("/intern/login", methods=["POST"])
def intern_login():
    try:
        data = request.get_json(force=True)
        email    = clean_text(data.get("email")).lower()
        password = clean_text(data.get("password"))
        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password required."}), 400
        ip = get_client_ip()
        allowed, ra = rate_check(f"login:intern:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/intern/login", f"login:intern:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        locked, _ = login_locked(email)
        if locked:
            log_abuse(ip, "/intern/login", _login_fail_bucket(email), "login_lockout", email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
        if not user or int(user["password_set"] or 0) != 1 or not verify_password(user["password_hash"], password):
            record_login_fail(email)
            return jsonify({"status": "error", "message": "Invalid credentials. (If you have a legacy account without a password, use Forgot Password)"}), 401
        if is_legacy_hash(user["password_hash"]):
            migrate_password_hash("intern_accounts", email, password)  # P17.0 lazy upgrade
        clear_login_fails(email)
        token = create_session(email, "intern")
        link_device_to_email(data.get("visitor_id"), email)

        # UAT #47 â€” an account that never finished signup (stage 1/2: no
        # application submitted yet) has no business landing on the portal
        # dashboard, which would otherwise fabricate a status like "Apply
        # Pending" with empty/partial data. Resume the signup wizard instead;
        # none of the tutor-handoff/apply-funnel redirect state below applies
        # until signup is actually complete.
        if int(user["signup_stage"] or 3) < 3:
            session.pop("post_login_return_to", None)
            session.pop("post_login_next", None)
            session.pop("next", None)
            resp = make_response(jsonify({
                "status": "success",
                "message": "Welcome back â€” let's finish setting up your account.",
                "redirect": "/#signup",
            }))
            _set_session_cookie(resp, token)
            return resp

        # Track 1 Â§3 â€” tutor handoff. If the intern arrived from the AI Tutor
        # (return_to=tutor stashed at GET /login), mint an SSO token and bounce
        # back when the 6 PM joining gate is open; otherwise keep them on the
        # portal where the profile shows the "opens at 6 PM" tutor lock.
        login_redirect = "/profile"
        login_message = "Login successful."
        login_before_joining = False
        if session.pop("post_login_return_to", None) == "tutor" and TUTOR_SSO_SECRET:
            tutor_next = _safe_tutor_next(session.pop("post_login_next", None))
            with get_db() as conn:
                acct_row = conn.execute(
                    "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)
                ).fetchone()
                enr_row = conn.execute(
                    "SELECT * FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
                ).fetchone()
            acct = row_to_dict(acct_row) if acct_row else {}
            joining_date_str = (row_to_dict(enr_row).get("joining_date", "") if enr_row else "")
            # T9 âš ï¸: same paid-gate as generate_tutor_token/mobile_login -- this call
            # site mints the identical real SSO token, so it must not bypass the gate.
            if acct and joining_unlocked(joining_date_str) and _intern_payment_verified(email):
                tok = mint_tutor_sso_token(acct, joining_date_str)
                login_redirect = f"{TUTOR_BASE_URL}/sso?token={tok}&next={quote(tutor_next, safe='')}"
            elif acct and not _intern_payment_verified(email):
                login_before_joining = False
                login_message = "You're signed in. Complete enrollment payment verification to access the AI Tutor."
            else:
                pretty = _joining_pretty(joining_date_str)
                login_before_joining = True
                login_message = (
                    f"You're signed in. The AI Tutor opens on {pretty} at 6:00 PM."
                    if pretty else "You're signed in. The AI Tutor opens at 6:00 PM."
                )
        session.pop("post_login_next", None)  # never leak a stale target
        # Track 2 Â§3 acquisition funnel: a logged-out Apply-Now stashed the post
        # URL in session['next']; resume there (only when not doing a tutor
        # handoff, i.e. still the default profile redirect). Relative-path only.
        pending_next = _safe_portal_next(session.pop("next", None))
        if pending_next and login_redirect == "/profile":
            login_redirect = pending_next
        login_payload = {"status": "success", "message": login_message, "redirect": login_redirect}
        if login_before_joining:
            login_payload["before_joining"] = True
        resp = make_response(jsonify(login_payload))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("intern-login", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TRACK 2 Â§1 â€” COMPANY ACCOUNTS (job-board posters)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def current_company():
    """The logged-in, active company (session role='company') or None."""
    user = require_role("company")
    if not user:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM companies WHERE email=? AND is_active=1 LIMIT 1", (user["email"],)
        ).fetchone()
    return row_to_dict(row) if row else None


def current_mentor():
    """The logged-in, active mentor (session role='mentor') or None."""
    user = require_role("mentor")
    if not user:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM mentors WHERE email=? AND is_active=1 LIMIT 1", (user["email"],)
        ).fetchone()
    return row_to_dict(row) if row else None


@app.route("/company/signup", methods=["GET"])
def company_signup_page():
    return render_template("company_signup.html")


@app.route("/company/signup", methods=["POST"])
def company_signup():
    try:
        data = request.get_json(force=True, silent=True) or {}
        name     = clean_text(data.get("name"))
        email    = clean_text(data.get("email")).lower()
        phone    = clean_text(data.get("phone"))
        website  = clean_text(data.get("website"))
        about    = clean_text(data.get("about"))
        password = data.get("password") or ""
        if not name or not email or not password:
            return jsonify({"status": "error", "message": "Company name, work email and password are required."}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Enter a valid work email."}), 400
        if len(password) < 8:
            return jsonify({"status": "error", "message": "Password must be at least 8 characters."}), 400
        with get_db() as conn:
            if conn.execute("SELECT id FROM companies WHERE email=?", (email,)).fetchone():
                return jsonify({"status": "error", "message": "An account with this email already exists."}), 400
            conn.execute(
                "INSERT INTO companies (name,email,phone,website,about,password_hash,"
                "is_approved,is_active,created_at,updated_at) VALUES (?,?,?,?,?,?,0,1,?,?)",
                (name, email, phone, website, about, set_password_hash(password),
                 now_str(), now_str()),
            )
            conn.commit()
        token = create_session(email, "company")
        resp = make_response(jsonify({
            "status": "success",
            "message": "Account created. Pending admin approval â€” you can draft posts but can't publish yet.",
            "redirect": "/company",
        }))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("company-signup", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/company/login", methods=["GET"])
def company_login_page():
    return render_template("company_login.html")


@app.route("/company/login", methods=["POST"])
def company_login():
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = clean_text(data.get("email") or request.form.get("email")).lower()
        password = (data.get("password") or request.form.get("password") or "").strip()
        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password required."}), 400
        ip = get_client_ip()
        allowed, ra = rate_check(f"login:company:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/company/login", f"login:company:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        locked, _ = login_locked(email)
        if locked:
            log_abuse(ip, "/company/login", _login_fail_bucket(email), "login_lockout", email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        with get_db() as conn:
            comp = conn.execute(
                "SELECT * FROM companies WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
        if not comp or not verify_password(comp["password_hash"], password):
            record_login_fail(email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        clear_login_fails(email)
        token = create_session(email, "company")
        resp = make_response(jsonify({
            "status": "success", "message": "Login successful.", "redirect": "/company",
        }))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("company-login", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/company/logout", methods=["POST"])
def company_logout():
    invalidate_session(get_session_token_from_request())
    resp = make_response(jsonify({"status": "success"}))
    _clear_session_cookie(resp)
    return resp


POST_TYPES = ("job", "internship")


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _post_slugify(title):
    s = re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")
    return s[:60] or "post"


def _live_post_count(conn, company_id):
    """Published posts that have not expired â€” the company's used live slots."""
    return conn.execute(
        "SELECT COUNT(*) FROM posts WHERE company_id=? AND status='published' "
        "AND (expires_at IS NULL OR expires_at > datetime('now','localtime'))",
        (company_id,),
    ).fetchone()[0]


@app.route("/company/profile", methods=["GET", "POST"])
def company_profile_edit():
    company = current_company()
    if not company:
        return redirect("/#company")
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        website = request.form.get("website", "").strip()
        about = request.form.get("about", "").strip()
        
        if not name:
            flash("Company name is required.", "error")
            return redirect("/company/profile")
            
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE companies SET name=?, phone=?, website=?, about=?, updated_at=datetime('now','localtime') WHERE id=?",
                    (name, phone, website, about, company["id"])
                )
                conn.commit()
            flash("Profile updated successfully.", "success")
        except Exception as e:
            log_error("company-profile", e)
            flash("An error occurred while updating the profile.", "error")
        return redirect("/company/profile")
        
    return render_template("company_profile_edit.html", active_page="company_profile", company=company)


@app.route("/company")
def company_dashboard():
    company = current_company()
    if not company:
        return redirect("/company/login")
    with get_db() as conn:
        posts = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM posts WHERE company_id=? AND status != 'deleted' ORDER BY id DESC", (company["id"],)
        ).fetchall()]
        live = _live_post_count(conn, company["id"])
    return render_template("company_dashboard.html", company=company, posts=posts, live_count=live)


@app.route("/company/posts/new")
def company_post_new():
    company = current_company()
    if not company:
        return redirect("/company/login")
    return render_template("post_form.html", company=company, post=None, domains=VALID_DOMAINS)


@app.route("/company/posts/<int:post_id>")
def company_post_manage(post_id):
    company = current_company()
    if not company:
        return redirect("/company/login")
    with get_db() as conn:
        post = conn.execute(
            "SELECT * FROM posts WHERE id=? AND company_id=? AND status != 'deleted'", (post_id, company["id"])
        ).fetchone()
    if not post:
        abort(404)
    return render_template("post_form.html", company=company, post=row_to_dict(post),
                           domains=VALID_DOMAINS)


@app.route("/company/posts", methods=["POST"])
def company_post_save():
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    post_type = clean_text(data.get("post_type"))
    domain    = clean_text(data.get("domain"))
    title     = clean_text(data.get("title"))
    if post_type not in POST_TYPES:
        return jsonify({"status": "error", "message": "Choose job or internship."}), 400
    if domain not in VALID_DOMAINS:
        return jsonify({"status": "error", "message": "Choose a valid domain."}), 400
    if not title:
        return jsonify({"status": "error", "message": "Title is required."}), 400

    # UAT #37D: Paid/Unpaid asked first â†’ when unpaid, wage fields are not stored.
    is_unpaid = 1 if data.get("is_unpaid") else 0
    stipend_min = None if is_unpaid else _int_or_none(data.get("stipend_min"))
    stipend_max = None if is_unpaid else _int_or_none(data.get("stipend_max"))
    pay_period  = "" if is_unpaid else clean_text(data.get("pay_period"))
    # UAT #37C: default "Apply by" to today + 15 days (IST) when the company leaves it blank
    # (applies to both jobs and internships); the company may still set any date.
    apply_by = clean_text(data.get("apply_by")) or (date.today() + timedelta(days=15)).isoformat()

    vals = (
        post_type, domain, title, _post_slugify(title),
        (data.get("description") or "").strip(),
        (data.get("responsibilities") or "").strip(),
        clean_text(data.get("skills")),
        clean_text(data.get("location")),
        clean_text(data.get("work_mode")),
        stipend_min,
        stipend_max,
        pay_period,
        is_unpaid,
        clean_text(data.get("duration")),
        _int_or_none(data.get("openings")) or 1,
        apply_by,
        json.dumps(data.get("certifications") or []),
        (data.get("eligibility") or "").strip(),
    )
    post_id = data.get("post_id")
    with get_db() as conn:
        if post_id:
            owns = conn.execute(
                "SELECT id FROM posts WHERE id=? AND company_id=? AND status != 'deleted'", (post_id, company["id"])
            ).fetchone()
            if not owns:
                return jsonify({"status": "error", "message": "Not found"}), 404
            # T6: expires_at ("extend") is edit-only -- it has no sensible value at
            # creation time, so it's applied as a separate optional SET clause rather
            # than being folded into the shared create/update `vals` tuple above.
            extra_set, extra_vals = "", []
            if "expires_at" in data:
                extra_set = ", expires_at=?"
                raw_expiry = clean_text(data.get("expires_at"))
                # _LIVE_SQL compares expires_at against a full 'now' timestamp string;
                # a bare date (YYYY-MM-DD) would sort as already-expired against
                # "YYYY-MM-DD HH:MM:SS" for the same day, so pin it to end-of-day.
                extra_vals = [f"{raw_expiry} 23:59:59" if raw_expiry else None]
            conn.execute(
                "UPDATE posts SET post_type=?,domain=?,title=?,slug=?,description=?,"
                "responsibilities=?,skills=?,location=?,work_mode=?,stipend_min=?,"
                "stipend_max=?,pay_period=?,is_unpaid=?,duration=?,openings=?,apply_by=?,"
                "certifications_json=?,eligibility=?,updated_at=?" + extra_set +
                " WHERE id=? AND company_id=?",
                (*vals, now_str(), *extra_vals, post_id, company["id"]),
            )
            conn.commit()
            return jsonify({"status": "success", "post_id": post_id})
        cur = conn.execute(
            "INSERT INTO posts (company_id,post_type,domain,title,slug,description,"
            "responsibilities,skills,location,work_mode,stipend_min,stipend_max,pay_period,"
            "is_unpaid,duration,openings,apply_by,certifications_json,eligibility,status,"
            "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'draft',?,?)",
            (company["id"], *vals, now_str(), now_str()),
        )
        conn.commit()
        return jsonify({"status": "success", "post_id": cur.lastrowid})


# â”€â”€ T7: company-authored courses (portal-side; DBERT collects + reviews) â”€â”€â”€â”€
@app.route("/company/courses", methods=["POST"])
def company_course_create():
    """Company creates a priced (or free) course. Always inserted as content_status
    'pending' -- DBERT reviews + co-signs before it can appear in the public catalogue
    or carry the industrial-certification attribute (T7)."""
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    title = clean_text(data.get("title"))
    if not title:
        return jsonify({"status": "error", "message": "Title is required."}), 400
    domain = clean_text(data.get("domain"))
    if domain and domain not in VALID_DOMAINS:
        return jsonify({"status": "error", "message": "Choose a valid domain."}), 400
    is_paid = 1 if data.get("is_paid") else 0
    price_inr = _int_or_none(data.get("price_inr")) or 0 if is_paid else 0
    if is_paid and price_inr <= 0:
        return jsonify({"status": "error", "message": "Set a price for a paid course."}), 400
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO courses (title, slug, domain, company_id, is_paid, price_inr, "
            "content_status, source) VALUES (?,?,?,?,?,?,'pending','custom')",
            (title, _post_slugify(title), domain, company["id"], is_paid, price_inr),
        )
        course_id = cur.lastrowid
        
        # Process custom syllabus chapters if provided
        custom_chapters = data.get("chapters") or []
        if custom_chapters and isinstance(custom_chapters, list):
            for ch_idx, ch in enumerate(custom_chapters, start=1):
                day_num = _int_or_none(ch.get("day_number")) or ch_idx
                ch_title = clean_text(ch.get("title")) or f"Day {day_num} Topic"
                ch_row = conn.execute(
                    "INSERT INTO course_chapters (course_id, day_number, title) VALUES (?,?,?)",
                    (course_id, day_num, ch_title)
                )
                ch_id = ch_row.lastrowid
                subtopics = ch.get("subtopics") or []
                for sub_idx, sub in enumerate(subtopics, start=1):
                    sub_title = clean_text(sub.get("title")) or f"Subtopic {sub_idx}"
                    sub_brief = clean_text(sub.get("brief")) or "Core learning objective."
                    takeaways = sub.get("key_takeaways") or ["Understand key concept", "Apply practical skills"]
                    conn.execute(
                        "INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) VALUES (?,?,?,?,?)",
                        (ch_id, sub_idx, sub_title, sub_brief, json.dumps(takeaways))
                    )
        else:
            # Auto-seed default 3-day structured syllabus for this new course
            c1 = conn.execute("INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 1, 'Foundations & Environment')", (course_id,)).lastrowid
            conn.execute("INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) VALUES (?, 1, 'Core Syntax & Architecture', 'Master fundamental constructs and environment setup.', ?)", (c1, json.dumps(["Master core syntax", "Configure dev environment"])))
            conn.execute("INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) VALUES (?, 2, 'Functions & Modules', 'Build reusable functional components.', ?)", (c1, json.dumps(["Write modular functions", "Import libraries"])))

            c2 = conn.execute("INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 2, 'Applied Core Concepts')", (course_id,)).lastrowid
            conn.execute("INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) VALUES (?, 1, 'Practical Implementation', 'Build end-to-end practical workflows.', ?)", (c2, json.dumps(["Implement domain workflows", "Handle error cases"])))

            c3 = conn.execute("INSERT INTO course_chapters (course_id, day_number, title) VALUES (?, 3, 'Capstone Project')", (course_id,)).lastrowid
            conn.execute("INSERT INTO course_subtopics (chapter_id, sort_order, title, brief, key_takeaways_json) VALUES (?, 1, 'Project Deployment', 'Deploy your final project to production.', ?)", (c3, json.dumps(["Build production artifact", "Deploy to cloud"])))

        conn.commit()
    return jsonify({"status": "success", "course_id": course_id + _PORTAL_COURSE_ID_OFFSET})


@app.route("/admin/courses", methods=["GET"])
def admin_courses_list():
    """Default to pending (the review queue); ?status=approved|rejected for history."""
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    status = clean_text(request.args.get("status")) or "pending"
    if status not in ("pending", "approved", "rejected"):
        status = "pending"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT c.*, co.name AS company_name FROM courses c "
            "LEFT JOIN companies co ON co.id = c.company_id "
            "WHERE c.content_status=? ORDER BY c.id DESC", (status,)
        ).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        d["public_id"] = d["id"] + _PORTAL_COURSE_ID_OFFSET
        out.append(d)
    return jsonify({"status": "success", "courses": out})


@app.route("/admin/courses/<int:course_id>/review", methods=["POST"])
def admin_course_review(course_id):
    """Approve = DBERT co-signs the content (unlocks the industrial-cert attribute +
    the public catalogue merge); reject = stays hidden. Issuance itself stays
    tutor-gated regardless (T7 âš ï¸ never simulate it here)."""
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    decision = clean_text(data.get("decision"))
    if decision not in ("approve", "reject"):
        return jsonify({"status": "error", "message": "decision must be approve or reject."}), 400
    new_status = "approved" if decision == "approve" else "rejected"
    with get_db() as conn:
        cur = conn.execute("UPDATE courses SET content_status=? WHERE id=?", (new_status, course_id))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "success", "id": course_id, "content_status": new_status})


@app.route("/admin/courses/<int:course_id>/toggle", methods=["POST"])
def admin_course_toggle(course_id):
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        row = conn.execute("SELECT is_active FROM courses WHERE id=?", (course_id,)).fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Not found"}), 404
        active = 0 if row["is_active"] else 1
        conn.execute("UPDATE courses SET is_active=? WHERE id=?", (active, course_id))
        conn.commit()
    return jsonify({"status": "success", "is_active": active})


@app.route("/company/posts/<int:post_id>/questions", methods=["GET"])
def company_post_questions_list(post_id):
    """T6: a company's own uploaded interview questions for one post (any status)."""
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        owns = conn.execute(
            "SELECT id FROM posts WHERE id=? AND company_id=?", (post_id, company["id"])
        ).fetchone()
        if not owns:
            return jsonify({"status": "error", "message": "Not found"}), 404
        rows = conn.execute(
            "SELECT id, text, status, sort_order, created_at FROM post_questions "
            "WHERE post_id=? ORDER BY sort_order, id", (post_id,)
        ).fetchall()
    return jsonify({"status": "success", "questions": [row_to_dict(r) for r in rows]})


@app.route("/company/posts/<int:post_id>/questions", methods=["POST"])
def company_post_questions_save(post_id):
    """T6: replace this post's question set. UGC -- always re-inserted as 'pending';
    a prior admin approval does NOT carry over to edited/new text, by design."""
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    raw_questions = data.get("questions")
    if not isinstance(raw_questions, list):
        return jsonify({"status": "error", "message": "questions must be a list."}), 400
    if len(raw_questions) > 10:
        return jsonify({"status": "error", "message": "Maximum 10 questions per post."}), 400
    cleaned = []
    for q in raw_questions:
        text = clean_text(q)
        if not text:
            continue
        if len(text) < 5 or len(text) > 500:
            return jsonify({"status": "error",
                            "message": "Each question must be 5â€“500 characters."}), 400
        cleaned.append(text)
    with get_db() as conn:
        owns = conn.execute(
            "SELECT id FROM posts WHERE id=? AND company_id=?", (post_id, company["id"])
        ).fetchone()
        if not owns:
            return jsonify({"status": "error", "message": "Not found"}), 404
        conn.execute("DELETE FROM post_questions WHERE post_id=?", (post_id,))
        for i, text in enumerate(cleaned):
            conn.execute(
                "INSERT INTO post_questions (post_id, company_id, text, sort_order, status) "
                "VALUES (?, ?, ?, ?, 'pending')",
                (post_id, company["id"], text, i),
            )
        conn.commit()
    return jsonify({"status": "success", "count": len(cleaned)})


@app.route("/company/posts/<int:post_id>/publish", methods=["POST"])
def company_post_publish(post_id):
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    if not company["is_approved"]:
        return jsonify({"status": "error",
                        "message": "Your account is pending admin approval â€” you can't publish yet."}), 403
    with get_db() as conn:
        post_row = conn.execute(
            "SELECT * FROM posts WHERE id=? AND company_id=?", (post_id, company["id"])
        ).fetchone()
        if not post_row:
            return jsonify({"status": "error", "message": "Not found"}), 404
        post = row_to_dict(post_row)
        if post["status"] == "published":
            return jsonify({"status": "success", "post_status": "published", "message": "Already live."})
        # T7: Google-for-Jobs completeness gate -- reject incomplete posts with the field list.
        missing = _post_completeness_errors(post)
        if missing:
            return jsonify({"status": "error", "code": "incomplete",
                            "message": "This post is missing required fields for publishing.",
                            "fields": missing}), 400
        # Atomic: the "< 3 live" guard and the flip are ONE statement, so two
        # concurrent publishes can never both pass (no race to 4). pitfall Â§9.
        cur = conn.execute(
            "UPDATE posts SET status='published', "
            "published_at=datetime('now','localtime'), "
            "expires_at=datetime('now','localtime','+30 days'), "
            "updated_at=datetime('now','localtime') "
            "WHERE id=? AND company_id=? AND status!='published' AND ("
            "  SELECT COUNT(*) FROM posts p2 WHERE p2.company_id=? AND p2.status='published'"
            "    AND (p2.expires_at IS NULL OR p2.expires_at > datetime('now','localtime'))"
            ") < 3",
            (post_id, company["id"], company["id"]),
        )
        conn.commit()
    if cur.rowcount == 0:
        return jsonify({"status": "error",
                        "message": "You already have 3 live posts. Unpublish one to free a slot."}), 409
    # Â§7: instant-indexing URL_UPDATED (best-effort, never blocks publish).
    with get_db() as conn:
        p = conn.execute("SELECT id, post_type, slug, title FROM posts WHERE id=?", (post_id,)).fetchone()
    if p:
        notify_search_engines(_canonical_post_url(row_to_dict(p)), action="URL_UPDATED")
        # UAT #36-D: alert this company's followers about the new live post.
        _notify_company_followers(
            company["id"], f"New role at {company['name']}",
            f"{company['name']} just posted: {row_to_dict(p).get('title') or 'a new opening'}.",
            link=_post_path(row_to_dict(p)), kind="post")
    return jsonify({"status": "success", "post_status": "published"})


@app.route("/company/posts/<int:post_id>/unpublish", methods=["POST"])
def company_post_unpublish(post_id):
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE posts SET status='unpublished', updated_at=datetime('now','localtime') "
            "WHERE id=? AND company_id=? AND status='published'",
            (post_id, company["id"]),
        )
        conn.commit()
    if cur.rowcount == 0:
        return jsonify({"status": "error", "message": "Not a live post."}), 400
    # Â§7: instant-indexing URL_DELETED so Google drops it promptly (best-effort).
    with get_db() as conn:
        p = conn.execute("SELECT id, post_type, slug FROM posts WHERE id=?", (post_id,)).fetchone()
    if p:
        notify_search_engines(_canonical_post_url(row_to_dict(p)), action="URL_DELETED")
    return jsonify({"status": "success", "post_status": "unpublished"})


@app.route("/company/posts/<int:post_id>/delete", methods=["POST"])
def company_post_delete(post_id):
    """T6: soft-delete only -- post_applications FKs to posts.id, so a hard DELETE
    would orphan any existing applicants. status='deleted' is excluded by _LIVE_SQL
    everywhere else, so a deleted post simply stops appearing anywhere public."""
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE posts SET status='deleted', updated_at=datetime('now','localtime') "
            "WHERE id=? AND company_id=? AND status != 'deleted'",
            (post_id, company["id"]),
        )
        conn.commit()
    if cur.rowcount == 0:
        return jsonify({"status": "error", "message": "Post not found or already deleted."}), 404
    # Â§7: instant-indexing URL_DELETED, same as unpublish, best-effort.
    with get_db() as conn:
        p = conn.execute("SELECT id, post_type, slug FROM posts WHERE id=?", (post_id,)).fetchone()
    if p:
        notify_search_engines(_canonical_post_url(row_to_dict(p)), action="URL_DELETED")
    return jsonify({"status": "success", "post_status": "deleted"})


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# UAT #35 (Cohorts) + #36 (company profile #A, follow+alerts #D)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def _notify_company_followers(company_id, title, body="", *, link="", kind="company"):
    """UAT #36-D: notify every intern following a company (best-effort)."""
    try:
        with get_db() as conn:
            ids = [r["intern_id"] for r in conn.execute(
                "SELECT intern_id FROM company_follows WHERE company_id=?", (company_id,)
            ).fetchall()]
        for iid in ids:
            add_notification(iid, title, body, kind=kind, link=link)
    except Exception as e:
        log_error("notify-followers", e)


def _company_public_slug(company):
    return f"{_cv_slugify(company.get('name'))}-{company['id']}"


def _cohort_seats_left(conn, cohort):
    """None when unlimited (capacity 0); else capacity âˆ’ current enrollments."""
    if not cohort.get("capacity"):
        return None
    used = conn.execute(
        "SELECT COUNT(*) FROM cohort_enrollments WHERE cohort_id=?", (cohort["id"],)
    ).fetchone()[0]
    return max(0, cohort["capacity"] - used)


# â”€â”€ Cohorts â€” company side â”€â”€
@app.route("/company/cohorts", methods=["GET"])
def company_cohorts():
    company = current_company()
    if not company:
        return redirect("/company/login")
    with get_db() as conn:
        rows = [row_to_dict(r) for r in conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM cohort_enrollments e WHERE e.cohort_id=c.id) "
            "AS enrolled FROM cohorts c WHERE c.company_id=? ORDER BY c.id DESC",
            (company["id"],)).fetchall()]
    return render_template("company_cohorts.html", company=company, cohorts=rows)


@app.route("/company/cohorts", methods=["POST"])
def company_cohort_create():
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    if not company["is_approved"]:
        return jsonify({"status": "error",
                        "message": "Your account is pending admin approval."}), 403
    d = request.get_json(silent=True) or request.form
    title = clean_text(d.get("title"))
    starts_at = clean_text(d.get("starts_at"))
    meeting_url = clean_text(d.get("meeting_url"))
    if not title or not starts_at or not meeting_url:
        return jsonify({"status": "error",
                        "message": "Title, date/time and meeting link are required."}), 400
    try:
        cap = int(d.get("capacity") or 0)
    except (TypeError, ValueError):
        cap = 0
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO cohorts (company_id,title,description,skills,platform,meeting_url,"
            "starts_at,capacity,status) VALUES (?,?,?,?,?,?,?,?,'pending')",
            (company["id"], title, (d.get("description") or "").strip(),
             clean_text(d.get("skills")), clean_text(d.get("platform")),
             meeting_url, starts_at, max(0, cap)))
        conn.commit()
        cid = cur.lastrowid
    return jsonify({"status": "success", "cohort_id": cid,
                    "message": "Cohort submitted â€” it goes live once an admin approves it."})


# â”€â”€ Cohorts â€” admin queue + review â”€â”€
@app.route("/admin/cohorts")
def admin_cohorts():
    if not require_admin():
        return redirect("/admin-login")
    sf = request.args.get("status", "pending")
    with get_db() as conn:
        q = ("SELECT c.*, co.name AS company_name FROM cohorts c "
             "JOIN companies co ON co.id=c.company_id ")
        if sf in ("pending", "published", "rejected"):
            rows = conn.execute(q + "WHERE c.status=? ORDER BY c.id DESC", (sf,)).fetchall()
        else:
            rows = conn.execute(q + "ORDER BY c.id DESC").fetchall()
        # T5: stat-card counts, independent of the active tab filter above.
        count_rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM cohorts GROUP BY status"
        ).fetchall()
    counts = {"pending": 0, "published": 0, "rejected": 0}
    for r in count_rows:
        if r["status"] in counts:
            counts[r["status"]] = r["n"]
    counts["total"] = sum(counts.values())
    return render_template("admin_cohorts.html",
                           cohorts=[row_to_dict(r) for r in rows], active=sf, counts=counts)


@app.route("/admin/cohorts/<int:cohort_id>/review", methods=["POST"])
def admin_cohort_review(cohort_id):
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    decision = clean_text((request.get_json(silent=True) or request.form).get("decision"))
    if decision not in ("approve", "reject"):
        return jsonify({"status": "error", "message": "decision must be approve|reject"}), 400
    new_status = "published" if decision == "approve" else "rejected"
    with get_db() as conn:
        co = conn.execute(
            "SELECT c.*, comp.name AS company_name FROM cohorts c "
            "JOIN companies comp ON comp.id=c.company_id WHERE c.id=?", (cohort_id,)).fetchone()
        if not co:
            return jsonify({"status": "error", "message": "Not found"}), 404
        co = row_to_dict(co)
        conn.execute("UPDATE cohorts SET status=?, updated_at=datetime('now','localtime') WHERE id=?",
                     (new_status, cohort_id))
        conn.commit()
    if decision == "approve":
        # UAT #36-D: alert the company's followers about the new live cohort.
        _notify_company_followers(
            co["company_id"], f"New cohort from {co['company_name']}",
            f"â€œ{co['title']}â€ is open to join â€” starts {co['starts_at']}.",
            link="/portal#cohorts", kind="cohort")
    return jsonify({"status": "success", "cohort_status": new_status})


# â”€â”€ Cohorts â€” intern side (portal tab) â”€â”€
@app.route("/intern/cohorts")
def intern_cohorts():
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        mine = {r["cohort_id"] for r in conn.execute(
            "SELECT cohort_id FROM cohort_enrollments WHERE intern_id=?", (intern["id"],)).fetchall()}
        rows = [row_to_dict(r) for r in conn.execute(
            "SELECT c.*, co.name AS company_name FROM cohorts c "
            "JOIN companies co ON co.id=c.company_id "
            "WHERE c.status='published' ORDER BY c.starts_at ASC, c.id DESC").fetchall()]
        out = []
        for c in rows:
            enrolled = c["id"] in mine
            out.append({
                "id": c["id"], "title": c["title"], "description": c["description"],
                "skills": c["skills"], "platform": c["platform"], "starts_at": c["starts_at"],
                "company_name": c["company_name"], "company_id": c["company_id"],
                "seats_left": _cohort_seats_left(conn, c),
                "enrolled": enrolled,
                # the meeting link is revealed to enrollees only
                "meeting_url": c["meeting_url"] if enrolled else "",
            })
    return jsonify({"status": "success", "cohorts": out})


@app.route("/cohorts/<int:cohort_id>/enroll", methods=["POST"])
def cohort_enroll(cohort_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        c = conn.execute("SELECT * FROM cohorts WHERE id=? AND status='published'",
                         (cohort_id,)).fetchone()
        if not c:
            return jsonify({"status": "error", "message": "Cohort not found."}), 404
        c = row_to_dict(c)
        already = conn.execute(
            "SELECT 1 FROM cohort_enrollments WHERE cohort_id=? AND intern_id=?",
            (cohort_id, intern["id"])).fetchone()
        if not already:
            seats = _cohort_seats_left(conn, c)
            if seats is not None and seats <= 0:
                return jsonify({"status": "error", "message": "This cohort is full."}), 409
            conn.execute(
                "INSERT OR IGNORE INTO cohort_enrollments (cohort_id, intern_id) VALUES (?,?)",
                (cohort_id, intern["id"]))
            conn.commit()
    add_notification(intern["id"], f"You're in: {c['title']}",
                     f"Joining link: {c['meeting_url']} Â· starts {c['starts_at']}.",
                     kind="cohort", link="/portal#cohorts")
    return jsonify({"status": "success", "meeting_url": c["meeting_url"]})


@app.route("/cron/cohort-reminders", methods=["POST", "GET"])
def cron_cohort_reminders():
    """Send a one-time reminder ~1h before a cohort starts. CRON_SECRET-gated."""
    key = request.headers.get("X-Cron-Key") or request.args.get("key", "")
    if not CRON_SECRET or key != CRON_SECRET:
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    sent = 0
    with get_db() as conn:
        due = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM cohorts WHERE status='published' "
            "AND starts_at > datetime('now','localtime') "
            "AND starts_at <= datetime('now','localtime','+60 minutes')").fetchall()]
        for c in due:
            enrollees = conn.execute(
                "SELECT id, intern_id FROM cohort_enrollments "
                "WHERE cohort_id=? AND reminder_sent=0", (c["id"],)).fetchall()
            for e in enrollees:
                add_notification(
                    e["intern_id"], f"Starting soon: {c['title']}",
                    f"Your cohort starts at {c['starts_at']}. Join: {c['meeting_url']}",
                    kind="cohort", link="/portal#cohorts")
                conn.execute("UPDATE cohort_enrollments SET reminder_sent=1 WHERE id=?", (e["id"],))
                sent += 1
        conn.commit()
    return jsonify({"status": "ok", "reminders_sent": sent})


# â”€â”€ #36-D: intern follows a company â”€â”€
@app.route("/intern/follow/<int:company_id>", methods=["POST"])
def intern_follow_company(company_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM companies WHERE id=? AND is_active=1",
                              (company_id,)).fetchone()
        if not exists:
            return jsonify({"status": "error", "message": "Company not found."}), 404
        conn.execute("INSERT OR IGNORE INTO company_follows (intern_id, company_id) VALUES (?,?)",
                     (intern["id"], company_id))
        conn.commit()
    return jsonify({"status": "success", "following": True})


@app.route("/intern/unfollow/<int:company_id>", methods=["POST"])
def intern_unfollow_company(company_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        conn.execute("DELETE FROM company_follows WHERE intern_id=? AND company_id=?",
                     (intern["id"], company_id))
        conn.commit()
    return jsonify({"status": "success", "following": False})


# â”€â”€ #36-A: public company profile â”€â”€
@app.route("/companies/<slug>")
def company_profile(slug):
    try:
        company_id = int(slug.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        abort(404)
    with get_db() as conn:
        company = conn.execute(
            "SELECT * FROM companies WHERE id=? AND is_active=1", (company_id,)).fetchone()
        if not company:
            abort(404)
        company = row_to_dict(company)
        posts = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM posts WHERE company_id=? AND " + _LIVE_SQL +
            " ORDER BY published_at DESC", (company_id,)).fetchall()]
        cohorts = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM cohorts WHERE company_id=? AND status='published' "
            "ORDER BY starts_at ASC", (company_id,)).fetchall()]
        viewer = current_intern()
        following = False
        if viewer:
            following = conn.execute(
                "SELECT 1 FROM company_follows WHERE intern_id=? AND company_id=?",
                (viewer["id"], company_id)).fetchone() is not None
    return render_template("company_profile.html", company=company, posts=posts,
                           cohorts=cohorts, post_path=_post_path, following=following,
                           viewer=viewer)


# â”€â”€ Â§4: certifications dropdown â€” cached proxy to the tutor's public courses â”€â”€
_COURSES_CACHE = {"at": 0.0, "data": None}
_COURSES_TTL = 600  # ~10 min


def _tutor_courses_cached():
    """Published courses from the tutor (Track 1 Â§5), cached ~10 min.

    Degrades gracefully: on a tutor outage/error, serve the last-good cache (or
    an empty list) so posting never depends on the tutor being up (pitfall Â§9).
    Returns (courses, from_cache)."""
    now = time.time()
    if _COURSES_CACHE["data"] is not None and (now - _COURSES_CACHE["at"]) < _COURSES_TTL:
        return _COURSES_CACHE["data"], True
    try:
        resp = requests.get(f"{TUTOR_BASE_URL}/api/v1/public/courses", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            courses = data.get("courses", []) if isinstance(data, dict) else []
            _COURSES_CACHE["data"] = courses
            _COURSES_CACHE["at"] = now
            return courses, False
        log_error("public-courses", Exception(f"tutor http_{resp.status_code}"))
    except Exception as e:
        log_error("public-courses", e)
    return (_COURSES_CACHE["data"] or []), True  # last-good or empty


def _portal_courses_public():
    """T7: active+approved portal-authored courses (admin or company), shaped like the
    tutor catalogue and tagged source='custom'. Public ids are offset (see
    _PORTAL_COURSE_ID_OFFSET) to stay collision-free with tutor ids."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM courses WHERE content_status='approved' AND is_active=1 ORDER BY id"
        ).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        out.append({
            "id": d["id"] + _PORTAL_COURSE_ID_OFFSET,
            "title": d["title"],
            "slug": d.get("slug") or "",
            "domain": d.get("domain") or "",
            "is_paid": bool(d.get("is_paid")),
            "price_inr": d.get("price_inr") or 0,
            "source": "custom",
            "company_id": d.get("company_id"),
            "industrial_certification": True,  # T7: attribute on approved company-co-signed courses
            # Track 6 / T2: custom/portal-authored courses have no real tutor-side
            # unlock mechanism yet -- a company payment can be marked "verified"
            # with nothing for the intern to actually access. Never let one of
            # these be required as a hiring certification gate until that's built.
            "certifiable": False,
        })
    return out


def _public_courses():
    """Merged catalogue: tutor courses (cached, tagged source='tutor') + active/approved
    portal courses (live read, tagged source='custom'). Returns (courses, from_cache) --
    ``from_cache`` reflects only the tutor half (the portal half is always fresh)."""
    tutor_courses, from_cache = _tutor_courses_cached()
    # Track 6 / T2: only tutor-catalogue courses are certifiable -- they're the
    # only ones with a real, working unlock mechanism. Portal/custom courses are
    # tagged certifiable=False in _portal_courses_public() above.
    tagged_tutor = [dict(c, source=c.get("source") or "tutor", certifiable=True) for c in tutor_courses]
    return tagged_tutor + _portal_courses_public(), from_cache


def _certifiable_course_ids():
    """Set of course ids a company is allowed to require as a hiring certification
    gate (T2 defense-in-depth -- the picker itself is filtered client-side, this
    guards the API directly against a stale form or a manual call)."""
    courses, _ = _public_courses()
    return {c["id"] for c in courses if c.get("certifiable")}


@app.route("/api/public/courses")
def api_public_courses():
    courses, _from_cache = _public_courses()
    return jsonify({"courses": courses})


@app.route("/cron/expire-posts", methods=["POST"])
def cron_expire_posts():
    """Daily cron: flip live posts past their 30-day window to 'expired'.
    Protected by CRON_SECRET (header X-Cron-Key or ?key=), like the other crons."""
    key = request.headers.get("X-Cron-Key") or request.args.get("key", "")
    if not CRON_SECRET or key != CRON_SECRET:
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    with get_db() as conn:
        # Capture which posts expire so we can de-index them (URL_DELETED) below.
        rows = conn.execute(
            "SELECT id, post_type, slug FROM posts WHERE status='published' "
            "AND expires_at IS NOT NULL AND expires_at < datetime('now','localtime')"
        ).fetchall()
        cur = conn.execute(
            "UPDATE posts SET status='expired', updated_at=datetime('now','localtime') "
            "WHERE status='published' AND expires_at IS NOT NULL "
            "AND expires_at < datetime('now','localtime')"
        )
        conn.commit()
    for r in rows:  # de-index each expired post (best-effort, never raises)
        notify_search_engines(_canonical_post_url(r), action="URL_DELETED")
    return jsonify({"status": "ok", "expired": cur.rowcount})


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TRACK 2 Â§7 â€” PUBLIC LISTINGS + DETAIL + SEO + SITEMAP + INSTANT INDEXING
# Canonical domain for every job/internship URL = internship.dbert.online (SITE_ORIGIN).
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
_POSTS_PER_PAGE = 200  # T2: bumped from 20 so client-side filters see the whole
# live result set (currently 74 published posts total) instead of a partial page;
# pagination logic stays in place and will kick back in automatically once volume
# exceeds this.
_LIVE_SQL = "status='published' AND (expires_at IS NULL OR expires_at > datetime('now','localtime'))"

# T1: homepage's one real metric â€” Î£ openings of all live posts Ã— 0.9. Cached briefly
# since the homepage is the highest-traffic page and this is a full-table aggregate.
_OPENINGS_CACHE = {"at": 0.0, "total": 0}
_OPENINGS_TTL = 60


def live_openings_total():
    """Î£ openings across all live posts, discounted Ã—0.9 (never overstate demand)."""
    now = time.time()
    if (now - _OPENINGS_CACHE["at"]) < _OPENINGS_TTL:
        return _OPENINGS_CACHE["total"]
    with get_db() as conn:
        total = conn.execute(
            f"SELECT COALESCE(SUM(openings),0) FROM posts WHERE {_LIVE_SQL}"
        ).fetchone()[0]
    result = int(total * 0.9)
    _OPENINGS_CACHE["at"] = now
    _OPENINGS_CACHE["total"] = result
    return result


def _trust_stats():
    """Wave A: real homepage trust numbers (replaces static hero-stat copy).
    Cheap, read-only aggregates -- no new tables needed."""
    with get_db() as conn:
        interns = conn.execute(
            "SELECT COUNT(*) FROM intern_accounts WHERE signup_stage=3"
        ).fetchone()[0]
        companies = conn.execute(
            "SELECT COUNT(DISTINCT company_id) FROM posts WHERE status='published'"
        ).fetchone()[0]
        avg_row = conn.execute(
            "SELECT AVG(COALESCE(stipend_max, stipend_min)) FROM posts "
            "WHERE status='published' AND (is_unpaid IS NULL OR is_unpaid=0) "
            "AND (stipend_min > 0 OR stipend_max > 0)"
        ).fetchone()
    return {
        "interns": interns,
        "companies": companies,
        "avg_stipend": int(avg_row[0]) if avg_row and avg_row[0] else 0,
    }


def _domain_tile_counts():
    """Live post counts per domain Ã— post_type, for the homepage domain tiles."""
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT domain, post_type, COUNT(*) AS n FROM posts WHERE {_LIVE_SQL} "
            "GROUP BY domain, post_type"
        ).fetchall()
    counts = {d: {"internship": 0, "job": 0} for d in VALID_DOMAINS}
    for r in rows:
        if r["domain"] in counts and r["post_type"] in ("internship", "job"):
            counts[r["domain"]][r["post_type"]] = r["n"]
    return [
        {"domain": d, "internship_count": counts[d]["internship"], "job_count": counts[d]["job"]}
        for d in VALID_DOMAINS
    ]


@app.route("/api/stats/openings")
def api_stats_openings():
    return jsonify({"openings": live_openings_total()})


def _canonical_post_url(post):
    """Absolute canonical URL for a post on the portal origin (for SEO + indexing)."""
    return f"{SITE_ORIGIN}{_post_path(post)}"


def _meta_desc(text, limit=155):
    """Plain-text meta description (~155 chars) from possibly-HTML body copy."""
    plain = re.sub(r"<[^>]+>", " ", text or "")
    plain = re.sub(r"\s+", " ", plain).strip()
    return (plain[: limit - 1].rstrip() + "â€¦") if len(plain) > limit else plain


def _post_completeness_errors(post):
    """T7: Google-for-Jobs completeness gate, enforced before a post can go live.
    Returns a list of human-readable missing/invalid field names (empty = complete)."""
    errors = []
    if not (post.get("title") or "").strip():
        errors.append("title")
    if len((post.get("description") or "").strip()) < 100:
        errors.append("description (minimum 100 characters)")
    work_mode = (post.get("work_mode") or "").strip().lower()
    if work_mode != "remote" and not (post.get("location") or "").strip():
        errors.append("location (or mark the post remote)")
    if not (post.get("apply_by") or "").strip():
        errors.append("apply_by")
    return errors


def _job_posting_jsonld(post, company):
    """schema.org/JobPosting with Google-required + recommended fields."""
    posted = (post.get("published_at") or "").replace(" ", "T")
    through = (post.get("expires_at") or post.get("apply_by") or "").replace(" ", "T")
    ld = {
        "@context": "https://schema.org/",
        "@type": "JobPosting",
        "title": post["title"],
        "description": post.get("description") or post.get("responsibilities") or post["title"],
        "datePosted": posted,
        "employmentType": "INTERN" if post["post_type"] == "internship" else "FULL_TIME",
        "hiringOrganization": {"@type": "Organization", "name": company["name"]},
        "identifier": {"@type": "PropertyValue", "name": company["name"], "value": str(post["id"])},
        "directApply": True,
    }
    if through:
        ld["validThrough"] = through
    if company.get("website"):
        ld["hiringOrganization"]["sameAs"] = company["website"]
    if (post.get("work_mode") or "").lower() == "remote":
        ld["jobLocationType"] = "TELECOMMUTE"
        ld["applicantLocationRequirements"] = {"@type": "Country", "name": "India"}
    else:
        addr = {"@type": "PostalAddress", "addressCountry": "IN"}
        if post.get("location"):
            addr["addressLocality"] = post["location"]
        ld["jobLocation"] = {"@type": "Place", "address": addr}
    if post.get("stipend_min") or post.get("stipend_max"):
        amt = {"@type": "QuantitativeValue",
               "unitText": (post.get("pay_period") or "MONTH").upper()}
        lo, hi = post.get("stipend_min"), post.get("stipend_max")
        if lo and hi:
            amt["minValue"], amt["maxValue"] = lo, hi
        else:
            amt["value"] = lo or hi
        ld["baseSalary"] = {"@type": "MonetaryAmount", "currency": "INR", "value": amt}
    return ld


# â”€â”€ instant indexing (configured-optional; best-effort; NEVER raises) â”€â”€â”€â”€â”€â”€â”€â”€
def _google_indexing_token():
    """OAuth token for the Google Indexing API from the service-account JSON in env.
    Returns None (no-op) if creds/lib absent â€” never raises."""
    if not GOOGLE_INDEXING_SA_JSON:
        return None
    try:
        from google.oauth2 import service_account
        import google.auth.transport.requests as g_requests
        info = json.loads(GOOGLE_INDEXING_SA_JSON)
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/indexing"])
        creds.refresh(g_requests.Request())
        return creds.token
    except Exception as e:
        log_error("google-indexing-auth", e)
        return None


def _ping_google_indexing(url, action):
    token = _google_indexing_token()
    if not token:
        return
    try:
        requests.post(
            "https://indexing.googleapis.com/v3/urlNotifications:publish",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"url": url, "type": action}, timeout=5)
    except Exception as e:
        log_error("google-indexing", e)


def _ping_indexnow(url):
    if not INDEXNOW_KEY:
        return
    try:
        from urllib.parse import urlparse
        host = urlparse(SITE_ORIGIN).netloc
        requests.get("https://api.indexnow.org/indexnow",
                     params={"url": url, "key": INDEXNOW_KEY, "keyLocation": f"{SITE_ORIGIN}/{INDEXNOW_KEY}.txt"},
                     timeout=4)
    except Exception as e:
        log_error("indexnow", e)


def notify_search_engines(url, action="URL_UPDATED"):
    """Best-effort instant-indexing on publish/unpublish/expire (pitfall Â§9 â€” a
    failure or missing creds must NEVER fail the action). action: URL_UPDATED|URL_DELETED."""
    try:
        _ping_google_indexing(url, action)
        _ping_indexnow(url)
    except Exception as e:
        log_error("notify-index", e)


if INDEXNOW_KEY:  # IndexNow ownership proof: host {key}.txt at the site root.
    @app.route(f"/{INDEXNOW_KEY}.txt")
    def _indexnow_keyfile():
        return Response(INDEXNOW_KEY, mimetype="text/plain")


# â”€â”€ public listings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _city_slugify(city):
    """T8: stable, readable slug for a free-text location string, e.g.
    'Bangalore, India' -> 'bangalore-india'. Pure string transform (no DB), so it's
    safe to call on both sides of a lookup."""
    s = re.sub(r"[^a-z0-9\s]", "", (city or "").lower())
    return re.sub(r"\s+", "-", s.strip())


def _render_listings(post_type, location_page=False, city=None, city_slug=None):
    """Shared renderer for the plain catalogue (/jobs, /internships) and the T8
    per-city landing pages (/jobs/<city>, /internships/<city>). ``location_page``
    switches in dynamic long-tail SEO (title/meta/H1/robots) and city-path
    interlinks; the query-string ``?location=`` filter on the plain catalogue still
    works as a non-canonical convenience (T3) but is no longer linked from the UI."""
    domain = clean_text(request.args.get("domain"))
    if domain and domain not in VALID_DOMAINS:
        domain = ""
    location = city or clean_text(request.args.get("location"))
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    where = f"p.post_type=? AND {_LIVE_SQL}"
    params = [post_type]
    if domain:
        where += " AND p.domain=?"
        params.append(domain)
    if location:
        where += " AND p.location=?"
        params.append(location)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT p.*, c.name AS company_name FROM posts p JOIN companies c ON c.id=p.company_id "
            f"WHERE {where} ORDER BY p.published_at DESC LIMIT ? OFFSET ?",
            (*params, _POSTS_PER_PAGE + 1, (page - 1) * _POSTS_PER_PAGE),
        ).fetchall()
        # Interlinking: which OTHER cities currently have live posts (within the active
        # domain filter), each tagged with its own slug for a clean-URL link.
        loc_where = f"post_type=? AND {_LIVE_SQL} AND location != ''"
        loc_params = [post_type]
        if domain:
            loc_where += " AND domain=?"
            loc_params.append(domain)
        if location:
            loc_where += " AND location != ?"
            loc_params.append(location)
        locations = [row_to_dict(r) for r in conn.execute(
            f"SELECT location, COUNT(*) AS n FROM posts WHERE {loc_where} GROUP BY location ORDER BY location",
            loc_params,
        ).fetchall()]
        for loc in locations:
            loc["slug"] = _city_slugify(loc["location"])
        live_count_here = None
        if location_page:
            live_count_here = conn.execute(
                f"SELECT COUNT(*) FROM posts p WHERE p.post_type=? AND p.location=? AND {_LIVE_SQL}",
                (post_type, location),
            ).fetchone()[0]
    posts = [row_to_dict(r) for r in rows[:_POSTS_PER_PAGE]]
    has_next = len(rows) > _POSTS_PER_PAGE
    base_path = "/internships" if post_type == "internship" else "/jobs"
    label = "Internships" if post_type == "internship" else "Jobs"
    listing_base = f"{base_path}/{city_slug}" if location_page else base_path

    page_title = page_h1 = page_meta_description = None
    noindex = False
    if location_page:
        domain_prefix = f"{domain} " if domain else ""
        page_h1 = f"{domain_prefix}{label} in {location} â€” Remote & On-site"
        page_title = f"{page_h1} | DBERT"
        page_meta_description = (
            f"Browse live {domain_prefix}{label.lower()} based in {location}. "
            f"Apply directly to verified companies on DBERT."
        )
        noindex = (live_count_here or 0) < 3

    return render_template(
        "post_listings.html", posts=posts, post_type=post_type, label=label,
        base_path=base_path, listing_base=listing_base, domains=VALID_DOMAINS,
        domain_slugs=DOMAIN_SLUGS,
        active_domain=domain, active_location=location, locations=locations,
        page=page, has_next=has_next, site_origin=SITE_ORIGIN, post_path=_post_path,
        location_page=location_page, city_slug=city_slug,
        page_title=page_title, page_h1=page_h1, page_meta_description=page_meta_description,
        noindex=noindex)


@app.route("/jobs")
def jobs_listing():
    return _render_listings("job")


@app.route("/internships")
def internships_listing():
    return _render_listings("internship")


def _resolve_city_slug(city_slug):
    """T8: reverse a city slug back to its exact stored `posts.location` string
    (any status, so a thin-but-real city still resolves -- noindex, not 404). None
    if no post anywhere uses a location matching that slug."""
    with get_db() as conn:
        rows = conn.execute("SELECT DISTINCT location FROM posts WHERE location != ''").fetchall()
    for r in rows:
        if _city_slugify(r["location"]) == city_slug:
            return r["location"]
    return None


@app.route("/jobs/<city_slug>")
def jobs_by_city(city_slug):
    city = _resolve_city_slug(city_slug)
    if not city:
        abort(404)
    return _render_listings("job", location_page=True, city=city, city_slug=city_slug)


@app.route("/internships/<city_slug>")
def internships_by_city(city_slug):
    city = _resolve_city_slug(city_slug)
    if not city:
        abort(404)
    return _render_listings("internship", location_page=True, city=city, city_slug=city_slug)


# â”€â”€ public detail (SEO + apply CTA + public comments) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _render_post_detail(post_type, slug, post_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT p.*, c.name AS company_name, c.website AS company_website "
            "FROM posts p JOIN companies c ON c.id=p.company_id WHERE p.id=?", (post_id,)
        ).fetchone()
    if not row or row["post_type"] != post_type:
        abort(404)  # never-existed (wrong id or wrong section)
    post = row_to_dict(row)
    if post["status"] == "draft":
        abort(404)  # drafts were never public
    if not _is_live_post(post):
        abort(410)  # expired/unpublished â†’ tell Google to drop it (pitfall Â§9)
    if (post.get("slug") or "post") != slug:  # cosmetic slug drifted â†’ 301 to canonical
        return redirect(_post_path(post), code=301)
    intern = current_intern()
    already_applied = False
    with get_db() as conn:
        conn.execute("UPDATE posts SET views=COALESCE(views,0)+1 WHERE id=?", (post_id,))
        conn.commit()
        # T4: public thread, NOT the private post_applications.comment interest note.
        comments = [row_to_dict(r) for r in conn.execute(
            "SELECT a.name AS intern_name, pc.body, pc.created_at "
            "FROM post_comments pc JOIN intern_accounts a ON a.id=pc.intern_id "
            "WHERE pc.post_id=? ORDER BY pc.id DESC", (post_id,)).fetchall()]
        # UAT #13: render the already-applied state server-side so a revisit shows
        # "Applied âœ“ â€” View in My Applications", not a fresh "Apply Now".
        if intern:
            already_applied = conn.execute(
                "SELECT 1 FROM post_applications WHERE post_id=? AND intern_id=?",
                (post_id, intern["id"]),
            ).fetchone() is not None
        # T3: real "N applied" alongside views â€” the apply-funnel's only social proof,
        # pulled straight from post_applications (never fabricated).
        applied_count = conn.execute(
            "SELECT COUNT(*) FROM post_applications WHERE post_id=?", (post_id,)
        ).fetchone()[0]
        # T3 interlinking: more in the same domain, more in the same city â€” both
        # exclude self and only ever surface other LIVE posts.
        related_posts = [row_to_dict(r) for r in conn.execute(
            f"SELECT id, title, post_type, slug, domain, location, work_mode FROM posts "
            f"WHERE domain=? AND id!=? AND {_LIVE_SQL} ORDER BY published_at DESC LIMIT 4",
            (post["domain"], post_id),
        ).fetchall()]
        city_posts = []
        if post.get("location"):
            city_posts = [row_to_dict(r) for r in conn.execute(
                f"SELECT id, title, post_type, slug, domain, location, work_mode FROM posts "
                f"WHERE location=? AND id!=? AND {_LIVE_SQL} ORDER BY published_at DESC LIMIT 4",
                (post["location"], post_id),
            ).fetchall()]
    company = {"name": post["company_name"], "website": post.get("company_website")}
    certs = []
    try:
        certs = json.loads(post.get("certifications_json") or "[]")
    except Exception:
        certs = []
    jsonld = json.dumps(_job_posting_jsonld(post, company)).replace("</", "<\\/")
    base_path = "/internships" if post_type == "internship" else "/jobs"
    label = "Internships" if post_type == "internship" else "Jobs"
    breadcrumbs = [
        ("Home", "/"), (label, base_path),
        (post["domain"], f"{base_path}?domain={quote(post['domain'])}"),
    ]
    return render_template(
        "post_detail.html", post=post, company=company, comments=comments, certs=certs,
        jsonld=jsonld, canonical=_canonical_post_url(post),
        meta_desc=_meta_desc(post.get("description")), is_intern=bool(intern),
        intern_email=(intern or {}).get("email", ""),
        already_applied=already_applied, my_apps_url="/portal#myapplications",
        tutor_base=TUTOR_BASE_URL, og_image=OG_IMAGE_URL,
        applied_count=applied_count, related_posts=related_posts, city_posts=city_posts,
        breadcrumbs=breadcrumbs, base_path=base_path, post_path=_post_path)


@app.route("/jobs/<slug>-<int:post_id>")
def job_detail(slug, post_id):
    return _render_post_detail("job", slug, post_id)


@app.route("/internships/<slug>-<int:post_id>")
def internship_detail(slug, post_id):
    return _render_post_detail("internship", slug, post_id)


@app.route("/jobs/<int:post_id>")
@app.route("/internships/<int:post_id>")
def post_detail_no_slug(post_id):
    """Slugless deep link â†’ 301 to the canonical <slug>-<id> URL (or 404/410)."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not row:
        abort(404)
    post = row_to_dict(row)
    if post["status"] == "draft":
        abort(404)
    if not _is_live_post(post):
        abort(410)
    return redirect(_post_path(post), code=301)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TRACK 2 Â§3 â€” APPLY (CTA + required comment) + funnel + applicants
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Track 2 Â§B (UAT #4): "Selected - Pending Certifications" lets a company select an
# applicant who lacks the post's required certs, with a "complete these" message
# delivered to the intern (My Applications tab + push + email).
APP_STATUS_PENDING_CERTS = "Selected - Pending Certifications"
APPLICATION_STATUSES = ("Applied", "Shortlisted", "Rejected", "Hired", APP_STATUS_PENDING_CERTS)


def _post_path(post):
    """Canonical detail path for a post (jobs/ or internships/) â€” <slug>-<id>."""
    base = "internships" if post["post_type"] == "internship" else "jobs"
    return f"/{base}/{(post['slug'] or 'post')}-{post['id']}"


def _post_required_certs(post):
    """Parse a post's certifications_json into a clean [{course_id:int, title:str}].
    Tolerant of bad/empty JSON (returns [])."""
    try:
        raw = json.loads(post.get("certifications_json") or "[]")
    except (ValueError, TypeError):
        return []
    out = []
    for c in raw if isinstance(raw, list) else []:
        if not isinstance(c, dict):
            continue
        cid = c.get("course_id")
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        out.append({"course_id": cid, "title": c.get("title") or "Certification"})
    return out


def _safe_portal_next(raw):
    """Sanitise a post-login resume target to a RELATIVE portal path (no open
    redirect): must start with a single '/', no scheme/host."""
    raw = (raw or "").strip()
    if raw.startswith("/") and not raw.startswith("//") and "://" not in raw:
        return raw
    return None


def _is_live_post(post):
    if post["status"] != "published":
        return False
    exp = post["expires_at"]
    if exp:
        with get_db() as conn:
            still = conn.execute(
                "SELECT ? > datetime('now','localtime')", (exp,)
            ).fetchone()[0]
        return bool(still)
    return True


@app.route("/apply/<int:post_id>")
def apply_entry(post_id):
    """Apply-Now entry. Logged-in â†’ post detail with the apply modal open.
    Logged-out (acquisition funnel) â†’ stash the post URL in session['next'] and
    send to the normal intern signup; resume after login (pitfall Â§9)."""
    with get_db() as conn:
        post = conn.execute("SELECT id, slug, post_type FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        abort(404)
    dest = _post_path(post) + "?apply=1"
    if current_intern():
        return redirect(dest)
    nxt = _safe_portal_next(dest)
    if nxt:
        session["next"] = nxt
    return redirect("/signup")


@app.route("/posts/<int:post_id>/apply", methods=["POST"])
def post_apply(post_id):
    with get_db() as conn:
        post = conn.execute(
            "SELECT p.*, c.name AS company_name FROM posts p JOIN companies c ON c.id = p.company_id "
            "WHERE p.id=?", (post_id,)
        ).fetchone()
    if not post:
        return jsonify({"status": "error", "message": "Not found"}), 404
    intern = current_intern()
    if not intern:
        # Front-end uses this to route through signup, then resume at `next`.
        return jsonify({"status": "login_required", "next": _post_path(post)}), 401
    if not _is_live_post(post):
        return jsonify({"status": "error", "message": "This post is no longer accepting applications."}), 400
    data = request.get_json(force=True, silent=True) or {}
    comment = (data.get("comment") or "").strip()
    if not comment:
        return jsonify({"status": "error", "message": "A comment is required to apply."}), 400
    with get_db() as conn:
        cv = conn.execute("SELECT id FROM cvs WHERE intern_id=?", (intern["id"],)).fetchone()
        cv_id = cv["id"] if cv else None  # CV is OPTIONAL â€” never block on a missing one
        is_new = conn.execute(
            "SELECT 1 FROM post_applications WHERE post_id=? AND intern_id=?", (post_id, intern["id"])
        ).fetchone() is None

        # UP6.1: Cert-Gated Job Application Intercept
        flag_cert_gate = get_config("FLAG_CERT_GATE", "0") == "1"
        app_status = "Applied"
        missing_cert_course_id = None

        if flag_cert_gate:
            req_course = conn.execute(
                "SELECT id, title FROM courses WHERE company_id = ? AND requires_project = 1 LIMIT 1",
                (post["company_id"],)
            ).fetchone()
            
            if req_course:
                has_cert = conn.execute(
                    "SELECT id FROM intern_certificates WHERE intern_id = ? AND course_id = ? AND tier = 'dbert_verified'",
                    (intern["id"], req_course["id"])
                ).fetchone()

                if not has_cert:
                    app_status = "PENDING_CERTS"
                    missing_cert_course_id = req_course["id"]

        conn.execute(
            "INSERT INTO post_applications (post_id, intern_id, comment, cv_id, status, created_at) "
            "VALUES (?,?,?,?, ?, ?) "
            "ON CONFLICT(post_id, intern_id) DO UPDATE SET comment=excluded.comment, cv_id=excluded.cv_id, status=excluded.status",
            (post_id, intern["id"], comment, cv_id, app_status, now_str()),
        )
        conn.commit()
    if is_new:  # T10: confirmation notice -- only on the first apply, not on a comment-edit re-submit
        try:
            notify_post_application_received(intern["name"], intern["email"], post["title"], post["company_name"])
        except Exception as e:
            log_error("post-apply-notify", e)
    return jsonify({
        "status": "success", "has_cv": cv_id is not None,
        "cv_hint": None if cv_id else "Add a CV to strengthen your application.",
    })


@app.route("/posts/<int:post_id>/comments")
def post_comments(post_id):
    """T4: public comment thread (post_comments) â€” any signed-up intern, no
    application required. Distinct from post_applications.comment, which stays
    a private company-only interest note and is never rendered here."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT a.name AS intern_name, pc.body, pc.created_at "
            "FROM post_comments pc JOIN intern_accounts a ON a.id = pc.intern_id "
            "WHERE pc.post_id=? ORDER BY pc.id DESC",
            (post_id,),
        ).fetchall()
    return jsonify({"comments": [row_to_dict(r) for r in rows]})


@app.route("/posts/<int:post_id>/comment", methods=["POST"])
def post_comment_add(post_id):
    """T4: any signed-up intern can post a public comment on a post without
    applying. Rate-limited per IP + per intern; length-validated; escaped at
    render (Jinja auto-escapes {{ }}; the JS renderer uses escHtml)."""
    with get_db() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        return jsonify({"status": "error", "message": "Not found"}), 404
    post = row_to_dict(post)
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Please sign in to comment."}), 401
    ip = get_client_ip()
    allowed, ra = rate_check(f"comment:ip:{ip}", *RL_COMMENT_IP)
    if not allowed:
        return too_many(ra)
    allowed, ra = rate_check(f"comment:intern:{intern['id']}", *RL_COMMENT_INTERN)
    if not allowed:
        return too_many(ra)
    data = request.get_json(force=True, silent=True) or {}
    body = clean_text(data.get("body"))
    if len(body) < 2 or len(body) > 1000:
        return jsonify({"status": "error", "message": "Comment must be 2â€“1000 characters."}), 400
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO post_comments (post_id, intern_id, body) VALUES (?, ?, ?)",
            (post_id, intern["id"], body),
        )
        conn.commit()
        comment_id = cur.lastrowid
        # T10: notify every OTHER applicant on this post -- they're "in the thread"
        # because they applied. Never notify the commenter about their own comment.
        other_applicants = [row_to_dict(r) for r in conn.execute(
            "SELECT DISTINCT a.name, a.email FROM post_applications pa "
            "JOIN intern_accounts a ON a.id = pa.intern_id "
            "WHERE pa.post_id=? AND pa.intern_id!=?", (post_id, intern["id"])
        ).fetchall()]
    for applicant in other_applicants:
        try:
            notify_post_comment_reply(applicant["name"], applicant["email"], post["title"], _post_path(post))
        except Exception as e:
            log_error("post-comment-notify", e)
    return jsonify({
        "status": "success",
        "comment": {"id": comment_id, "intern_name": intern["name"], "body": body, "created_at": now_str()},
    })


@app.route("/company/posts/<int:post_id>/applicants")
def company_applicants(post_id):
    company = current_company()
    if not company:
        return redirect("/company/login")
    with get_db() as conn:
        post = conn.execute(
            "SELECT * FROM posts WHERE id=? AND company_id=?", (post_id, company["id"])
        ).fetchone()
        if not post:
            abort(404)
        apps = conn.execute(
            "SELECT pa.id, pa.intern_id, pa.comment, pa.status, pa.created_at, pa.cv_id, "
            "pa.needed_certs_json, pa.decision_note, "
            "a.name AS intern_name, a.email AS intern_email, c.slug AS cv_slug "
            "FROM post_applications pa JOIN intern_accounts a ON a.id = pa.intern_id "
            "LEFT JOIN cvs c ON c.id = pa.cv_id "
            "WHERE pa.post_id=? ORDER BY pa.id DESC",
            (post_id,),
        ).fetchall()
        post_d = row_to_dict(post)
        required_certs = _post_required_certs(post_d)
        req_ids = {c["course_id"] for c in required_certs}
        applicants = []
        for r in apps:
            ad = row_to_dict(r)
            earned = conn.execute(
                "SELECT course_id, course_title FROM intern_certificates WHERE intern_id=?",
                (ad["intern_id"],),
            ).fetchall()
            earned_ids = {e["course_id"] for e in earned}
            ad["earned_certs"] = [
                {"course_id": e["course_id"], "title": e["course_title"]} for e in earned
            ]
            # Missing = the post's required certs this applicant has NOT earned.
            ad["missing_certs"] = [c for c in required_certs if c["course_id"] not in earned_ids]
            # T5: surface the candidate's interview state + anti-copy telemetry for this post.
            iv_row = conn.execute(
                "SELECT status, attempt_no, time_taken_sec, tab_switches, completed_at FROM interviews "
                "WHERE email=? AND post_id=? ORDER BY id DESC LIMIT 1",
                (ad["intern_email"], post_id),
            ).fetchone()
            ad["interview"] = row_to_dict(iv_row) if iv_row else None
            applicants.append(ad)
    return render_template("company_applicants.html", post=post_d,
                           applicants=applicants, required_certs=required_certs,
                           statuses=APPLICATION_STATUSES,
                           pending_certs_status=APP_STATUS_PENDING_CERTS)


@app.route("/company/applications/<int:app_id>/status", methods=["POST"])
def company_app_status(app_id):
    company = current_company()
    if not company:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    new_status = clean_text(data.get("status"))
    if new_status not in APPLICATION_STATUSES:
        return jsonify({"status": "error", "message": "Invalid status."}), 400

    is_cert_gate = new_status == APP_STATUS_PENDING_CERTS
    needed_certs = []
    note = clean_text(data.get("note")) if is_cert_gate else ""
    notify = None  # (name, email, post_title, company_name, needed_certs, note) â€” sent after commit
    with get_db() as conn:
        row = conn.execute(
            "SELECT pa.id, pa.status AS old_status, pa.intern_id, p.title AS post_title, "
            "p.certifications_json, a.name AS intern_name, a.email AS intern_email "
            "FROM post_applications pa JOIN posts p ON p.id = pa.post_id "
            "JOIN intern_accounts a ON a.id = pa.intern_id "
            "WHERE pa.id=? AND p.company_id=?", (app_id, company["id"]),
        ).fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Not found"}), 404
        r = row_to_dict(row)
        if is_cert_gate:
            # Auto-detect missing = (post required âˆ’ intern earned); the company may
            # override via the request body (editable list of {course_id,title}).
            if isinstance(data.get("needed_certs"), list):
                needed_certs = _post_required_certs({"certifications_json":
                                                     json.dumps(data["needed_certs"])})
                # Track 6 / T2: defense-in-depth -- the picker in post_form.html is
                # filtered to certifiable courses already, but never trust that
                # alone; drop anything that isn't actually certifiable here too.
                certifiable_ids = _certifiable_course_ids()
                needed_certs = [c for c in needed_certs if c["course_id"] in certifiable_ids]
            else:
                required = _post_required_certs({"certifications_json": r["certifications_json"]})
                certifiable_ids = _certifiable_course_ids()
                required = [c for c in required if c["course_id"] in certifiable_ids]
                earned_ids = {e["course_id"] for e in conn.execute(
                    "SELECT course_id FROM intern_certificates WHERE intern_id=?",
                    (r["intern_id"],)).fetchall()}
                needed_certs = [c for c in required if c["course_id"] not in earned_ids]
            # Track 6 / T3: a Pending-Certifications transition with zero certs
            # attached was a silent dead end for the intern -- no action, no
            # timeline, just "check with the company" forever. If a company
            # genuinely needs no certification, Hired is the correct status
            # instead; this rejects the empty-cert case rather than saving it.
            if not needed_certs:
                return jsonify({"status": "error", "message":
                    "Select at least one required certification, or choose "
                    "Hired instead if none are needed for this role."}), 400
            conn.execute(
                "UPDATE post_applications SET status=?, needed_certs_json=?, decision_note=?, "
                "decided_at=?, notified_at=? WHERE id=?",
                (new_status, json.dumps(needed_certs), note, now_str(), now_str(), app_id),
            )
        else:
            conn.execute("UPDATE post_applications SET status=?, decided_at=? WHERE id=?",
                         (new_status, now_str(), app_id))
        conn.commit()
        # Notify only on an actual transition.
        if r["old_status"] != new_status:
            if is_cert_gate:
                notify = (r["intern_name"], r["intern_email"], r["post_title"],
                          company["name"], needed_certs, note)
            elif new_status in ("Shortlisted", "Hired", "Rejected"):
                notify = (r["intern_name"], r["intern_email"], r["post_title"],
                          company["name"], new_status)

    if notify:
        try:
            if is_cert_gate:
                send_post_selection_email(*notify)  # email + push (both best-effort)
            else:
                notify_post_status_change(*notify)  # T10: Shortlisted/Hired/Rejected
        except Exception as e:
            log_error("post-selection-notify", e)
    return jsonify({"status": "success", "application_status": new_status,
                    "needed_certs": needed_certs})


# â”€â”€ Admin: companies section (list + approve/suspend) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/admin/companies")
def admin_companies():
    if not require_admin():
        return redirect("/admin-login")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    with get_db() as conn:
        pagination = paginate(
            conn,
            "SELECT * FROM companies ORDER BY is_approved ASC, id DESC",
            page=page,
            per_page=per_page
        )
    return render_template("admin_companies.html", companies=pagination["items"], pagination=pagination)


@app.route("/admin/companies/approve", methods=["POST"])
def admin_company_approve():
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    cid = data.get("company_id")
    approve = 1 if data.get("approve", True) else 0
    with get_db() as conn:
        conn.execute("UPDATE companies SET is_approved=?, updated_at=? WHERE id=?",
                     (approve, now_str(), cid))
        conn.commit()
    return jsonify({"status": "success", "is_approved": approve})


@app.route("/admin/companies/suspend", methods=["POST"])
def admin_company_suspend():
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    cid = data.get("company_id")
    active = 0 if data.get("suspend", True) else 1
    with get_db() as conn:
        conn.execute("UPDATE companies SET is_active=?, updated_at=? WHERE id=?",
                     (active, now_str(), cid))
        conn.commit()
    return jsonify({"status": "success", "is_active": active})


# â”€â”€ Admin: company-uploaded interview question moderation (T6) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/admin/post-questions")
def admin_post_questions():
    """Default to pending (the moderation queue); ?status=approved|rejected to review history."""
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    status = clean_text(request.args.get("status")) or "pending"
    if status not in ("pending", "approved", "rejected"):
        status = "pending"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT pq.id, pq.post_id, pq.text, pq.status, pq.sort_order, pq.created_at, "
            "p.title AS post_title, c.name AS company_name "
            "FROM post_questions pq JOIN posts p ON p.id = pq.post_id "
            "JOIN companies c ON c.id = pq.company_id "
            "WHERE pq.status=? ORDER BY pq.id DESC", (status,)
        ).fetchall()
    return jsonify({"status": "success", "questions": [row_to_dict(r) for r in rows]})


@app.route("/admin/post-questions/<int:question_id>/review", methods=["POST"])
def admin_post_question_review(question_id):
    if not require_admin():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    decision = clean_text(data.get("decision"))
    if decision not in ("approve", "reject"):
        return jsonify({"status": "error", "message": "decision must be approve or reject."}), 400
    new_status = "approved" if decision == "approve" else "rejected"
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE post_questions SET status=? WHERE id=?", (new_status, question_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "success", "id": question_id, "question_status": new_status})


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TRACK 2 Â§5 â€” UNIFIED MESSAGING (inbox + threads, text-only v1)
# Permissions enforced on CREATE *and* SEND (pitfall Â§9): internâ†”company only with
# a backing application; internâ†”mentor ok; internâ†”admin always; NEVER internâ†”intern.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
MSG_COUNTERPARTIES = ("mentor", "admin", "company")
_ADMIN_CP_ID = 0          # admin is a singleton realm
MAX_MSG_CHARS = 4000


def _msg_actor():
    """The current participant across all realms, or None. Returns
    {role, id, name, sender_type} (role == sender_type for messaging)."""
    intern = current_intern()
    if intern:
        return {"role": "intern", "id": intern["id"], "name": intern.get("name") or "Intern", "sender_type": "intern"}
    company = current_company()
    if company:
        return {"role": "company", "id": company["id"], "name": company.get("name") or "Company", "sender_type": "company"}
    mentor = current_mentor()
    if mentor:
        return {"role": "mentor", "id": mentor["id"], "name": mentor.get("name") or "Mentor", "sender_type": "mentor"}
    if require_admin():
        return {"role": "admin", "id": _ADMIN_CP_ID, "name": "DBERT Team", "sender_type": "admin"}
    return None


def _intern_company_linked(conn, intern_id, company_id):
    """True iff the intern has applied to any of the company's posts (the backing
    relationship that authorises an internâ†”company thread)."""
    return conn.execute(
        "SELECT 1 FROM post_applications pa JOIN posts p ON p.id=pa.post_id "
        "WHERE pa.intern_id=? AND p.company_id=? LIMIT 1", (intern_id, company_id)
    ).fetchone() is not None


def _can_converse(conn, intern_id, cp_type, cp_id):
    """Relationship gate. cp_type MUST be in MSG_COUNTERPARTIES so 'intern' is
    rejected â†’ internâ†”intern is impossible by construction."""
    if cp_type == "admin":
        return True
    if cp_type == "mentor":
        return conn.execute("SELECT 1 FROM mentors WHERE id=? AND is_active=1", (cp_id,)).fetchone() is not None
    if cp_type == "company":
        return _intern_company_linked(conn, intern_id, cp_id)
    return False


def _actor_in_conversation(conv, actor):
    if actor["role"] == "intern":
        return conv["intern_id"] == actor["id"]
    if actor["role"] == "admin":
        return conv["counterparty_type"] == "admin"
    return conv["counterparty_type"] == actor["role"] and conv["counterparty_id"] == actor["id"]


def _conversation_label(conn, conv, actor):
    """Display name of the OTHER party, from the actor's perspective."""
    if actor["role"] == "intern":
        ct, cid = conv["counterparty_type"], conv["counterparty_id"]
        if ct == "admin":
            return "DBERT Team"
        tbl = "mentors" if ct == "mentor" else "companies"
        r = conn.execute(f"SELECT name FROM {tbl} WHERE id=?", (cid,)).fetchone()
        return r["name"] if r else ct.capitalize()
    r = conn.execute("SELECT name FROM intern_accounts WHERE id=?", (conv["intern_id"],)).fetchone()
    return r["name"] if r else "Intern"


def _get_or_create_conversation(conn, intern_id, cp_type, cp_id, post_id):
    conn.execute(
        "INSERT OR IGNORE INTO conversations (intern_id, counterparty_type, counterparty_id, post_id) "
        "VALUES (?,?,?,?)", (intern_id, cp_type, cp_id, post_id))
    return conn.execute(
        "SELECT id FROM conversations WHERE intern_id=? AND counterparty_type=? AND counterparty_id=? AND post_id=?",
        (intern_id, cp_type, cp_id, post_id)).fetchone()["id"]


def _msg_inbox_rows(conn, actor):
    if actor["role"] == "intern":
        convs = conn.execute("SELECT * FROM conversations WHERE intern_id=? ORDER BY updated_at DESC",
                             (actor["id"],)).fetchall()
    elif actor["role"] == "admin":
        convs = conn.execute("SELECT * FROM conversations WHERE counterparty_type='admin' ORDER BY updated_at DESC").fetchall()
    else:
        convs = conn.execute("SELECT * FROM conversations WHERE counterparty_type=? AND counterparty_id=? ORDER BY updated_at DESC",
                             (actor["role"], actor["id"])).fetchall()
    rows = []
    for c in convs:
        last = conn.execute("SELECT body FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1", (c["id"],)).fetchone()
        unread = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE conversation_id=? AND is_read=0 AND sender_type!=?",
            (c["id"], actor["sender_type"])).fetchone()[0]
        rows.append({"id": c["id"], "label": _conversation_label(conn, c, actor),
                     "last": last["body"] if last else "", "unread": unread})
    return rows


def _intern_mentor_id(conn, intern_id):
    """The intern's assigned mentor id (via their latest application's mentor_email)."""
    r = conn.execute(
        "SELECT m.id FROM applications a JOIN mentors m ON m.email=a.mentor_email "
        "WHERE a.email=(SELECT email FROM intern_accounts WHERE id=?) AND m.is_active=1 "
        "ORDER BY a.id DESC LIMIT 1", (intern_id,)).fetchone()
    return r["id"] if r else None


@app.route("/messages")
@app.route("/portal/messages")
def messages_inbox():
    actor = _msg_actor()
    if not actor:
        return redirect("/#signin")
    # UAT #23: interns use the in-shell Messages tab; deep-link them into it.
    if actor["role"] == "intern":
        return redirect("/portal#messages")
    start_targets = []
    with get_db() as conn:
        rows = _msg_inbox_rows(conn, actor)
        if actor["role"] == "intern":
            start_targets.append({"type": "admin", "id": _ADMIN_CP_ID, "label": "DBERT Team"})
            mid = _intern_mentor_id(conn, actor["id"])
            if mid:
                start_targets.append({"type": "mentor", "id": mid, "label": "My mentor"})
    return render_template("messages_inbox.html", actor=actor, conversations=rows, start_targets=start_targets)


@app.route("/messages/start", methods=["POST"])
@app.route("/portal/messages/start", methods=["POST"])
def messages_start():
    actor = _msg_actor()
    if not actor:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    post_id = _int_or_none(data.get("post_id")) or 0
    if actor["role"] == "intern":
        cp_type = clean_text(data.get("counterparty_type"))
        cp_id = _int_or_none(data.get("counterparty_id")) or 0
        if cp_type not in MSG_COUNTERPARTIES:
            return jsonify({"status": "error", "message": "Invalid recipient."}), 400
        if cp_type == "admin":
            cp_id = _ADMIN_CP_ID
        intern_id = actor["id"]
    else:  # company / mentor / admin initiating to an intern
        cp_type, cp_id = actor["role"], actor["id"]
        intern_id = _int_or_none(data.get("intern_id")) or 0
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM intern_accounts WHERE id=?", (intern_id,)).fetchone():
            return jsonify({"status": "error", "message": "Unknown intern."}), 400
        if not _can_converse(conn, intern_id, cp_type, cp_id):
            return jsonify({"status": "error", "message": "You can't message this user."}), 403
        conv_id = _get_or_create_conversation(conn, intern_id, cp_type, cp_id, post_id)
        conn.commit()
    return jsonify({"status": "success", "conversation_id": conv_id})


@app.route("/messages/<int:conv_id>")
@app.route("/portal/messages/<int:conv_id>")
def messages_thread(conv_id):
    actor = _msg_actor()
    if not actor:
        return redirect("/#signin")
    with get_db() as conn:
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conv_id,)).fetchone()
        if not conv or not _actor_in_conversation(conv, actor):
            abort(404)
        msgs = [row_to_dict(m) for m in conn.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC", (conv_id,)).fetchall()]
        conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_type!=?",
                     (conv_id, actor["sender_type"]))
        conn.commit()
        label = _conversation_label(conn, conv, actor)
    return render_template("messages_thread.html", actor=actor, conv_id=conv_id, label=label, messages=msgs)


@app.route("/messages/<int:conv_id>/send", methods=["POST"])
@app.route("/portal/messages/<int:conv_id>/send", methods=["POST"])
def messages_send(conv_id):
    actor = _msg_actor()
    if not actor:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"status": "error", "message": "Message is empty."}), 400
    body = body[:MAX_MSG_CHARS]
    with get_db() as conn:
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conv_id,)).fetchone()
        if not conv or not _actor_in_conversation(conv, actor):
            return jsonify({"status": "error", "message": "Not found"}), 404
        # Re-validate the backing relationship on EVERY send (pitfall Â§9) â€” e.g. an
        # internâ†”company thread must still have a backing application.
        if not _can_converse(conn, conv["intern_id"], conv["counterparty_type"], conv["counterparty_id"]):
            return jsonify({"status": "error", "message": "This conversation is no longer permitted."}), 403
        conn.execute("INSERT INTO messages (conversation_id, sender_type, sender_id, body) VALUES (?,?,?,?)",
                     (conv_id, actor["sender_type"], actor["id"], body))
        conn.execute("UPDATE conversations SET updated_at=datetime('now','localtime') WHERE id=?", (conv_id,))
        conn.commit()
        m = row_to_dict(conn.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1", (conv_id,)).fetchone())
    return jsonify({"status": "success", "message_obj": {
        "id": m["id"], "body": m["body"], "sender_type": m["sender_type"], "created_at": m["created_at"]}})


@app.route("/messages/<int:conv_id>/poll")
@app.route("/portal/messages/<int:conv_id>/poll")
def messages_poll(conv_id):
    actor = _msg_actor()
    if not actor:
        return jsonify({"status": "error"}), 401
    after = _int_or_none(request.args.get("after")) or 0
    with get_db() as conn:
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conv_id,)).fetchone()
        if not conv or not _actor_in_conversation(conv, actor):
            return jsonify({"status": "error"}), 404
        rows = [row_to_dict(m) for m in conn.execute(
            "SELECT id, sender_type, body, created_at FROM messages "
            "WHERE conversation_id=? AND id>? ORDER BY id ASC", (conv_id, after)).fetchall()]
        conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_type!=? AND id>?",
                     (conv_id, actor["sender_type"], after))
        conn.commit()
    return jsonify({"status": "success", "messages": rows})


# â”€â”€ UAT #23: JSON for the in-shell Messages tab (portal.html). Reuses the same
# service + permission gates as the standalone pages; send/poll/start are already
# JSON and are reused as-is by the tab. â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/intern/messages")
def intern_messages_json():
    actor = _msg_actor()
    if not actor:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        rows = _msg_inbox_rows(conn, actor)
        start_targets = []
        if actor["role"] == "intern":
            start_targets.append({"type": "admin", "id": _ADMIN_CP_ID, "label": "DBERT Team"})
            mid = _intern_mentor_id(conn, actor["id"])
            if mid:
                start_targets.append({"type": "mentor", "id": mid, "label": "My mentor"})
    return jsonify({"status": "success", "conversations": rows,
                    "start_targets": start_targets, "my_sender_type": actor["sender_type"]})


@app.route("/intern/messages/<int:conv_id>")
def intern_messages_thread_json(conv_id):
    actor = _msg_actor()
    if not actor:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conv_id,)).fetchone()
        if not conv or not _actor_in_conversation(conv, actor):
            return jsonify({"status": "error", "message": "Not found"}), 404
        msgs = [{"id": m["id"], "body": m["body"], "sender_type": m["sender_type"],
                 "created_at": m["created_at"]}
                for m in conn.execute(
                    "SELECT id, body, sender_type, created_at FROM messages "
                    "WHERE conversation_id=? ORDER BY id ASC", (conv_id,)).fetchall()]
        conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_type!=?",
                     (conv_id, actor["sender_type"]))
        conn.commit()
        label = _conversation_label(conn, conv, actor)
    return jsonify({"status": "success", "conversation_id": conv_id, "label": label,
                    "messages": msgs, "my_sender_type": actor["sender_type"]})


# â”€â”€ UAT #26: Notifications tab â€” list + mark read â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/intern/notifications")
def intern_notifications():
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        rows = [row_to_dict(r) for r in conn.execute(
            "SELECT id, kind, title, body, link, is_read, created_at FROM notifications "
            "WHERE intern_id=? ORDER BY id DESC LIMIT 100", (intern["id"],)).fetchall()]
    unread = sum(1 for r in rows if not r["is_read"])
    return jsonify({"status": "success", "notifications": rows, "unread": unread})


@app.route("/intern/notifications/<int:notif_id>/read", methods=["POST"])
def intern_notification_read(notif_id):
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND intern_id=?",
                     (notif_id, intern["id"]))
        conn.commit()
    return jsonify({"status": "success"})


@app.route("/intern/notifications/read-all", methods=["POST"])
def intern_notifications_read_all():
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE intern_id=? AND is_read=0",
                     (intern["id"],))
        conn.commit()
    return jsonify({"status": "success"})


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TRACK 2 Â§6 â€” CV BUILDER (public page + PDF)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def current_intern():
    """The logged-in, active intern_accounts row (session role='intern') or None."""
    user = require_role("intern")
    if not user:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (user["email"],)
        ).fetchone()
    return row_to_dict(row) if row else None


def _cv_slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:40] or "cv"


def _cv_json_list(raw):
    try:
        v = json.loads(raw) if raw else []
        return v if isinstance(v, list) else []
    except Exception:
        return []


def _cv_lines_to_list(text):
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def _cv_skills_to_list(text):
    return [s.strip() for s in re.split(r"[,\n]", text or "") if s.strip()]


def _cv_entries(raw):
    """UAT #28: normalize experience/education JSON â†’ list of
    {title, org, dates, bullets:[]}. Tolerates legacy list-of-strings
    (each becomes a title-only entry) so old CVs keep rendering."""
    out = []
    for item in _cv_json_list(raw):
        if isinstance(item, str):
            if item.strip():
                out.append({"title": item.strip(), "org": "", "dates": "", "bullets": []})
        elif isinstance(item, dict):
            title = (item.get("title") or "").strip()
            org = (item.get("org") or "").strip()
            dates = (item.get("dates") or "").strip()
            bullets = [b.strip() for b in (item.get("bullets") or [])
                       if isinstance(b, str) and b.strip()]
            if title or org or bullets:
                out.append({"title": title, "org": org, "dates": dates, "bullets": bullets})
    return out


def _cv_clean_entries(raw):
    """UAT #28: sanitize POSTed experience/education for storage. Accepts the new
    structured shape (list of {title,org,dates,bullets}) AND legacy free-text
    (a string or list of strings â†’ each line becomes a title-only entry)."""
    if isinstance(raw, str):
        return [{"title": ln, "org": "", "dates": "", "bullets": []}
                for ln in _cv_lines_to_list(raw)]
    out = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                if item.strip():
                    out.append({"title": item.strip(), "org": "", "dates": "", "bullets": []})
                continue
            if not isinstance(item, dict):
                continue
            title = clean_text(item.get("title"))
            org = clean_text(item.get("org"))
            dates = clean_text(item.get("dates"))
            bullets = [clean_text(b) for b in (item.get("bullets") or [])
                       if isinstance(b, str) and clean_text(b)]
            if title or org or bullets:
                out.append({"title": title, "org": org, "dates": dates, "bullets": bullets})
    return out


def _cv_render_ctx(cv, intern_row, certs):
    """Shared context for the public CV page + its PDF (parsed JSON â†’ lists)."""
    return {
        "cv": cv,
        "intern": row_to_dict(intern_row) if intern_row else {},
        "headline": cv.get("headline") or "",
        "summary": cv.get("summary") or "",
        "skills": _cv_json_list(cv.get("skills_json")),
        "projects": _cv_json_list(cv.get("projects_json")),
        "experience": _cv_entries(cv.get("experience_json")),   # UAT #28: structured
        "education": _cv_entries(cv.get("education_json")),      # UAT #28: structured
        "links": _cv_json_list(cv.get("links_json")),
        "certs": certs,
    }


def _load_public_cv(slug):
    """Fetch (cv, intern_row, certs) for a slug, enforcing is_public. Returns
    None if missing or private-to-someone-else (caller â†’ 404)."""
    with get_db() as conn:
        cv_row = conn.execute("SELECT * FROM cvs WHERE slug=?", (slug,)).fetchone()
        if not cv_row:
            return None
        cv = row_to_dict(cv_row)
        intern_row = conn.execute(
            "SELECT id,name,email,phone,city,college,course,domain FROM intern_accounts WHERE id=?",
            (cv["intern_id"],),
        ).fetchone()
        certs = [row_to_dict(r) for r in conn.execute(
            "SELECT course_title, cert_id, issued_at, url FROM intern_certificates "
            "WHERE intern_id=? ORDER BY issued_at DESC, id DESC",
            (cv["intern_id"],),
        ).fetchall()]
    if not cv["is_public"]:
        viewer = current_intern()
        if not viewer or viewer["id"] != cv["intern_id"]:
            return None
    return cv, intern_row, certs


@app.route("/portal/cv", methods=["GET"])
def portal_cv_editor():
    intern = current_intern()
    if not intern:
        return redirect("/portal")
    with get_db() as conn:
        cv_row = conn.execute("SELECT * FROM cvs WHERE intern_id=?", (intern["id"],)).fetchone()
    cv = row_to_dict(cv_row) if cv_row else None
    form = {
        "headline":   (cv or {}).get("headline") or "",
        "summary":    (cv or {}).get("summary") or "",
        "skills":     ", ".join(_cv_json_list((cv or {}).get("skills_json"))),
        "projects":   "\n".join(_cv_json_list((cv or {}).get("projects_json"))),
        "experience": _cv_entries((cv or {}).get("experience_json")),  # UAT #28: structured list
        "education":  _cv_entries((cv or {}).get("education_json")),    # UAT #28: structured list
        "links":      "\n".join(_cv_json_list((cv or {}).get("links_json"))),
        "is_public":  (cv or {}).get("is_public", 1),
        "slug":       (cv or {}).get("slug"),
    }
    return render_template("cv_editor.html", intern=intern, form=form)


@app.route("/portal/cv", methods=["POST"])
def portal_cv_save():
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    headline   = clean_text(data.get("headline"))
    summary    = (data.get("summary") or "").strip()
    skills     = json.dumps(_cv_skills_to_list(data.get("skills")))
    projects   = json.dumps(_cv_lines_to_list(data.get("projects")))
    experience = json.dumps(_cv_clean_entries(data.get("experience")))  # UAT #28: structured
    education  = json.dumps(_cv_clean_entries(data.get("education")))    # UAT #28: structured
    links      = json.dumps(_cv_lines_to_list(data.get("links")))
    is_public  = 1 if data.get("is_public", True) else 0
    with get_db() as conn:
        existing = conn.execute("SELECT slug FROM cvs WHERE intern_id=?", (intern["id"],)).fetchone()
        slug = existing["slug"] if existing and existing["slug"] else \
            f"{_cv_slugify(intern['name'])}-{intern['id']}"
        conn.execute("""
            INSERT INTO cvs (intern_id, slug, headline, summary, skills_json, projects_json,
                experience_json, education_json, links_json, is_public, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(intern_id) DO UPDATE SET
                headline=excluded.headline, summary=excluded.summary,
                skills_json=excluded.skills_json, projects_json=excluded.projects_json,
                experience_json=excluded.experience_json, education_json=excluded.education_json,
                links_json=excluded.links_json, is_public=excluded.is_public,
                updated_at=excluded.updated_at
        """, (intern["id"], slug, headline, summary, skills, projects, experience,
              education, links, is_public, now_str()))
        conn.commit()
    return jsonify({"status": "success", "slug": slug, "public_url": f"/cv/{slug}"})


@app.route("/cv/<slug>.pdf")
def cv_pdf(slug):
    loaded = _load_public_cv(slug)
    if loaded is None:
        abort(404)
    cv, intern_row, certs = loaded
    html = render_template("cv_pdf.html", **_cv_render_ctx(cv, intern_row, certs))
    try:
        from io import BytesIO

        from xhtml2pdf import pisa
        buf = BytesIO()
        pisa.CreatePDF(src=html, dest=buf)
        return Response(
            buf.getvalue(), mimetype="application/pdf",
            headers={"Content-Disposition": f"inline; filename=cv-{slug}.pdf"},
        )
    except Exception as e:
        log_error("cv-pdf", e)  # soft dependency â€” degrade to HTML
        return Response(html, mimetype="text/html")


@app.route("/cv/<slug>")
def cv_public(slug):
    loaded = _load_public_cv(slug)
    if loaded is None:
        abort(404)
    cv, intern_row, certs = loaded
    return render_template("cv_public.html", slug=slug, **_cv_render_ctx(cv, intern_row, certs))


@app.route("/intern/cv-meta")
def intern_cv_meta():
    """UAT #29: lightweight CV status for the dashboard card (exists / slug / public)."""
    intern = current_intern()
    if not intern:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    with get_db() as conn:
        row = conn.execute(
            "SELECT slug, is_public, updated_at FROM cvs WHERE intern_id=?", (intern["id"],)
        ).fetchone()
    if not row:
        return jsonify({"status": "success", "exists": False, "edit_url": "/portal/cv"})
    slug = row["slug"]
    return jsonify({
        "status": "success", "exists": True, "slug": slug,
        "is_public": bool(row["is_public"]),
        "public_url": f"/cv/{slug}", "pdf_url": f"/cv/{slug}.pdf",
        "edit_url": "/portal/cv", "updated_at": row["updated_at"],
    })


@app.route("/mentor/login", methods=["POST"])
def mentor_login():
    try:
        data = request.get_json(force=True)
        email    = clean_text(data.get("email")).lower()
        password = clean_text(data.get("password"))
        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password required."}), 400
        ip = get_client_ip()
        allowed, ra = rate_check(f"login:mentor:ip:{ip}", *RL_LOGIN_IP)
        if not allowed:
            log_abuse(ip, "/mentor/login", f"login:mentor:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        locked, _ = login_locked(email)
        if locked:
            log_abuse(ip, "/mentor/login", _login_fail_bucket(email), "login_lockout", email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        with get_db() as conn:
            mentor = conn.execute(
                "SELECT * FROM mentors WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
        if not mentor:
            record_login_fail(email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        pw_hash = mentor["password_hash"] or ""
        if not pw_hash:
            pw_hash = set_password_hash(generate_password(10))
            with get_db() as conn:
                conn.execute("UPDATE mentors SET password_hash=?,updated_at=? WHERE email=?",
                             (pw_hash, now_str(), email)); conn.commit()
        if not verify_password(pw_hash, password):
            record_login_fail(email)
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401
        if is_legacy_hash(pw_hash):
            migrate_password_hash("mentors", email, password)  # P17.0 lazy upgrade
        clear_login_fails(email)
        token = create_session(email, "mentor")
        resp = make_response(jsonify({"status": "success", "message": "Login successful."}))
        _set_session_cookie(resp, token)
        return resp
    except Exception as e:
        log_error("mentor-login", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/logout", methods=["POST"])
def logout():
    try:
        invalidate_session(get_session_token_from_request())
        resp = make_response(jsonify({"status": "success", "message": "Logged out."}))
        _clear_session_cookie(resp)
        return resp
    except Exception as e:
        log_error("logout", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/me")
def intern_me():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)
            ).fetchone()
            apps = conn.execute(
                "SELECT * FROM applications WHERE email=? ORDER BY created_at DESC", (email,)
            ).fetchall()
            enr = conn.execute(
                "SELECT * FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
            ).fetchone()
            paid_ok, _paid_reason, _ = paid_enroll_eligible(conn, email)
            # Wave A fix: this route previously never queried post_applications at all,
            # so anyone who applied via the job board (the primary flow post-pivot) had
            # zero visibility into their application status anywhere in the portal.
            # BUGFIX (2026-07-06): posts has no company_name column -- only company_id,
            # a FK to companies. This crashed /intern/me for EVERY intern account with
            # SQLite error "no such column: p.company_name", which is why the whole
            # portal was stuck on "Loading your profile..." for everyone, not just
            # accounts with job applications (the query fails at compile time regardless
            # of whether any rows match). Fixed by joining companies properly, same as
            # /intern/my-applications already does correctly.
            job_apps = []
            if acct:
                job_apps = conn.execute(
                    "SELECT pa.id, pa.post_id, pa.status, pa.created_at, pa.decision_note, "
                    "p.title AS post_title, p.domain AS post_domain, co.name AS company_name, "
                    "p.post_type AS post_type, p.status AS post_status, "
                    "d.status AS deposit_status "
                    "FROM post_applications pa JOIN posts p ON p.id = pa.post_id "
                    "JOIN companies co ON co.id = p.company_id "
                    "LEFT JOIN post_hire_deposits d ON d.post_application_id = pa.id "
                    "AND d.id = (SELECT MAX(id) FROM post_hire_deposits WHERE post_application_id = pa.id) "
                    "WHERE pa.intern_id = ? ORDER BY pa.id DESC",
                    (acct["id"],),
                ).fetchall()
            # Attendance summary for current week (Sun-Sat)
            week_start, week_end = get_week_bounds()
            ws = week_start.strftime("%Y-%m-%d")
            att_row = conn.execute(
                "SELECT total_minutes FROM attendance WHERE intern_id=? AND week_start=?",
                (acct["id"], ws)
            ).fetchone() if acct else None
            att_mins = att_row["total_minutes"] if att_row else 0
            attendance_summary = {
                "total_minutes": att_mins,
                "hours": round(att_mins / 60.0, 1),
                "target_hours": 10,
                "target_minutes": 600,
                "pct": min(100, int(round((att_mins / 600.0) * 100))),
                "status": "On Track" if att_mins >= 300 else "Action Needed"
            }

            # Approved micro-tasks count
            approved_tasks = conn.execute(
                "SELECT COUNT(*) as count FROM task_submissions WHERE intern_id=? AND status='approved'",
                (acct["id"],)
            ).fetchone()["count"] if acct else 0

            # Coins balance â€” the portal header shows SPENDABLE coins, so this is
            # the task ledger only. Reading the newest balance_after was doubly
            # wrong: it is a running total across every ledger_kind, and once
            # referral coins exist it would advertise withdrawable cash as
            # spendable credit.
            total_coins = get_task_balance(conn, acct["id"]) if acct else 0

            # Course enrollments summary with local progress calculation
            enriched_enrs = []
            if acct:
                raw_enrs = conn.execute(
                    "SELECT ce.*, c.title, c.slug, c.level FROM course_enrollments ce JOIN courses c ON c.id=ce.course_id WHERE ce.intern_id=? ORDER BY ce.id DESC",
                    (acct["id"],)
                ).fetchall()
                for ce in raw_enrs:
                    d = row_to_dict(ce)
                    total_days = conn.execute(
                        "SELECT MAX(day_number) FROM course_day_quizzes WHERE course_id = ?",
                        (d["course_id"],)
                    ).fetchone()[0] or 0
                    quizzes_passed = conn.execute(
                        "SELECT COUNT(DISTINCT day_quiz_id) FROM day_quiz_attempts "
                        "WHERE enrollment_id = ? AND passed = 1",
                        (d["id"],)
                    ).fetchone()[0] or 0
                    d["total_days"] = total_days
                    d["quizzes_passed"] = quizzes_passed
                    cur_day = d.get("current_day") or 1
                    pct = round(((cur_day - 1) / total_days * 100) if total_days > 0 else 0, 1)
                    d["guided_completion_pct"] = pct
                    d["tutor_completion_pct"] = pct  # compatibility alias
                    enriched_enrs.append(d)

        if not acct:
            return jsonify({"status": "error", "message": "Account not found."}), 404

        top_pct = enriched_enrs[0]["guided_completion_pct"] if enriched_enrs else 0

        # Build rejection re-apply info if latest app is rejected
        latest_app = apps[0] if apps else None
        reapply_info = None
        if latest_app and latest_app["status"] == STATUS_REJECTED:
            rejected_at = latest_app["rejected_at"]
            if rejected_at:
                try:
                    rejected_dt = datetime.strptime(rejected_at, "%Y-%m-%d %H:%M:%S")
                    days_since  = (datetime.now() - rejected_dt).days
                    days_left   = max(0, 30 - days_since)
                    reapply_info = {
                        "days_left": days_left,
                        "can_reapply": days_left == 0,
                        "rejected_at": rejected_at,
                    }
                except Exception:
                    reapply_info = {"days_left": 0, "can_reapply": True}

        return jsonify({
            "status": "success",
            "intern": {
                "name":             acct["name"],
                "email":            acct["email"],
                "phone":            acct["phone"],
                "city":             acct["city"],
                "college":          acct["college"],
                "course":           acct["course"],
                "semester":         acct["semester"],
                "year_of_passing":  acct["year_of_passing"],
                "domain":           acct["domain"],
                "tutor_completion_pct": top_pct,
                "learning_completion_pct": top_pct,
                "signup_stage":     int(acct["signup_stage"] or 3),
            },
            "applications": [row_to_dict(r) for r in apps],
            "job_applications": [row_to_dict(r) for r in job_apps],
            "enrollment":   row_to_dict(enr) if enr else None,
            "joining_date": row_to_dict(enr).get("joining_date", "") if enr else "",
            "reapply_info": reapply_info,
            "upi_id":       UPI_ID,
            "upi_amount":   UPI_AMOUNT,
            "paid_program_amount": PAID_PROGRAM_AMOUNT,
            "paid_eligible":       paid_ok,
            "paid_reason":         _paid_reason,
            "attendance_summary": attendance_summary,
            "tasks_completed_count": approved_tasks,
            "total_coins": total_coins,
            "course_enrollments": enriched_enrs,
        })
    except Exception as e:
        log_error("intern-me", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 11.3 â€” Interview routes (require intern session; both URL prefixes).
# Attempt/cooling/lock rules: 2 attempts max; 24h cooling between attempt 1 and 2;
# hard lock after 2 used; the 24h-since-last-attempt gate also outlives an admin reset.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _parse_dt(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _interview_state(acct):
    """Returns (attempts_used, locked, cooling_until_str|None, cooling_passed)."""
    attempts_used = int(acct.get("interview_attempts") or 0)
    locked = bool(int(acct.get("interview_locked") or 0)) or attempts_used >= INTERVIEW_MAX_ATTEMPTS
    last_dt = _parse_dt(acct.get("interview_last_attempt_at") or "")
    cooling_until, cooling_passed = None, True
    if last_dt:
        ready_at = last_dt + timedelta(hours=INTERVIEW_COOLING_HOURS)
        if datetime.now() < ready_at:
            cooling_passed = False
            cooling_until = ready_at.strftime("%Y-%m-%d %H:%M:%S")
    return attempts_used, locked, cooling_until, cooling_passed


def _interview_state_for_post(conn, email, acct, post_id):
    """T5: per-(intern, post) attempt cap + cooling, mirroring _interview_state's shape
    but scoped to one post. The intern_accounts.interview_locked hard-lock (staff-set,
    e.g. for cheating) still applies globally across every post.
    Returns (attempts_used, locked, cooling_until_str|None, cooling_passed)."""
    attempts_used = conn.execute(
        "SELECT COUNT(*) FROM interviews WHERE email=? AND post_id=?", (email, post_id)
    ).fetchone()[0]
    locked = bool(int(acct.get("interview_locked") or 0)) or attempts_used >= INTERVIEW_MAX_ATTEMPTS
    last_row = conn.execute(
        "SELECT created_at FROM interviews WHERE email=? AND post_id=? ORDER BY id DESC LIMIT 1",
        (email, post_id),
    ).fetchone()
    last_dt = _parse_dt(last_row["created_at"]) if last_row else None
    cooling_until, cooling_passed = None, True
    if last_dt:
        ready_at = last_dt + timedelta(hours=INTERVIEW_COOLING_HOURS)
        if datetime.now() < ready_at:
            cooling_passed = False
            cooling_until = ready_at.strftime("%Y-%m-%d %H:%M:%S")
    return attempts_used, locked, cooling_until, cooling_passed


def _build_interview_profile(acct, github_summary, why_join=""):
    return {
        "domain":         acct.get("domain", ""),
        "course":         acct.get("course", ""),
        "semester":       acct.get("semester", ""),
        "year":           acct.get("year_of_passing", ""),
        "college":        acct.get("college", ""),
        "why_join":       why_join or "",
        "github_summary": github_summary or "not provided",
        "linkedin_url":   acct.get("linkedin_url") or "",
    }


def _public_questions(questions):
    """Strip to id/text only â€” never expose internal fields to the candidate. The ``type``
    category (technical/commitment/goals/â€¦) is interviewer-internal: it stays in questions_json
    for assess_interview + the staff dossier, but is NOT sent to the browser (no tags shown)."""
    return [{"id": q.get("id"), "text": q.get("text", "")} for q in questions]


@app.route("/intern/interview/status")
def interview_status():
    """Legacy (no ?post_id): global per-account snapshot, unchanged for old callers.
    T5 (?post_id=<id> given): per-post snapshot used by the post-gated interview page
    and the dashboard's per-applied-post Start/Resume button."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        with get_db() as conn:
            acct = row_to_dict(conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)).fetchone())
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404

            post_id = request.args.get("post_id", type=int)
            if post_id:
                applied = conn.execute(
                    f"SELECT 1 FROM post_applications WHERE post_id=? AND intern_id=? AND status IN "
                    f"({_placeholders(len(APPLICATION_STATUSES))})",
                    (post_id, acct["id"], *APPLICATION_STATUSES)).fetchone()
                ivr = conn.execute(
                    "SELECT * FROM interviews WHERE email=? AND post_id=? ORDER BY id DESC LIMIT 1",
                    (email, post_id)).fetchone()
                iv = row_to_dict(ivr) if ivr else None
                attempts_used, locked, cooling_until, cooling_passed = _interview_state_for_post(
                    conn, email, acct, post_id)
                in_progress = bool(iv and iv.get("status") == "in_progress")
                can_start = bool(INTERVIEW_ENABLED and bool(applied) and not locked
                                 and attempts_used < INTERVIEW_MAX_ATTEMPTS and cooling_passed)
                return jsonify({
                    "status": "success", "post_id": post_id, "applied": bool(applied),
                    "interview_status": (iv.get("status") if iv else "not_started"),
                    "attempt_no": (iv.get("attempt_no") if iv else 0),
                    "attempts_used": attempts_used, "max_attempts": INTERVIEW_MAX_ATTEMPTS,
                    "locked": locked, "cooling_until": cooling_until, "in_progress": in_progress,
                    "can_start": can_start, "enabled": INTERVIEW_ENABLED,
                })

            ivr = conn.execute(
                "SELECT * FROM interviews WHERE email=? ORDER BY id DESC LIMIT 1", (email,)).fetchone()
        iv = row_to_dict(ivr) if ivr else None
        attempts_used, locked, cooling_until, cooling_passed = _interview_state(acct)
        in_progress = bool(iv and iv.get("status") == "in_progress")
        can_start = bool(INTERVIEW_ENABLED and not locked and attempts_used < INTERVIEW_MAX_ATTEMPTS
                         and cooling_passed and not in_progress)
        return jsonify({
            "status": "success",
            "interview_status": (iv.get("status") if iv else "not_started"),
            "attempt_no": (iv.get("attempt_no") if iv else 0),
            "attempts_used": attempts_used,
            "max_attempts": INTERVIEW_MAX_ATTEMPTS,
            "locked": locked,
            "cooling_until": cooling_until,
            "in_progress": in_progress,
            "has_linkedin": bool(clean_text(acct.get("linkedin_url"))),
            "has_github": bool(clean_text(acct.get("github_url"))),
            "domain": acct.get("domain"),
            "can_start": can_start,
            "enabled": INTERVIEW_ENABLED,
        })
    except Exception as e:
        log_error("interview-status", e)
        return jsonify({"status": "error", "message": "Error"}), 500


def _validate_profile_url(url, host):
    """Returns (ok, cleaned). Empty is allowed (optional). Host must match."""
    url = clean_text(url)
    if not url:
        return True, ""
    if not is_valid_url(url):
        return False, url
    try:
        from urllib.parse import urlparse
        netloc = (urlparse(url).netloc or "").lower()
        if host not in netloc:
            return False, url
    except Exception:
        return False, url
    return True, url


@app.route("/intern/interview/profile-urls", methods=["POST"])
def interview_profile_urls():
    """Optional/skippable. Save linkedin_url / github_url (host-validated)."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        data = request.get_json(force=True) or {}
        ok_li, linkedin = _validate_profile_url(data.get("linkedin_url"), "linkedin.com")
        if not ok_li:
            return jsonify({"status": "error", "message": "Please enter a valid LinkedIn profile URL."}), 400
        ok_gh, github = _validate_profile_url(data.get("github_url"), "github.com")
        if not ok_gh:
            return jsonify({"status": "error", "message": "Please enter a valid GitHub profile URL."}), 400
        with get_db() as conn:
            conn.execute(
                "UPDATE intern_accounts SET linkedin_url=?, github_url=?, updated_at=? WHERE email=?",
                (linkedin, github, now_str(), email))
            conn.commit()
        return jsonify({"status": "success", "message": "Saved.",
                        "has_linkedin": bool(linkedin), "has_github": bool(github)})
    except Exception as e:
        log_error("interview-profile-urls", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/interview/start", methods=["POST"])
def interview_start():
    """T5: post-gated. Requires post_id + a prior post_applications row for that
    (intern, post). Attempt cap + cooling are scoped per (email, post_id); a hard
    intern_accounts.interview_locked flag still blocks every post. Concurrent
    in-progress interviews are capped at 3 across all posts. Attempt 2+ regenerates
    fresh questions for that post's domain. Returns questions only â€” never any
    assessment."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        ip = get_client_ip()
        if not INTERVIEW_ENABLED:
            return jsonify({"status": "error", "message": "The interview is temporarily unavailable. Please try again shortly."}), 503
        allowed, ra = rate_check(f"interview:ip:{ip}", *RL_INTERVIEW_IP)
        if not allowed:
            log_abuse(ip, "/intern/interview/start", f"interview:ip:{ip}", "rate_limit", email)
            return too_many(ra)

        data = request.get_json(force=True, silent=True) or {}
        post_id = data.get("post_id")
        try:
            post_id = int(post_id)
        except (TypeError, ValueError):
            post_id = None
        if not post_id:
            return jsonify({"status": "error", "code": "select_post",
                            "message": "Select an internship or job to start its interview."}), 400

        # Phase 1: read everything (no network held).
        with get_db() as conn:
            acct = row_to_dict(conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)).fetchone())
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404
            post_row = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
            if not post_row:
                return jsonify({"status": "error", "code": "select_post",
                                "message": "That post could not be found."}), 400
            post = row_to_dict(post_row)
            company_questions = _company_questions_for_post(conn, post_id)
            applied = conn.execute(
                f"SELECT 1 FROM post_applications WHERE post_id=? AND intern_id=? AND status IN "
                f"({_placeholders(len(APPLICATION_STATUSES))})",
                (post_id, acct["id"], *APPLICATION_STATUSES)).fetchone()
            if not applied:
                return jsonify({"status": "error", "code": "select_post",
                                "message": "Apply to this post before starting its interview."}), 400

            ivr = conn.execute(
                "SELECT * FROM interviews WHERE email=? AND post_id=? AND status='in_progress' "
                "ORDER BY id DESC LIMIT 1", (email, post_id)).fetchone()
            if ivr:  # resume â€” do NOT burn another attempt, do NOT recheck caps
                iv = row_to_dict(ivr)
                return jsonify({"status": "success", "attempt_no": iv.get("attempt_no"), "post_id": post_id,
                                "questions": _public_questions(json.loads(iv.get("questions_json") or "[]"))})

            concurrent = conn.execute(
                "SELECT COUNT(*) FROM interviews WHERE email=? AND status='in_progress'", (email,)
            ).fetchone()[0]
            if concurrent >= 3:
                return jsonify({"status": "error", "code": "concurrent_limit",
                                "message": "You already have 3 interviews in progress. Finish one before "
                                           "starting another."}), 403

            attempts_used, locked, cooling_until, cooling_passed = _interview_state_for_post(
                conn, email, acct, post_id)
            if locked or attempts_used >= INTERVIEW_MAX_ATTEMPTS:
                return jsonify({"status": "error", "locked": True,
                                "message": "You have used all your interview attempts for this post."}), 403
            if not cooling_passed:
                return jsonify({"status": "error", "cooling_until": cooling_until,
                                "message": "Your next attempt for this post isn't available yet."}), 429

            prev_iv = conn.execute(
                "SELECT questions_json FROM interviews WHERE email=? AND post_id=? AND status!='in_progress' "
                "ORDER BY id DESC LIMIT 1", (email, post_id)).fetchone()

        # Phase 2: question source. If the post has enough APPROVED company-uploaded
        # questions (T6), use those verbatim; otherwise assemble from the static domain
        # bank (no LLM). Domain comes from the POST, not the intern account (account
        # domain may be empty â€” T9). The only external call here is the best-effort
        # GitHub summary (own timeout), for staff-review context.
        net_start = time.monotonic()
        domain = post.get("domain") or ""
        gh_summary = build_github_summary(acct.get("github_url"))
        profile = _build_interview_profile(acct, gh_summary, why_join="")
        profile["domain"] = domain
        if company_questions:
            questions = company_questions
        else:
            exclude_keys = set()
            if prev_iv:
                try:
                    exclude_keys = {q.get("key") for q in json.loads(prev_iv["questions_json"] or "[]") if q.get("key")}
                except Exception:
                    exclude_keys = set()
            questions = generate_interview_questions(profile, start_ts=net_start, exclude_keys=exclude_keys)
        attempt_no = attempts_used + 1

        # Phase 3: write (re-check race: another tab may have created one meanwhile).
        with get_db() as conn:
            race = conn.execute(
                "SELECT * FROM interviews WHERE email=? AND post_id=? AND status='in_progress' "
                "ORDER BY id DESC LIMIT 1", (email, post_id)).fetchone()
            if race:
                iv = row_to_dict(race)
                return jsonify({"status": "success", "attempt_no": iv.get("attempt_no"), "post_id": post_id,
                                "questions": _public_questions(json.loads(iv.get("questions_json") or "[]"))})
            conn.execute(
                "INSERT INTO interviews (email, post_id, domain, attempt_no, status, "
                "questions_json, github_summary, started_at, created_at) "
                "VALUES (?,?,?,?,'in_progress',?,?,?, datetime('now','localtime'))",
                (email, post_id, domain, attempt_no, json.dumps(questions), gh_summary, now_str()))
            conn.commit()
        return jsonify({"status": "success", "attempt_no": attempt_no, "post_id": post_id,
                        "questions": _public_questions(questions)})
    except Exception as e:
        log_error("interview-start", e)
        return jsonify({"status": "error", "message": "Could not start the interview. Please try again shortly."}), 500


@app.route("/intern/interview/submit", methods=["POST"])
def interview_submit():
    """Validate all answers, assess, store both blocks + anti-copy telemetry (informational
    only, never enforced), complete the interview. Legacy (pre-T5, post_id IS NULL) attempts
    still move the matching legacy `applications` row to Under Review; post-gated attempts
    don't touch post_applications.status -- that stays the company's manual call. Returns the
    SOFT candidate_focus only."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        ip = get_client_ip()
        allowed, ra = rate_check(f"interview:ip:{ip}", *RL_INTERVIEW_IP)
        if not allowed:
            log_abuse(ip, "/intern/interview/submit", f"interview:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        data = request.get_json(force=True) or {}
        answers_in = data.get("answers") or {}
        try:
            post_id = int(data.get("post_id")) if data.get("post_id") is not None else None
        except (TypeError, ValueError):
            post_id = None
        try:
            time_taken_sec = max(0, int(data.get("time_taken_sec") or 0))
        except (TypeError, ValueError):
            time_taken_sec = 0
        try:
            tab_switches = max(0, int(data.get("tab_switches") or 0))
        except (TypeError, ValueError):
            tab_switches = 0

        with get_db() as conn:
            acct = row_to_dict(conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)).fetchone())
            if post_id:
                ivr = conn.execute(
                    "SELECT * FROM interviews WHERE email=? AND post_id=? AND status='in_progress' "
                    "ORDER BY id DESC LIMIT 1", (email, post_id)).fetchone()
            else:  # backward compat: a pre-T5 in-progress interview has no post_id
                ivr = conn.execute(
                    "SELECT * FROM interviews WHERE email=? AND post_id IS NULL AND status='in_progress' "
                    "ORDER BY id DESC LIMIT 1", (email,)).fetchone()
        if not acct:
            return jsonify({"status": "error", "message": "Account not found."}), 404
        if not ivr:
            return jsonify({"status": "error", "message": "No interview in progress to submit."}), 400
        iv = row_to_dict(ivr)
        questions = json.loads(iv.get("questions_json") or "[]")

        # Validate: every question must have a non-empty typed answer.
        norm = {}
        for q in questions:
            qid = str(q.get("id"))
            ans = clean_text(answers_in.get(qid, answers_in.get(q.get("id"), "")))
            if len(ans) < 2:
                return jsonify({"status": "error", "message": "Please answer all questions before submitting."}), 400
            norm[qid] = ans

        # Assess (network; graceful on failure).
        profile = _build_interview_profile(acct, iv.get("github_summary") or "not provided")
        result = assess_interview(profile, questions, norm)

        with get_db() as conn:
            cur = conn.execute(
                "UPDATE interviews SET answers_json=?, mentor_assessment_json=?, candidate_focus_json=?, "
                "time_taken_sec=?, tab_switches=?, status='completed', completed_at=? "
                "WHERE id=? AND status='in_progress'",
                (json.dumps(norm), json.dumps(result["mentor_assessment"]),
                 json.dumps(result["candidate_focus"]), time_taken_sec, tab_switches,
                 now_str(), iv["id"]))
            if cur.rowcount == 0:
                conn.commit()
                return jsonify({"status": "error", "message": "This interview was already submitted."}), 409
            moved = False
            if not iv.get("post_id"):  # legacy Track-1 flow only
                app_row = conn.execute(
                    "SELECT * FROM applications WHERE email=? AND domain=? ORDER BY id DESC LIMIT 1",
                    (email, iv.get("domain"))).fetchone()
                app_row = row_to_dict(app_row) if app_row else None
                if app_row and app_row.get("status") not in (
                        STATUS_SELECTED, STATUS_ENROLLMENT_PENDING, STATUS_ENROLLED, STATUS_ACCEPTED):
                    conn.execute("UPDATE applications SET status=?, updated_at=? WHERE id=?",
                                 (STATUS_UNDER_REVIEW, now_str(), app_row["id"]))
                    moved = True
            conn.commit()

        if moved:
            send_status_update_email(acct.get("name"), email, iv.get("domain"), STATUS_UNDER_REVIEW)
        return jsonify({"status": "success",
                        "candidate_focus": result["candidate_focus"],
                        "redirect": "/portal"})
    except Exception as e:
        log_error("interview-submit", e)
        return jsonify({"status": "error", "message": "Could not submit. Please try again."}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 11.8 â€” Admin/mentor interview assessment view + reset (single & bulk).
# mentor_assessment_json is staff-only; candidate never sees it. Reset clears the
# hard lock + attempt count but the 24h-since-last-attempt gate (11.3) still holds.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _safe_json_load(s, default=None):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def _build_interview_dossier(conn, email):
    """Full staff view for one candidate: account interview-state + every attempt
    (questions, answers, mentor_assessment, candidate_focus, timing)."""
    acct = conn.execute(
        "SELECT name,email,domain,linkedin_url,github_url,interview_attempts,"
        "interview_last_attempt_at,interview_locked FROM intern_accounts WHERE email=?",
        (email,)).fetchone()
    rows = conn.execute(
        "SELECT i.*, p.title AS post_title FROM interviews i LEFT JOIN posts p ON p.id = i.post_id "
        "WHERE i.email=? ORDER BY i.id DESC", (email,)).fetchall()
    attempts = []
    for r in rows:
        d = row_to_dict(r)
        attempts.append({
            "id": d["id"],
            "attempt_no": d.get("attempt_no"),
            "status": d.get("status"),
            "domain": d.get("domain"),
            "post_id": d.get("post_id"),
            "post_title": d.get("post_title"),
            "github_summary": d.get("github_summary"),
            "questions": _safe_json_load(d.get("questions_json"), []),
            "answers": _safe_json_load(d.get("answers_json"), {}),
            "mentor_assessment": _safe_json_load(d.get("mentor_assessment_json"), None),
            "candidate_focus": _safe_json_load(d.get("candidate_focus_json"), None),
            # T5: anti-copy telemetry -- informational only, never enforced.
            "time_taken_sec": d.get("time_taken_sec") or 0,
            "tab_switches": d.get("tab_switches") or 0,
            "started_at": d.get("started_at"),
            "completed_at": d.get("completed_at"),
            "created_at": d.get("created_at"),
        })
    acct_d = row_to_dict(acct) if acct else None
    if acct_d:
        attempts_used, locked, cooling_until, cooling_passed = _interview_state(acct_d)
        acct_d["locked_effective"] = locked
        acct_d["cooling_until"] = cooling_until
        acct_d["cooling_passed"] = cooling_passed
    return {"account": acct_d, "attempts": attempts}


@app.route("/admin/interview/<path:email>")
def admin_interview_view(email):
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = clean_text(email).lower()
        with get_db() as conn:
            dossier = _build_interview_dossier(conn, email)
        if not dossier["account"]:
            return jsonify({"status": "error", "message": "Account not found."}), 404
        return jsonify({"status": "success", **dossier})
    except Exception as e:
        log_error("admin-interview-view", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/mentor/interview/<path:email>")
def mentor_interview_view(email):
    try:
        user = require_role("mentor")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = clean_text(email).lower()
        with get_db() as conn:
            # A mentor may only view candidates assigned to them.
            owns = conn.execute(
                "SELECT 1 FROM applications WHERE email=? AND mentor_email=? LIMIT 1",
                (email, user["email"])).fetchone()
            if not owns:
                return jsonify({"status": "error", "message": "Not authorized for this candidate."}), 403
            dossier = _build_interview_dossier(conn, email)
        if not dossier["account"]:
            return jsonify({"status": "error", "message": "Account not found."}), 404
        return jsonify({"status": "success", **dossier})
    except Exception as e:
        log_error("mentor-interview-view", e)
        return jsonify({"status": "error", "message": "Error"}), 500


def _reset_interview_for_emails(emails):
    """Clear hard lock + attempt count for the given emails. interview_last_attempt_at
    is intentionally preserved so the 24h cooling gate (11.3) still applies post-reset."""
    if not emails:
        return 0
    with get_db() as conn:
        cur = conn.execute(
            f"UPDATE intern_accounts SET interview_locked=0, interview_attempts=0, updated_at=? "
            f"WHERE email IN ({_placeholders(len(emails))})",
            [now_str()] + list(emails))
        conn.commit()
        return cur.rowcount


@app.route("/admin/interview/reset", methods=["POST"])
def admin_interview_reset():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data = request.get_json(force=True) or {}
        email = clean_text(data.get("email")).lower()
        if not email:
            return jsonify({"status": "error", "message": "email required."}), 400
        updated = _reset_interview_for_emails([email])
        if not updated:
            return jsonify({"status": "error", "message": "Account not found."}), 404
        return jsonify({"status": "success", "reset": updated,
                        "note": "Lock and attempt count cleared. The 24h cooling since the last attempt still applies."})
    except Exception as e:
        log_error("admin-interview-reset", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/interview/bulk-reset", methods=["POST"])
def admin_interview_bulk_reset():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ids = _parse_int_ids(request.get_json(force=True))
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        with get_db() as conn:
            rows = conn.execute(
                f"SELECT email FROM intern_accounts WHERE id IN ({_placeholders(len(ids))})", ids
            ).fetchall()
        emails = [r["email"] for r in rows]
        updated = _reset_interview_for_emails(emails)
        return jsonify({"status": "success", "reset": updated,
                        "note": "Locks and attempt counts cleared. The 24h cooling since each last attempt still applies."})
    except Exception as e:
        log_error("admin-interview-bulk-reset", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/update-profile", methods=["POST"])
def intern_update_profile():
    """Update editable intern fields. email + domain are LOCKED (never changed)."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        data = request.get_json(force=True) or {}

        updates = {}
        if data.get("name") is not None:
            name = clean_text(data.get("name"))
            if not (2 <= len(name) <= 80):
                return jsonify({"status": "error", "message": "Name must be 2â€“80 characters."}), 400
            updates["name"] = name
        if data.get("phone") is not None:
            phone = clean_text(data.get("phone"))
            if not is_valid_phone(phone):
                return jsonify({"status": "error", "message": "Enter a valid 10-digit phone number."}), 400
            updates["phone"] = phone
        if data.get("city") is not None:
            city = clean_text(data.get("city"))
            if not city:
                return jsonify({"status": "error", "message": "City cannot be empty."}), 400
            updates["city"] = city
        if data.get("college") is not None:
            college = clean_text(data.get("college"))
            if not college:
                return jsonify({"status": "error", "message": "College cannot be empty."}), 400
            updates["college"] = college
        if data.get("course") is not None:
            course = clean_text(data.get("course"))
            if course not in VALID_COURSES:
                return jsonify({"status": "error", "message": "Invalid course."}), 400
            updates["course"] = course
        if data.get("semester") is not None:
            semester = clean_text(data.get("semester"))
            if semester not in VALID_SEMESTERS:
                return jsonify({"status": "error", "message": "Invalid semester."}), 400
            updates["semester"] = semester
        if data.get("year_of_passing") is not None:
            year = clean_text(data.get("year_of_passing"))
            if year not in VALID_YEARS:
                return jsonify({"status": "error", "message": "Invalid year of passing."}), 400
            updates["year_of_passing"] = year

        if not updates:
            return jsonify({"status": "error", "message": "No valid fields to update."}), 400

        # email + domain are intentionally never updated (locked).
        updates["updated_at"] = now_str()
        set_clause = ", ".join(f"{k}=?" for k in updates)  # keys are a fixed internal whitelist
        params = list(updates.values()) + [email]
        with get_db() as conn:
            conn.execute(f"UPDATE intern_accounts SET {set_clause} WHERE email=?", params)
            conn.commit()
        return jsonify({"status": "success", "message": "Profile updated."})
    except Exception as e:
        log_error("intern-update-profile", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/change-password", methods=["POST"])
def intern_change_password():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]
        data = request.get_json(force=True) or {}
        current = clean_text(data.get("current_password"))
        new     = clean_text(data.get("new_password"))
        confirm = clean_text(data.get("confirm_password"))
        if not current or not new:
            return jsonify({"status": "error", "message": "All password fields are required."}), 400
        if len(new) < 8:
            return jsonify({"status": "error", "message": "New password must be at least 8 characters."}), 400
        if new != confirm:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400
        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404
            if int(acct["password_set"] or 0) != 1:
                return jsonify({"status": "error", "message": "Please set your password first using the Set Password flow."}), 400
            if not verify_password(acct["password_hash"], current):
                return jsonify({"status": "error", "message": "Current password is incorrect."}), 401
            conn.execute(
                "UPDATE intern_accounts SET password_hash=?, updated_at=? WHERE email=?",
                (set_password_hash(new), now_str(), email)
            )
            conn.commit()
        return jsonify({"status": "success", "message": "Password changed successfully."})
    except Exception as e:
        log_error("intern-change-password", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/company/change-password", methods=["POST"])
def company_change_password():
    """Track 2 Â§B (UAT #4): company self-service password change (Account section)."""
    try:
        company = current_company()
        if not company:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data = request.get_json(force=True) or {}
        current = clean_text(data.get("current_password"))
        new     = clean_text(data.get("new_password"))
        confirm = clean_text(data.get("confirm_password"))
        if not current or not new:
            return jsonify({"status": "error", "message": "All password fields are required."}), 400
        if len(new) < 8:
            return jsonify({"status": "error", "message": "New password must be at least 8 characters."}), 400
        if new != confirm:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400
        if not verify_password(company["password_hash"], current):
            return jsonify({"status": "error", "message": "Current password is incorrect."}), 401
        with get_db() as conn:
            conn.execute(
                "UPDATE companies SET password_hash=?, updated_at=? WHERE id=?",
                (set_password_hash(new), now_str(), company["id"])
            )
            conn.commit()
        return jsonify({"status": "success", "message": "Password changed successfully."})
    except Exception as e:
        log_error("company-change-password", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/my-applications")
def intern_my_applications():
    """Track 2 Â§B (UAT #4): the logged-in intern's job/internship applications +
    statuses, incl. the 'complete these certifications' decision when present."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = conn.execute(
                "SELECT pa.id, pa.status, pa.comment, pa.created_at, pa.decision_note, "
                "pa.needed_certs_json, p.id AS post_id, p.title AS post_title, "
                "p.post_type, p.slug, co.id AS company_id, co.name AS company_name "
                "FROM post_applications pa JOIN posts p ON p.id = pa.post_id "
                "JOIN companies co ON co.id = p.company_id "
                "WHERE pa.intern_id=? ORDER BY pa.id DESC",
                (intern["id"],),
            ).fetchall()
            out = []
            for r in rows:
                d = row_to_dict(r)
                try:
                    d["needed_certs"] = json.loads(d.pop("needed_certs_json") or "[]")
                except (ValueError, TypeError):
                    d["needed_certs"] = []
                d["post_path"] = _post_path({"post_type": d["post_type"],
                                             "slug": d["slug"], "id": d["post_id"]})
                # T5: per-post interview eligibility, so the dashboard can render a
                # Start/Resume/Locked button next to each applied post without N extra calls.
                ivr = conn.execute(
                    "SELECT status, attempt_no FROM interviews WHERE email=? AND post_id=? "
                    "ORDER BY id DESC LIMIT 1", (intern["email"], d["post_id"])).fetchone()
                iv = row_to_dict(ivr) if ivr else None
                attempts_used, locked, cooling_until, cooling_passed = _interview_state_for_post(
                    conn, intern["email"], intern, d["post_id"])
                d["interview"] = {
                    "status": iv.get("status") if iv else "not_started",
                    "in_progress": bool(iv and iv.get("status") == "in_progress"),
                    "attempts_used": attempts_used, "max_attempts": INTERVIEW_MAX_ATTEMPTS,
                    "locked": locked, "cooling_until": cooling_until,
                    "can_start": bool(INTERVIEW_ENABLED and not locked
                                       and attempts_used < INTERVIEW_MAX_ATTEMPTS and cooling_passed),
                }
                out.append(d)
        return jsonify({"status": "success", "applications": out,
                        "tutor_base": TUTOR_BASE_URL})
    except Exception as e:
        log_error("intern-my-applications", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/post-hire/deposit", methods=["POST"])
def post_hire_deposit():
    """Track 5: â‚¹499 refundable security deposit for a job-board hire. Triggers only
    once a company has marked the post_applications row 'Hired' (i.e. certifications
    are already complete by that point -- gating happens at the company's Hired
    transition, not here). Entirely separate from the legacy /enroll route."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]

        ip = get_client_ip()
        allowed, ra = rate_check(f"post_hire_deposit:ip:{ip}", *RL_ENROLL_IP)
        if not allowed:
            log_abuse(ip, "/post-hire/deposit", f"post_hire_deposit:ip:{ip}", "rate_limit", email)
            return too_many(ra)

        post_app_id = clean_text(request.form.get("post_application_id"))
        if not post_app_id or not post_app_id.isdigit():
            return jsonify({"status": "error", "message": "post_application_id required."}), 400
        post_app_id = int(post_app_id)

        if "payment_screenshot" not in request.files:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        file = request.files["payment_screenshot"]
        if not file or not file.filename:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        if not allowed_file(file.filename):
            return jsonify({"status": "error", "message": "Allowed: png,jpg,jpeg,pdf"}), 400
        sniffed = sniff_upload_type(file)
        if sniffed is None:
            log_abuse(ip, "/post-hire/deposit", "post_hire_deposit:upload", "bad_magic", email)
            return jsonify({"status": "error", "message": "File must be a real PNG, JPEG, or PDF."}), 400

        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404

            pa = conn.execute(
                "SELECT * FROM post_applications WHERE id=? AND intern_id=?",
                (post_app_id, acct["id"]),
            ).fetchone()
            if not pa:
                return jsonify({"status": "error", "message": "Application not found."}), 404
            if pa["status"] != "Hired":
                return jsonify({"status": "error", "message": "Not eligible for the deposit yet."}), 400

            existing = conn.execute(
                "SELECT id FROM post_hire_deposits WHERE post_application_id=? "
                "AND status IN ('pending','verified')",
                (post_app_id,),
            ).fetchone()
            if existing:
                return jsonify({"status": "error", "message": "A deposit has already been submitted for this role."}), 400

            filename = f"{uuid.uuid4().hex}.{sniffed}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            conn.execute(
                "INSERT INTO post_hire_deposits "
                "(post_application_id, intern_id, post_id, amount, payment_screenshot, "
                "status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (post_app_id, acct["id"], pa["post_id"], UPI_AMOUNT, filename,
                 "pending", now_str(), now_str()),
            )
            conn.commit()

        return jsonify({"status": "success", "message": "Deposit submitted for verification."})
    except Exception as e:
        log_error("post-hire-deposit", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/enroll", methods=["POST"])
def enroll():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]

        ip = get_client_ip()
        allowed, ra = rate_check(f"enroll:ip:{ip}", *RL_ENROLL_IP)
        if not allowed:
            log_abuse(ip, "/enroll", f"enroll:ip:{ip}", "rate_limit", email)
            return too_many(ra)

        joining_date = clean_text(request.form.get("joining_date"))
        valid, err = validate_joining_date(joining_date)
        if not valid:
            return jsonify({"status": "error", "message": err}), 400

        if "payment_screenshot" not in request.files:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        file = request.files["payment_screenshot"]
        if not file or not file.filename:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        if not allowed_file(file.filename):
            return jsonify({"status": "error", "message": "Allowed: png,jpg,jpeg,pdf"}), 400
        # 8.5: verify real content type by magic bytes; reject extension/content mismatches.
        sniffed = sniff_upload_type(file)
        if sniffed is None:
            log_abuse(ip, "/enroll", "enroll:upload", "bad_magic", email)
            return jsonify({"status": "error", "message": "File must be a real PNG, JPEG, or PDF."}), 400
        # 8.5: store under a random uuid name with the sniffed extension (never trust user name).
        filename = f"{uuid.uuid4().hex}.{sniffed}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        batch_label = make_batch_label(joining_date)

        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404
            app_row = conn.execute(
                "SELECT * FROM applications WHERE email=? AND status IN (?,?,?,?,?) ORDER BY id DESC LIMIT 1",
                (email, STATUS_SELECTED, STATUS_ENROLLMENT_PENDING, STATUS_ENROLLED, STATUS_ACCEPTED, STATUS_PAID_ENROLLED)
            ).fetchone()
            if not app_row:
                return jsonify({"status": "error", "message": "Not eligible for enrollment yet."}), 400

            existing = conn.execute("SELECT * FROM enrollments WHERE email=? LIMIT 1", (email,)).fetchone()
            if existing:
                conn.execute("""
                    UPDATE enrollments SET application_id=?,timestamp=?,name=?,phone=?,city=?,college=?,course=?,
                    semester=?,year_of_passing=?,domain=?,joining_date=?,batch_label=?,payment_screenshot=?,
                    payment_status='Pending Verification',updated_at=? WHERE email=?
                """, (app_row["id"], now_str(), acct["name"], acct["phone"], acct["city"], acct["college"],
                      acct["course"], acct["semester"], acct["year_of_passing"], app_row["domain"],
                      joining_date, batch_label, filename, now_str(), email))
            else:
                conn.execute("""
                    INSERT INTO enrollments
                    (application_id,timestamp,name,email,phone,city,college,course,semester,
                    year_of_passing,domain,joining_date,batch_label,payment_screenshot,payment_status,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (app_row["id"], now_str(), acct["name"], email, acct["phone"], acct["city"], acct["college"],
                      acct["course"], acct["semester"], acct["year_of_passing"], app_row["domain"],
                      joining_date, batch_label, filename, "Pending Verification", now_str(), now_str()))

            old_status = app_row["status"]
            # SEC-007: Do not advance to STATUS_ENROLLED until payment is verified by admin.
            # Keep as STATUS_ENROLLMENT_PENDING (or current status if already PA).
            conn.execute("UPDATE applications SET status=?,updated_at=? WHERE id=?",
                         (STATUS_ENROLLMENT_PENDING, now_str(), app_row["id"]))
            conn.commit()

        send_enrollment_confirmation_email(acct["name"], email, app_row["domain"], joining_date)
        if old_status != STATUS_ENROLLED:
            send_status_update_email(acct["name"], email, app_row["domain"], STATUS_ENROLLED, "", joining_date)
        return jsonify({"status": "success", "message": "Enrollment submitted successfully."})
    except Exception as e:
        log_error("enroll", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Phase 12 â€” Paid program (â‚¹1599) direct-enroll (parallel product to â‚¹499).
# 12.0 availability rule: offered ONLY after the candidate has completed the
# interview (Under Review onward) OR at rejection / non-selection â€” never at signup.
# Reuses the screenshot-upload + manual-verify flow, with its own product/status.
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def paid_enroll_eligible(conn, email):
    """Returns (eligible: bool, reason: str, app_row|None). See 12.0 availability rule."""
    app_row = conn.execute(
        "SELECT * FROM applications WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
    ).fetchone()
    if not app_row:
        return False, "no_application", None
    status = app_row["status"]
    # Already on the free success path â€” the paid track is not offered to them.
    if status in (STATUS_ACCEPTED, STATUS_ENROLLED):
        return False, "already_enrolled_free", app_row
    # A paid enrollee whose payment was Rejected must be allowed to re-upload, even if
    # they never sat an interview â€” the interview gate below must not trap them.
    if status == STATUS_PAID_ENROLLED:
        latest_enr = conn.execute(
            "SELECT product, payment_status FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
            (email,),
        ).fetchone()
        if (latest_enr and latest_enr["product"] == "paid_program"
                and latest_enr["payment_status"] == "Rejected"):
            return True, "ok", app_row
    completed_iv = conn.execute(
        "SELECT 1 FROM interviews WHERE email=? AND status='completed' LIMIT 1", (email,)
    ).fetchone()
    # F7: when interviews are disabled, don't trap paid-intent users behind a gate they
    # cannot clear â€” allow paid enrol from any non-final state in that case.
    if completed_iv or status == STATUS_REJECTED or not INTERVIEW_ENABLED:
        return True, "ok", app_row
    return False, "interview_required", app_row


@app.route("/paid/enroll", methods=["POST"])
def paid_enroll():
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        email = user["email"]

        ip = get_client_ip()
        allowed, ra = rate_check(f"enroll:ip:{ip}", *RL_ENROLL_IP)
        if not allowed:
            log_abuse(ip, "/paid/enroll", f"enroll:ip:{ip}", "rate_limit", email)
            return too_many(ra)

        joining_date = clean_text(request.form.get("joining_date"))
        valid, err = validate_joining_date(joining_date)
        if not valid:
            return jsonify({"status": "error", "message": err}), 400

        if "payment_screenshot" not in request.files:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        file = request.files["payment_screenshot"]
        if not file or not file.filename:
            return jsonify({"status": "error", "message": "Payment screenshot required."}), 400
        if not allowed_file(file.filename):
            return jsonify({"status": "error", "message": "Allowed: png,jpg,jpeg,pdf"}), 400
        sniffed = sniff_upload_type(file)
        if sniffed is None:
            log_abuse(ip, "/paid/enroll", "paid:upload", "bad_magic", email)
            return jsonify({"status": "error", "message": "File must be a real PNG, JPEG, or PDF."}), 400
        filename = f"{uuid.uuid4().hex}.{sniffed}"

        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found."}), 404
            eligible, reason, app_row = paid_enroll_eligible(conn, email)
            if not eligible:
                msg = {
                    "no_application": "Please apply first.",
                    "already_enrolled_free": "You're already enrolled through the standard track.",
                    "interview_required": "The paid program opens after you complete your virtual interview.",
                }.get(reason, "Not eligible for the paid program yet.")
                return jsonify({"status": "error", "message": msg, "code": reason}), 400

            # Save the screenshot only after eligibility passes.
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            batch_label = make_batch_label(joining_date)

            existing = conn.execute("SELECT * FROM enrollments WHERE email=? LIMIT 1", (email,)).fetchone()
            if existing:
                conn.execute("""
                    UPDATE enrollments SET application_id=?,timestamp=?,name=?,phone=?,city=?,college=?,course=?,
                    semester=?,year_of_passing=?,domain=?,joining_date=?,batch_label=?,payment_screenshot=?,
                    payment_status='Pending Verification',admin_note='',product='paid_program',amount=?,updated_at=? WHERE email=?
                """, (app_row["id"], now_str(), acct["name"], acct["phone"], acct["city"], acct["college"],
                      acct["course"], acct["semester"], acct["year_of_passing"], app_row["domain"],
                      joining_date, batch_label, filename, PAID_PROGRAM_AMOUNT, now_str(), email))
            else:
                conn.execute("""
                    INSERT INTO enrollments
                    (application_id,timestamp,name,email,phone,city,college,course,semester,
                    year_of_passing,domain,joining_date,batch_label,payment_screenshot,payment_status,
                    product,amount,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (app_row["id"], now_str(), acct["name"], email, acct["phone"], acct["city"], acct["college"],
                      acct["course"], acct["semester"], acct["year_of_passing"], app_row["domain"],
                      joining_date, batch_label, filename, "Pending Verification",
                      "paid_program", PAID_PROGRAM_AMOUNT, now_str(), now_str()))

            conn.execute("UPDATE applications SET status=?,updated_at=? WHERE id=?",
                         (STATUS_PAID_ENROLLED, now_str(), app_row["id"]))
            conn.commit()

        send_status_update_email(acct["name"], email, app_row["domain"], STATUS_PAID_ENROLLED)
        return jsonify({"status": "success",
                        "message": "Paid program enrollment submitted. We'll verify your payment shortly.",
                        "amount": PAID_PROGRAM_AMOUNT,
                        "redirect": "/profile"})
    except Exception as e:
        log_error("paid-enroll", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ATTENDANCE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/attendance/ping", methods=["POST"])
def attendance_ping():
    """
    Heartbeat endpoint called every 3 minutes from the dashboard.
    Credits 3 minutes to the current Sunâ€“Sat week.
    Only credits if today >= enrollment joining_date.
    Returns updated weekly total so the frontend counter stays live.
    """
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        with get_db() as conn:
            acct = conn.execute(
                "SELECT id FROM intern_accounts WHERE email=? AND is_active=1", (user["email"],)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found"}), 404

            intern_id = acct["id"]

            # Joining date guard â€” no attendance credits before joining date at 18:00
            enr = conn.execute(
                "SELECT joining_date FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1",
                (user["email"],)
            ).fetchone()
            if enr and not joining_unlocked(enr["joining_date"]):
                return jsonify({"status": "ok", "skipped": True,
                                "reason": "before_joining_date"})

            week_start, week_end = get_week_bounds()
            ws = week_start.strftime("%Y-%m-%d")
            we = week_end.strftime("%Y-%m-%d")

            existing = conn.execute(
                "SELECT id, total_minutes FROM attendance WHERE intern_id=? AND week_start=?",
                (intern_id, ws)
            ).fetchone()

            if existing:
                new_total = existing["total_minutes"] + 3
                conn.execute(
                    "UPDATE attendance SET total_minutes=?, updated_at=? WHERE id=?",
                    (new_total, now_str(), existing["id"])
                )
            else:
                new_total = 3
                conn.execute(
                    "INSERT INTO attendance (intern_id,week_start,week_end,total_minutes,updated_at) VALUES (?,?,?,?,?)",
                    (intern_id, ws, we, new_total, now_str())
                )
            conn.commit()

        hours   = new_total // 60
        minutes = new_total % 60
        return jsonify({
            "status":        "success",
            "total_minutes": new_total,
            "hours":         hours,
            "minutes":       minutes,
            "week_start":    ws,
            "week_end":      we,
        })
    except Exception as e:
        log_error("attendance-ping", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/attendance")
def intern_attendance():
    """Return full attendance history for the logged-in intern."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        with get_db() as conn:
            acct = conn.execute(
                "SELECT id FROM intern_accounts WHERE email=? AND is_active=1", (user["email"],)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found"}), 404

            rows = conn.execute(
                "SELECT * FROM attendance WHERE intern_id=? ORDER BY week_start DESC",
                (acct["id"],)
            ).fetchall()

        week_start, week_end = get_week_bounds()
        ws = week_start.strftime("%Y-%m-%d")

        weeks = []
        for r in rows:
            total_mins = r["total_minutes"] or 0
            weeks.append({
                "week_start":    r["week_start"],
                "week_end":      r["week_end"],
                "total_minutes": total_mins,
                "hours":         total_mins // 60,
                "minutes":       total_mins % 60,
                "met_threshold": total_mins >= 600,   # 10 hours
                "is_current":    r["week_start"] == ws,
            })

        # Current week might not have a row yet â€” inject a zero row
        has_current = any(w["is_current"] for w in weeks)
        if not has_current:
            weeks.insert(0, {
                "week_start":    ws,
                "week_end":      week_end.strftime("%Y-%m-%d"),
                "total_minutes": 0,
                "hours":         0,
                "minutes":       0,
                "met_threshold": False,
                "is_current":    True,
            })

        return jsonify({"status": "success", "weeks": weeks})
    except Exception as e:
        log_error("intern-attendance", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/intern/tutor-progress")
@app.route("/intern/learning-progress")
def intern_tutor_progress():
    """Local guided-learning progress â€” reads course_enrollments,
    course_day_quizzes, day_quiz_attempts, course_subtopics."""
    try:
        user = require_role("intern")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            acct = conn.execute(
                "SELECT id FROM intern_accounts WHERE email=? AND is_active=1",
                (user["email"],)
            ).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found"}), 404

            enrollments = conn.execute(
                "SELECT ce.*, c.title, c.slug FROM course_enrollments ce "
                "JOIN courses c ON c.id = ce.course_id WHERE ce.intern_id = ?",
                (acct["id"],)
            ).fetchall()

            courses_progress = []
            overall_pct = 0
            for enr in enrollments:
                enr_d = row_to_dict(enr)
                course_id = enr_d["course_id"]
                enr_id = enr_d["id"]

                total_days = conn.execute(
                    "SELECT MAX(day_number) FROM course_day_quizzes WHERE course_id=?",
                    (course_id,)
                ).fetchone()[0] or 0

                quizzes = [row_to_dict(r) for r in conn.execute(
                    "SELECT dqa.*, cdq.day_number, "
                    "('Day ' || cdq.day_number || ' Quiz') as title "
                    "FROM day_quiz_attempts dqa "
                    "JOIN course_day_quizzes cdq ON cdq.id = dqa.day_quiz_id "
                    # day_quiz_attempts records created_at, not attempted_at â€”
                    # the second of two bad column names in this query.
                    "WHERE dqa.enrollment_id = ? ORDER BY dqa.created_at DESC",
                    (enr_id,)
                ).fetchall()]

                chapters = conn.execute(
                    # course_chapters is ordered by day_number â€” it has no
                    # sort_order column (that is on course_subtopics). Ordering
                    # by a non-existent column raised OperationalError, so this
                    # endpoint returned {"status":"error"} for every intern with
                    # an enrolled course and the Learning tab stayed empty.
                    "SELECT * FROM course_chapters WHERE course_id=? ORDER BY day_number",
                    (course_id,)
                ).fetchall()
                lessons = []
                for ch in chapters:
                    subtopics = conn.execute(
                        "SELECT * FROM course_subtopics WHERE chapter_id=? ORDER BY sort_order",
                        (ch["id"],)
                    ).fetchall()
                    for st in subtopics:
                        lessons.append({
                            "day_number": st["sort_order"],
                            "title": st["title"],
                            "status": "completed" if (enr_d["current_day"] or 1) > (st["sort_order"] or 0) else "pending",
                        })

                current_day = enr_d["current_day"] or 1
                pct = round(((current_day - 1) / total_days * 100) if total_days > 0 else 0, 1)
                overall_pct = max(overall_pct, pct)

                courses_progress.append({
                    "course_id": course_id,
                    "title": enr_d.get("title", ""),
                    "current_day": current_day,
                    "total_days": total_days,
                    "completion_pct": pct,
                    "lessons": lessons,
                    "quizzes": quizzes,
                    "projects": [],
                    "done_lessons": max(0, current_day - 1),
                    "total_lessons": len(lessons) or total_days,
                    "updated_at": enr_d.get("last_accessed_at", ""),
                })

        data_payload = courses_progress[0] if courses_progress else {
            "lessons": [], "quizzes": [], "projects": [],
            "completion_pct": 0, "total_lessons": 0, "done_lessons": 0, "updated_at": ""
        }

        return jsonify({
            "status": "ok",
            "source": "local",
            "data": data_payload,
            "all_courses": courses_progress,
            "overall_completion_pct": overall_pct,
        })
    except Exception as e:
        log_error("intern-tutor-progress", e)
        return jsonify({"status": "error", "message": "Error"}), 500

def link_device_to_email(visitor_id, email):
    """Stamp the intern's email onto their device_profiles row (keyed by visitor_id)."""
    visitor_id = clean_text(visitor_id)
    email = clean_text(email).lower()
    if not visitor_id or not email:
        return
    try:
        with get_db() as conn:
            conn.execute("UPDATE device_profiles SET email=? WHERE visitor_id=?", (email, visitor_id))
            conn.commit()
    except Exception as e:
        log_error("link-device-email", e)


@app.route("/track-visit", methods=["POST"])
def track_visit():
    try:
        data = request.get_json(force=True)
        visitor_id   = clean_text(str(data.get("visitor_id") or "")[:64]) or secrets.token_hex(8)
        intent_score = calculate_intent_score(data)
        with get_db() as conn:
            conn.execute("""
                INSERT INTO device_profiles
                (visitor_id,email,ip_address,user_agent,screen_res,timezone,language,
                device_type,referrer,is_return_visit,visit_count,time_on_page,intent_score,path,last_seen,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(visitor_id) DO UPDATE SET
                    email        = COALESCE(excluded.email, device_profiles.email),
                    ip_address   = excluded.ip_address,
                    user_agent   = excluded.user_agent,
                    screen_res   = excluded.screen_res,
                    timezone     = excluded.timezone,
                    language     = excluded.language,
                    device_type  = excluded.device_type,
                    referrer     = excluded.referrer,
                    is_return_visit = 1,
                    visit_count  = device_profiles.visit_count + 1,
                    time_on_page = excluded.time_on_page,
                    intent_score = excluded.intent_score,
                    path         = excluded.path,
                    last_seen    = excluded.last_seen
            """, (
                visitor_id,
                clean_text(data.get("email")).lower() or None,
                get_client_ip(),
                request.headers.get("User-Agent", "")[:500],
                clean_text(data.get("screen_res")),
                clean_text(data.get("timezone")),
                clean_text(data.get("language")),
                clean_text(data.get("device_type")),
                clean_text(data.get("referrer")),
                1 if data.get("return_visit") else 0,
                max(0, min(10000, int(data.get("visit_count", 1) or 1))),
                max(0, min(86400, int(data.get("time_on_page", 0) or 0))),
                intent_score,
                clean_text(data.get("path")) or "/",
                now_str(), now_str(),
            ))
            conn.commit()
        return jsonify({"status": "success", "visitor_id": visitor_id, "intent_score": intent_score})
    except Exception as e:
        log_error("track-visit", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/status")
def check_status():
    try:
        user = get_current_user()
        if not user or user.get("role") != "intern":
            return jsonify({"status": "error", "message": "Authentication required."}), 401
            
        email = request.args.get("email", "").strip().lower()
        if not email or not is_valid_email(email):
            email = user.get("email", "")
            
        if email != user.get("email"):
            return jsonify({"status": "error", "message": "You can only check your own status."}), 403
            
            return jsonify({"status": "error", "message": "Valid email required."}), 400
        with get_db() as conn:
            conn.execute("INSERT INTO check_log (timestamp,email,check_count,ip) VALUES (?,?,?,?)",
                         (now_str(), email, 1, get_client_ip()))
            apps = conn.execute(
                "SELECT * FROM applications WHERE email=? ORDER BY created_at DESC", (email,)
            ).fetchall()
            enr = conn.execute(
                "SELECT * FROM enrollments WHERE email=? ORDER BY id DESC LIMIT 1", (email,)
            ).fetchone()
            conn.commit()
        if not apps:
            return jsonify({"status": "success", "found": False, "message": "No application found."})
        return jsonify({
            "status": "success", "found": True,
            "applications": [{
                "id": r["id"], "name": r["name"], "domain": r["domain"],
                "app_status": r["status"], "mentor_note": r["mentor_note"] or "",
                "created_at": r["created_at"], "relative_time": _relative_time(r["created_at"]),
            } for r in apps],
            "enrollment": {
                "domain": enr["domain"], "joining_date": enr["joining_date"],
                "batch_label": enr["batch_label"], "payment_status": enr["payment_status"],
            } if enr else None,
        })
    except Exception as e:
        log_error("status", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MENTOR API
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/mentor/me")
def mentor_me():
    try:
        user = require_role("mentor")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            mentor = conn.execute(
                "SELECT id,name,email,domain,is_active,created_at FROM mentors WHERE email=? AND is_active=1",
                (user["email"],)
            ).fetchone()
        if not mentor:
            return jsonify({"status": "error", "message": "Mentor not found."}), 404
        return jsonify({"status": "success", "mentor": row_to_dict(mentor)})
    except Exception as e:
        log_error("mentor-me", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/mentor/applications")
def mentor_applications():
    try:
        user = require_role("mentor")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            mentor = conn.execute(
                "SELECT * FROM mentors WHERE email=? AND is_active=1", (user["email"],)
            ).fetchone()
            if not mentor:
                return jsonify({"status": "error", "message": "Mentor not found."}), 404
            rows = conn.execute("""
                SELECT a.*,e.payment_status,e.joining_date FROM applications a
                LEFT JOIN enrollments e ON e.email=a.email AND e.domain=a.domain
                WHERE a.mentor_email=? ORDER BY a.created_at DESC
            """, (user["email"],)).fetchall()
        return jsonify({
            "status": "success",
            "mentor": row_to_dict(mentor),
            "applications": [row_to_dict(r) for r in rows],
        })
    except Exception as e:
        log_error("mentor-applications", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/mentor/update-status", methods=["POST"])
def mentor_update_status():
    try:
        user = require_role("mentor")
        if not user:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data       = request.get_json(force=True)
        app_id     = data.get("id")
        new_status = clean_text(data.get("status"))
        note       = clean_text(data.get("note")) or ""
        ALLOWED = {STATUS_UNDER_REVIEW, STATUS_ON_HOLD, STATUS_SELECTED, STATUS_ENROLLMENT_PENDING, STATUS_REJECTED}
        if not app_id or not new_status:
            return jsonify({"status": "error", "message": "id and status required."}), 400
        if new_status not in ALLOWED:
            return jsonify({"status": "error", "message": "Not allowed to set this status."}), 403
        with get_db() as conn:
            app_row = conn.execute(
                "SELECT * FROM applications WHERE id=? AND mentor_email=?", (app_id, user["email"])
            ).fetchone()
            if not app_row:
                return jsonify({"status": "error", "message": "Application not found."}), 404
            old_status = app_row["status"]
            rejected_at_val = now_str() if new_status == STATUS_REJECTED else app_row["rejected_at"]
            conn.execute(
                "UPDATE applications SET status=?,mentor_note=?,reviewed_at=?,rejected_at=?,updated_at=? WHERE id=?",
                (new_status, note, now_str(), rejected_at_val, now_str(), app_id)
            )
            conn.commit()
        if old_status != new_status:
            send_status_update_email(app_row["name"], app_row["email"], app_row["domain"], new_status, note)
        return jsonify({"status": "success", "message": f"Status updated to {new_status}."})
    except Exception as e:
        log_error("mentor-update-status", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ADMIN API
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/admin/stats")
def admin_stats():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            def cnt(q, *a): return conn.execute(q, a).fetchone()["c"]
            total_apps  = cnt("SELECT COUNT(*) as c FROM applications")
            domain_stats = conn.execute(
                "SELECT domain,COUNT(*) as count FROM applications GROUP BY domain ORDER BY count DESC"
            ).fetchall()

            # Attendance â€” interns below threshold this week
            week_start, _ = get_week_bounds()
            ws = week_start.strftime("%Y-%m-%d")
            accepted_emails = conn.execute(
                "SELECT email FROM applications WHERE status=?", (STATUS_ACCEPTED,)
            ).fetchall()
            accepted_ids = []
            for row in accepted_emails:
                acct = conn.execute(
                    "SELECT id FROM intern_accounts WHERE email=? AND is_active=1", (row["email"],)
                ).fetchone()
                if acct:
                    accepted_ids.append(acct["id"])

            below_threshold = 0
            for iid in accepted_ids:
                att = conn.execute(
                    "SELECT total_minutes FROM attendance WHERE intern_id=? AND week_start=?",
                    (iid, ws)
                ).fetchone()
                if not att or att["total_minutes"] < 600:
                    below_threshold += 1

        return jsonify({
            "status": "success",
            "stats": {
                "total_applications": total_apps,
                "total_candidates":   cnt("SELECT COUNT(DISTINCT email) as c FROM applications"),
                "under_review":       cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_UNDER_REVIEW),
                "selected":           cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_SELECTED),
                "enrolled":           cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_ENROLLED),
                "accepted":           cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_ACCEPTED),
                "rejected":           cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_REJECTED),
                "on_hold":            cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_ON_HOLD),
                "total_enrollments":  cnt("SELECT COUNT(*) as c FROM enrollments"),
                "free_enrollments":   cnt("SELECT COUNT(*) as c FROM enrollments WHERE product='free_deposit' OR product IS NULL"),
                "paid_enrollments":   cnt("SELECT COUNT(*) as c FROM enrollments WHERE product='paid_program'"),
                "paid_enrolled":      cnt("SELECT COUNT(*) as c FROM applications WHERE status=?", STATUS_PAID_ENROLLED),
                "pending_payments":   cnt("SELECT COUNT(*) as c FROM enrollments WHERE payment_status='Pending Verification'"),
                "total_mentors":      cnt("SELECT COUNT(*) as c FROM mentors WHERE is_active=1"),
                "total_visits":       cnt("SELECT COUNT(*) as c FROM device_profiles"),
                "below_threshold_this_week": below_threshold,
            },
            "domain_stats": [row_to_dict(r) for r in domain_stats],
        })
    except Exception as e:
        log_error("admin-stats", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/attendance")
def admin_attendance():
    """Return attendance data for all accepted interns â€” for the Attendance tab."""
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

        week_start, week_end = get_week_bounds()
        ws = week_start.strftime("%Y-%m-%d")

        with get_db() as conn:
            # Get all accepted interns
            accepted = conn.execute("""
                SELECT ia.id, ia.name, ia.email, ia.domain,
                       e.joining_date, e.batch_label
                FROM intern_accounts ia
                JOIN applications a ON a.email = ia.email
                LEFT JOIN enrollments e ON e.email = ia.email
                WHERE a.status = ? AND ia.is_active = 1
                GROUP BY ia.id
                ORDER BY ia.name ASC
            """, (STATUS_ACCEPTED,)).fetchall()

            result = []
            for intern in accepted:
                iid = intern["id"]
                # Current week
                cur_att = conn.execute(
                    "SELECT total_minutes FROM attendance WHERE intern_id=? AND week_start=?",
                    (iid, ws)
                ).fetchone()
                cur_mins = cur_att["total_minutes"] if cur_att else 0

                # All weeks history
                all_weeks = conn.execute(
                    "SELECT * FROM attendance WHERE intern_id=? ORDER BY week_start DESC",
                    (iid,)
                ).fetchall()

                weeks_below = sum(1 for w in all_weeks if w["total_minutes"] < 600)

                result.append({
                    "intern_id":       iid,
                    "name":            intern["name"],
                    "email":           intern["email"],
                    "domain":          intern["domain"],
                    "joining_date":    intern["joining_date"] or "",
                    "batch_label":     intern["batch_label"] or "",
                    "current_week_minutes": cur_mins,
                    "current_week_hours":   cur_mins // 60,
                    "current_week_mins_rem": cur_mins % 60,
                    "met_threshold":   cur_mins >= 600,
                    "weeks_below_total": weeks_below,
                    "week_start":      ws,
                    "week_end":        week_end.strftime("%Y-%m-%d"),
                    "all_weeks": [{
                        "week_start":    w["week_start"],
                        "week_end":      w["week_end"],
                        "total_minutes": w["total_minutes"],
                        "hours":         w["total_minutes"] // 60,
                        "minutes":       w["total_minutes"] % 60,
                        "met_threshold": w["total_minutes"] >= 600,
                    } for w in all_weeks],
                })

        below_count = sum(1 for r in result if not r["met_threshold"])
        return jsonify({
            "status": "success",
            "interns": result,
            "below_threshold_count": below_count,
            "week_start": ws,
            "week_end":   week_end.strftime("%Y-%m-%d"),
        })
    except Exception as e:
        log_error("admin-attendance", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/job-applications")
def admin_job_applications():
    """Admin-wide view of post_applications (job-board applications) across every
    company/post -- previously the admin dashboard only saw the legacy `applications`
    table and had no visibility into who applied to which posted job/internship."""
    if not require_admin():
        return redirect("/admin-login")
    with get_db() as conn:
        rows = conn.execute(
            "SELECT pa.id, pa.status, pa.created_at, "
            "a.name AS intern_name, a.email AS intern_email, a.college AS college, "
            "p.id AS post_id, p.title AS post_title, p.domain AS domain, p.post_type AS post_type, "
            "co.name AS company_name "
            "FROM post_applications pa "
            "JOIN intern_accounts a ON a.id = pa.intern_id "
            "JOIN posts p ON p.id = pa.post_id "
            "JOIN companies co ON co.id = p.company_id "
            "ORDER BY pa.id DESC"
        ).fetchall()
        counts = conn.execute(
            "SELECT status, COUNT(*) AS n FROM post_applications GROUP BY status"
        ).fetchall()
    status_counts = {s: 0 for s in APPLICATION_STATUSES}
    for r in counts:
        if r["status"] in status_counts:
            status_counts[r["status"]] = r["n"]
    badge_map = {
        "Applied": "applied", "Shortlisted": "shortlisted", "Rejected": "rejected",
        "Hired": "hired", APP_STATUS_PENDING_CERTS: "pendingcerts",
    }
    apps_out = []
    for r in rows:
        d = row_to_dict(r)
        d["badge_class"] = badge_map.get(d["status"], "applied")
        apps_out.append(d)
    return render_template(
        "admin_job_applications.html",
        applications=apps_out,
        statuses=APPLICATION_STATUSES,
        status_counts=status_counts,
        domains=VALID_DOMAINS,
    )


@app.route("/admin/applications")
def admin_applications():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
            counts = conn.execute("SELECT email, COUNT(*) AS c FROM applications GROUP BY email").fetchall()
        # Phase 9: sibling_count = OTHER applications by the same email (computed in Python, no N+1)
        by_email = {(r["email"] or "").lower(): r["c"] for r in counts}
        apps = []
        for r in rows:
            d = row_to_dict(r)
            d["sibling_count"] = max(0, by_email.get((d["email"] or "").lower(), 1) - 1)
            apps.append(d)
        return jsonify({"status": "success", "applications": apps})
    except Exception as e:
        log_error("admin-applications", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/enrollments")
def admin_enrollments():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        sf = request.args.get("status", "all")
        with get_db() as conn:
            base_q = """
                SELECT e.*,
                       COALESCE(
                           (SELECT ROUND(((ce.current_day - 1) * 100.0) / NULLIF(
                               (SELECT MAX(day_number) FROM course_day_quizzes WHERE course_id = ce.course_id), 0
                           ), 1) FROM course_enrollments ce WHERE ce.intern_id = ia.id LIMIT 1),
                       0) AS tutor_completion_pct
                FROM enrollments e
                LEFT JOIN intern_accounts ia ON ia.email = e.email AND ia.is_active = 1
            """
            if sf == "pending":
                rows = conn.execute(
                    base_q + " WHERE e.payment_status='Pending Verification' ORDER BY e.created_at DESC"
                ).fetchall()
            elif sf == "accepted":
                rows = conn.execute(
                    base_q + " WHERE e.payment_status='Accepted' ORDER BY e.created_at DESC"
                ).fetchall()
            elif sf == "rejected":
                rows = conn.execute(
                    base_q + " WHERE e.payment_status='Rejected' ORDER BY e.created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    base_q + " ORDER BY e.created_at DESC"
                ).fetchall()
            total_apps     = conn.execute("SELECT COUNT(*) as c FROM applications").fetchone()["c"]
            pending_pay    = conn.execute("SELECT COUNT(*) as c FROM enrollments WHERE payment_status='Pending Verification'").fetchone()["c"]
            total_accepted = conn.execute("SELECT COUNT(*) as c FROM enrollments WHERE payment_status='Accepted'").fetchone()["c"]
            total_visits   = conn.execute("SELECT COUNT(*) as c FROM device_profiles").fetchone()["c"]
            free_count     = conn.execute("SELECT COUNT(*) as c FROM enrollments WHERE product='free_deposit' OR product IS NULL").fetchone()["c"]
            paid_count     = conn.execute("SELECT COUNT(*) as c FROM enrollments WHERE product='paid_program'").fetchone()["c"]
        return jsonify({
            "status": "success",
            "enrollments": [row_to_dict(r) for r in rows],
            "stats": {
                "total_applications": total_apps,
                "pending_payments":   pending_pay,
                "accepted":           total_accepted,
                "total_visits":       total_visits,
                "free_enrollments":   free_count,
                "paid_enrollments":   paid_count,
            },
        })
    except Exception as e:
        log_error("admin-enrollments", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/enrollment/review", methods=["POST"])
def admin_enrollment_review():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data   = request.get_json(force=True)
        eid    = data.get("enrollment_id")
        action = clean_text(data.get("action"))
        note   = clean_text(data.get("note")) or ""
        if not eid or action not in ("accept", "reject"):
            return jsonify({"status": "error", "message": "enrollment_id and action required."}), 400
        nps = "Accepted" if action == "accept" else "Rejected"
        with get_db() as conn:
            enr = conn.execute("SELECT * FROM enrollments WHERE id=?", (eid,)).fetchone()
            if not enr:
                return jsonify({"status": "error", "message": "Enrollment not found."}), 404
            ops = enr["payment_status"]
            is_paid = (enr["product"] or "free_deposit") == "paid_program"
            reject_status = STATUS_PAID_ENROLLED if is_paid else STATUS_ENROLLMENT_PENDING
            conn.execute("UPDATE enrollments SET payment_status=?,admin_note=?,updated_at=? WHERE id=?",
                         (nps, note, now_str(), eid))
            conn.execute("UPDATE applications SET status=?,updated_at=? WHERE email=? AND domain=?",
                         (STATUS_ACCEPTED if action == "accept" else reject_status,
                          now_str(), enr["email"], enr["domain"]))
            if action == "accept":
                acct = conn.execute("SELECT id, name FROM intern_accounts WHERE email=?",
                                    (enr["email"],)).fetchone()
                if acct:
                    # Â§6.1 â€” an Accepted intern becomes an ambassador: mint their
                    # code here so the tab has something to show on first visit.
                    try:
                        ensure_referral_code(conn, acct["id"], acct["name"])
                    except Exception as e:
                        log_error("referral-code-mint", e)
                    # Â§6.3 â€” the enrolment fee is a verified payment too.
                    try:
                        credit_referral_commission(
                            conn, acct["id"], enr["amount"] if "amount" in enr.keys() else UPI_AMOUNT,
                            "programme enrolment", ref_payment_id=f"enrollment_{eid}")
                    except Exception as e:
                        log_error("referral-commission-enrollment", e)
            conn.commit()
        if ops != nps:
            ed = row_to_dict(enr)
            joining_date = ed.get("joining_date", "")
            if action == "accept":
                send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ACCEPTED,
                                         "Payment verified. You're confirmed!", joining_date)
            elif is_paid:
                send_paid_payment_rejected_email(ed["name"], ed["email"], ed["domain"])
            else:
                send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ENROLLMENT_PENDING,
                                         note or "Payment screenshot could not be verified. Please re-submit.")
        return jsonify({"status": "success", "message": f"Enrollment {nps}."})
    except Exception as e:
        log_error("admin-enrollment-review", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/enrollment/bulk-review", methods=["POST"])
def admin_enrollment_bulk_review():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data   = request.get_json(force=True)
        ids    = data.get("ids", [])
        action = clean_text(data.get("action"))
        note   = clean_text(data.get("note")) or ""
        if not ids or action not in ("accept", "reject"):
            return jsonify({"status": "error", "message": "ids[] and action required."}), 400
        nps = "Accepted" if action == "accept" else "Rejected"
        processed = 0
        with get_db() as conn:
            for eid in ids:
                try:
                    enr = conn.execute("SELECT * FROM enrollments WHERE id=?", (eid,)).fetchone()
                    if not enr: continue
                    ops = enr["payment_status"]
                    is_paid = (enr["product"] or "free_deposit") == "paid_program"
                    reject_status = STATUS_PAID_ENROLLED if is_paid else STATUS_ENROLLMENT_PENDING
                    conn.execute("UPDATE enrollments SET payment_status=?,admin_note=?,updated_at=? WHERE id=?",
                                 (nps, note, now_str(), eid))
                    conn.execute("UPDATE applications SET status=?,updated_at=? WHERE email=? AND domain=?",
                                 (STATUS_ACCEPTED if action == "accept" else reject_status,
                                  now_str(), enr["email"], enr["domain"]))
                    if ops != nps:
                        ed = row_to_dict(enr)
                        joining_date = ed.get("joining_date", "")
                        if action == "accept":
                            send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ACCEPTED,
                                                     "Payment verified. Confirmed!", joining_date)
                        elif is_paid:
                            send_paid_payment_rejected_email(ed["name"], ed["email"], ed["domain"])
                        else:
                            send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ENROLLMENT_PENDING,
                                                     note or "Payment could not be verified. Please re-submit.")
                    processed += 1
                except Exception as row_err:
                    log_error("bulk-row", row_err); continue
            conn.commit()
        return jsonify({"status": "success", "message": f"Bulk {action} done.", "processed": processed})
    except Exception as e:
        log_error("admin-bulk-review", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/application/update", methods=["POST"])
def admin_application_update():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data       = request.get_json(force=True)
        app_id     = data.get("application_id")
        new_status = clean_text(data.get("status")) or None
        note       = clean_text(data.get("note")) or None
        if not app_id:
            return jsonify({"status": "error", "message": "application_id required."}), 400
        if new_status and new_status not in VALID_STATUSES:
            return jsonify({"status": "error", "message": "Invalid status."}), 400
        with get_db() as conn:
            app_row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app_row:
                return jsonify({"status": "error", "message": "Application not found."}), 404
            old_status = app_row["status"]
            rejected_at_val = now_str() if new_status == STATUS_REJECTED else app_row["rejected_at"]
            if new_status and note:
                conn.execute(
                    "UPDATE applications SET status=?,mentor_note=?,reviewed_at=?,rejected_at=?,updated_at=? WHERE id=?",
                    (new_status, note, now_str(), rejected_at_val, now_str(), app_id))
            elif new_status:
                conn.execute(
                    "UPDATE applications SET status=?,reviewed_at=?,rejected_at=?,updated_at=? WHERE id=?",
                    (new_status, now_str(), rejected_at_val, now_str(), app_id))
            elif note:
                conn.execute("UPDATE applications SET mentor_note=?,updated_at=? WHERE id=?",
                             (note, now_str(), app_id))
            conn.commit()
        if new_status and old_status != new_status:
            send_status_update_email(app_row["name"], app_row["email"], app_row["domain"], new_status, note or "")
        return jsonify({"status": "success", "message": "Application updated."})
    except Exception as e:
        log_error("admin-application-update", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/update-application-status", methods=["POST"])
def admin_update_application_status():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data       = request.get_json(force=True)
        app_id     = data.get("id")
        new_status = clean_text(data.get("status"))
        note       = clean_text(data.get("note")) or ""
        if not app_id or not new_status:
            return jsonify({"status": "error", "message": "id and status required."}), 400
        if new_status not in VALID_STATUSES:
            return jsonify({"status": "error", "message": "Invalid status."}), 400
        joining_date_for_email = None
        with get_db() as conn:
            app_row = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app_row:
                return jsonify({"status": "error", "message": "Application not found."}), 404
            old_status     = app_row["status"]
            rejected_at_val = now_str() if new_status == STATUS_REJECTED else app_row["rejected_at"]
            conn.execute(
                "UPDATE applications SET status=?,mentor_note=?,reviewed_at=?,rejected_at=?,updated_at=? WHERE id=?",
                (new_status, note, now_str(), rejected_at_val, now_str(), app_id))
            if new_status == STATUS_ACCEPTED:
                joining_date_for_email = auto_assign_joining_date_on_accept(conn, app_row)
            conn.commit()
        if old_status != new_status:
            send_status_update_email(app_row["name"], app_row["email"], app_row["domain"], new_status, note, joining_date_for_email)
        return jsonify({"status": "success", "message": f"Status updated to {new_status}."})
    except Exception as e:
        log_error("admin-update-application-status", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/update-enrollment-status", methods=["POST"])
def admin_update_enrollment_status():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data = request.get_json(force=True)
        eid  = data.get("id")
        nps  = clean_text(data.get("payment_status"))
        note = clean_text(data.get("note")) or ""
        if not eid or not nps:
            return jsonify({"status": "error", "message": "id and payment_status required."}), 400
        if nps not in {"Pending Verification", "Accepted", "Rejected"}:
            return jsonify({"status": "error", "message": "Invalid payment status."}), 400
        with get_db() as conn:
            enr = conn.execute("SELECT * FROM enrollments WHERE id=?", (eid,)).fetchone()
            if not enr:
                return jsonify({"status": "error", "message": "Enrollment not found."}), 404
            ops = enr["payment_status"]
            is_paid = (enr["product"] or "free_deposit") == "paid_program"
            reject_status = STATUS_PAID_ENROLLED if is_paid else STATUS_ENROLLMENT_PENDING
            conn.execute("UPDATE enrollments SET payment_status=?,admin_note=?,updated_at=? WHERE id=?",
                         (nps, note, now_str(), eid))
            if nps == "Accepted":
                conn.execute("UPDATE applications SET status=?,updated_at=? WHERE email=? AND domain=?",
                             (STATUS_ACCEPTED, now_str(), enr["email"], enr["domain"]))
            elif nps == "Rejected":
                conn.execute("UPDATE applications SET status=?,updated_at=? WHERE email=? AND domain=?",
                             (reject_status, now_str(), enr["email"], enr["domain"]))
            conn.commit()
        if ops != nps:
            ed = row_to_dict(enr)
            joining_date = ed.get("joining_date", "")
            if nps == "Accepted":
                send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ACCEPTED,
                                         "Payment verified. You're confirmed!", joining_date)
            elif nps == "Rejected" and is_paid:
                send_paid_payment_rejected_email(ed["name"], ed["email"], ed["domain"])
            elif nps == "Rejected":
                send_status_update_email(ed["name"], ed["email"], ed["domain"], STATUS_ENROLLMENT_PENDING,
                                         note or "Payment could not be verified. Please re-submit.")
        return jsonify({"status": "success", "message": f"Payment status updated to {nps}."})
    except Exception as e:
        log_error("admin-update-enrollment-status", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/push-test", methods=["POST"])
def admin_push_test():
    """Admin-only self-test: send one push to an external_id and return OneSignal's raw
    response so live delivery can be verified without guessing."""
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if not ONESIGNAL_APP_ID or not ONESIGNAL_REST_API_KEY:
            return jsonify({"status": "error", "message": "OneSignal not configured."}), 400
        data  = request.get_json(force=True)
        email = clean_text(data.get("email"))
        if not email:
            return jsonify({"status": "error", "message": "email required."}), 400
        title   = clean_text(data.get("title"))   or "DBERT test push"
        message = clean_text(data.get("message")) or "If you can see this, push delivery is working."
        resp = _onesignal_post(email, title, message, "https://internship.dbert.online")
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        ok = 200 <= resp.status_code < 300
        if not ok:
            log_error("onesignal-push", f"HTTP {resp.status_code}: {resp.text}")
        return jsonify({"status": "success" if ok else "error",
                        "http_status": resp.status_code,
                        "onesignal": body}), (200 if ok else 502)
    except Exception as e:
        log_error("admin-push-test", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/users")
def admin_users():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        # Phase 9: one row per PERSON (intern_accounts), with an application summary.
        rank = {STATUS_ACCEPTED: 7, STATUS_PAID_ENROLLED: 6, STATUS_ENROLLED: 6,
                STATUS_ENROLLMENT_PENDING: 5, STATUS_SELECTED: 4, STATUS_UNDER_REVIEW: 3,
                STATUS_ON_HOLD: 2, STATUS_APPLY_PENDING: 1, STATUS_REJECTED: 0}
        with get_db() as conn:
            accounts = conn.execute("""
                SELECT ia.id, ia.name, ia.email, ia.phone, ia.city, ia.college, ia.course,
                       ia.year_of_passing, ia.is_active, ia.password_set,
                       ia.tutor_completion_pct, ia.created_at,
                       COALESCE(dp.intent_score, 0) AS intent_score
                FROM intern_accounts ia
                LEFT JOIN device_profiles dp ON dp.email = ia.email
                ORDER BY ia.created_at DESC
            """).fetchall()
            apps = conn.execute("SELECT email, domain, status FROM applications").fetchall()
        by_email = {}
        for a in apps:
            by_email.setdefault((a["email"] or "").lower(), []).append(
                {"domain": a["domain"], "status": a["status"]})
        users = []
        for r in accounts:
            d = row_to_dict(r)
            mine = by_email.get((d["email"] or "").lower(), [])
            d["application_count"] = len(mine)
            d["applications"] = mine
            d["domains"] = ", ".join(m["domain"] for m in mine if m["domain"])
            d["furthest_status"] = max(mine, key=lambda m: rank.get(m["status"], -1))["status"] if mine else ""
            d["multi_flag"] = len(mine) > 1
            users.append(d)
        return jsonify({"status": "success", "users": users})
    except Exception as e:
        log_error("admin-users", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/devices")
def admin_devices():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM device_profiles ORDER BY created_at DESC LIMIT 500").fetchall()
        return jsonify({"status": "success", "devices": [row_to_dict(r) for r in rows]})
    except Exception as e:
        log_error("admin-devices", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/abuse-log")
def admin_abuse_log():
    """Phase 8.6: read-only recent abuse/blocked events for the admin Security tab."""
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, timestamp, ip, route, bucket, reason, email FROM abuse_log ORDER BY id DESC LIMIT 200"
            ).fetchall()
        return jsonify({"status": "success", "events": [row_to_dict(r) for r in rows]})
    except Exception as e:
        log_error("admin-abuse-log", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/mentors")
def admin_mentors():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM mentors ORDER BY created_at DESC").fetchall()
        return jsonify({"status": "success", "mentors": [row_to_dict(r) for r in rows]})
    except Exception as e:
        log_error("admin-mentors", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/add-mentor", methods=["POST"])
def admin_add_mentor():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data     = request.get_json(force=True)
        name     = clean_text(data.get("name"))
        email    = clean_text(data.get("email")).lower()
        domain   = clean_text(data.get("domain"))
        password = clean_text(data.get("password")) or generate_password(10)
        if not all([name, email, domain]):
            return jsonify({"status": "error", "message": "Name, email, domain required."}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Invalid email."}), 400
        if domain not in VALID_DOMAINS:
            return jsonify({"status": "error", "message": "Invalid domain."}), 400
        pw_hash = set_password_hash(password)
        with get_db() as conn:
            if conn.execute("SELECT id FROM mentors WHERE email=?", (email,)).fetchone():
                conn.execute("UPDATE mentors SET name=?,domain=?,password_hash=?,is_active=1,updated_at=? WHERE email=?",
                             (name, domain, pw_hash, now_str(), email))
            else:
                conn.execute("INSERT INTO mentors (name,email,domain,password_hash,is_active,created_at,updated_at) VALUES (?,?,?,?,1,?,?)",
                             (name, email, domain, pw_hash, now_str(), now_str()))
            conn.commit()
        return jsonify({"status": "success", "message": "Mentor added/updated.", "generated_password": password})
    except Exception as e:
        log_error("admin-add-mentor", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/delete-mentor", methods=["POST"])
def admin_delete_mentor():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data = request.get_json(force=True)
        mid  = data.get("id")
        if not mid:
            return jsonify({"status": "error", "message": "Mentor ID required."}), 400
        with get_db() as conn:
            conn.execute("UPDATE mentors SET is_active=0,updated_at=? WHERE id=?", (now_str(), mid))
            conn.commit()
        return jsonify({"status": "success", "message": "Mentor deactivated."})
    except Exception as e:
        log_error("admin-delete-mentor", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/add-application", methods=["POST"])
def admin_add_application():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data            = request.get_json(force=True)
        name            = clean_text(data.get("name"))
        email           = clean_text(data.get("email")).lower()
        phone           = clean_text(data.get("phone"))
        city            = clean_text(data.get("city"))
        college         = clean_text(data.get("college"))
        course          = clean_text(data.get("course"))
        semester        = clean_text(data.get("semester"))
        year_of_passing = clean_text(data.get("year_of_passing"))
        domain          = clean_text(data.get("domain"))
        why_join        = clean_text(data.get("why_join")) or "Added by admin."
        portfolio       = clean_text(data.get("portfolio"))
        initial_status  = clean_text(data.get("initial_status")) or STATUS_UNDER_REVIEW
        if not all([name, email, phone, city, college, course, semester, year_of_passing, domain]):
            return jsonify({"status": "error", "message": "Missing required fields."}), 400
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Invalid email."}), 400
        if not is_valid_phone(phone):
            return jsonify({"status": "error", "message": "Invalid phone."}), 400
        if domain not in VALID_DOMAINS:
            return jsonify({"status": "error", "message": "Invalid domain."}), 400
        if course not in VALID_COURSES:
            return jsonify({"status": "error", "message": "Invalid course."}), 400
        if semester not in VALID_SEMESTERS:
            return jsonify({"status": "error", "message": "Invalid semester."}), 400
        if year_of_passing not in VALID_YEARS:
            return jsonify({"status": "error", "message": "Invalid year."}), 400
        if initial_status not in VALID_STATUSES:
            initial_status = STATUS_UNDER_REVIEW
        mentor_email = assign_mentor_email(domain)
        with get_db() as conn:
            existing = conn.execute(
                "SELECT * FROM applications WHERE email=? AND domain=?", (email, domain)
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE applications SET name=?,phone=?,city=?,college=?,course=?,semester=?,year_of_passing=?,
                    why_join=?,portfolio=?,status=?,mentor_email=?,updated_at=? WHERE email=? AND domain=?
                """, (name, phone, city, college, course, semester, year_of_passing, why_join, portfolio,
                      initial_status, mentor_email, now_str(), email, domain))
                application_id = existing["id"]
            else:
                cur = conn.execute("""
                    INSERT INTO applications (name,email,phone,city,college,course,semester,year_of_passing,domain,
                    why_join,portfolio,status,mentor_email,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (name, email, phone, city, college, course, semester, year_of_passing, domain,
                      why_join, portfolio, initial_status, mentor_email, "admin", now_str(), now_str()))
                application_id = cur.lastrowid
            acct = conn.execute("SELECT * FROM intern_accounts WHERE email=?", (email,)).fetchone()
            if acct:
                conn.execute("""
                    UPDATE intern_accounts SET application_id=?,name=?,phone=?,city=?,college=?,course=?,
                    semester=?,year_of_passing=?,domain=?,updated_at=? WHERE email=?
                """, (application_id, name, phone, city, college, course, semester, year_of_passing, domain, now_str(), email))
            else:
                conn.execute("""
                    INSERT INTO intern_accounts (application_id,name,email,phone,city,college,course,semester,
                    year_of_passing,domain,password_hash,password_set,is_active,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (application_id, name, email, phone, city, college, course, semester,
                      year_of_passing, domain, "", 0, 1, now_str(), now_str()))
            conn.commit()
        return jsonify({"status": "success", "message": "Application added.", "application_id": application_id})
    except Exception as e:
        log_error("admin-add-application", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/delete-application", methods=["POST"])
def admin_delete_application():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data   = request.get_json(force=True)
        app_id = data.get("id")
        if not app_id:
            return jsonify({"status": "error", "message": "Application ID required."}), 400
        with get_db() as conn:
            conn.execute("DELETE FROM applications WHERE id=?", (app_id,))
            conn.commit()
        return jsonify({"status": "success", "message": "Application deleted."})
    except Exception as e:
        log_error("admin-delete-application", e)
        return jsonify({"status": "error", "message": "Error"}), 500


def _parse_int_ids(data):
    """Validate request body {"ids":[...]} -> list[int], or None if invalid/empty."""
    ids = (data or {}).get("ids")
    if not isinstance(ids, list) or not ids:
        return None
    out = []
    for x in ids:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            return None
    return out


def _placeholders(n):
    return ",".join(["?"] * n)


@app.route("/admin/applications/bulk-delete", methods=["POST"])
def admin_applications_bulk_delete():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ids = _parse_int_ids(request.get_json(force=True))
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        with get_db() as conn:
            cur = conn.execute(f"DELETE FROM applications WHERE id IN ({_placeholders(len(ids))})", ids)
            conn.commit()
            deleted = cur.rowcount
        return jsonify({"status": "success", "deleted": deleted})
    except Exception as e:
        log_error("admin-applications-bulk-delete", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/enrollments/bulk-delete", methods=["POST"])
def admin_enrollments_bulk_delete():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ids = _parse_int_ids(request.get_json(force=True))
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        with get_db() as conn:
            cur = conn.execute(f"DELETE FROM enrollments WHERE id IN ({_placeholders(len(ids))})", ids)
            conn.commit()
            deleted = cur.rowcount
        return jsonify({"status": "success", "deleted": deleted})
    except Exception as e:
        log_error("admin-enrollments-bulk-delete", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/mentors/bulk-delete", methods=["POST"])
def admin_mentors_bulk_delete():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ids = _parse_int_ids(request.get_json(force=True))
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        with get_db() as conn:
            cur = conn.execute(f"DELETE FROM mentors WHERE id IN ({_placeholders(len(ids))})", ids)
            conn.commit()
            deleted = cur.rowcount
        return jsonify({"status": "success", "deleted": deleted})
    except Exception as e:
        log_error("admin-mentors-bulk-delete", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/devices/bulk-delete", methods=["POST"])
def admin_devices_bulk_delete():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ids = _parse_int_ids(request.get_json(force=True))
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        with get_db() as conn:
            cur = conn.execute(f"DELETE FROM device_profiles WHERE id IN ({_placeholders(len(ids))})", ids)
            conn.commit()
            deleted = cur.rowcount
        return jsonify({"status": "success", "deleted": deleted})
    except Exception as e:
        log_error("admin-devices-bulk-delete", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/users/bulk-delete", methods=["POST"])
def admin_users_bulk_delete():
    """Cascade delete by email. Input = list of intern_accounts IDs (Phase 9: Users-tab
    rows are now one-per-person account ids, not application ids). Removes every related
    row across applications, intern_accounts, enrollments, attendance (via intern_id),
    and device_profiles. Transactional."""
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data = request.get_json(force=True)
        ids = _parse_int_ids(data)
        reason = str(data.get("reason") or "admin action")[:500]
        if not ids:
            return jsonify({"status": "error", "message": "No valid ids provided."}), 400
        admin_user = require_admin()
        actor = admin_user.get("email", "unknown") if isinstance(admin_user, dict) else "admin"
        with get_db() as conn:
            rows = conn.execute(
                f"SELECT DISTINCT email FROM intern_accounts WHERE id IN ({_placeholders(len(ids))})", ids
            ).fetchall()
            emails = [r["email"] for r in rows if r["email"]]
            deleted = 0
            for email in emails:
                # P2-3: Soft-delete: deactivate instead of hard delete
                conn.execute(
                    "UPDATE intern_accounts SET is_active=0, updated_at=? WHERE LOWER(email)=LOWER(?)",
                    (now_str(), email))
                conn.execute(
                    "UPDATE applications SET status='Deactivated', updated_at=? WHERE LOWER(email)=LOWER(?)",
                    (now_str(), email))
                # Revoke sessions
                conn.execute("DELETE FROM user_sessions WHERE LOWER(email)=LOWER(?)", (email,))
                deleted += 1
                # Audit log
                log_audit_event("USER_DEACTIVATE", f"intern:{email}", 1)
            conn.commit()
        return jsonify({"status": "success", "deactivated": deleted,
                        "message": f"{deleted} account(s) deactivated. Data retained for recovery window."})
    except Exception as e:
        log_error("admin-users-bulk-delete", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/reset-intern-password", methods=["POST"])
def admin_reset_intern_password():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        data  = request.get_json(force=True)
        email = clean_text(data.get("email")).lower()
        if not email:
            return jsonify({"status": "error", "message": "Email required."}), 400
        with get_db() as conn:
            acct = conn.execute("SELECT * FROM intern_accounts WHERE email=? AND is_active=1", (email,)).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Intern not found."}), 404
            
            # SEC-005 fix: Do not return password. Send reset link instead.
            email_role = email + "|intern"
            conn.execute("UPDATE password_resets SET used=1 WHERE email=? AND used=0", (email_role,))
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            expires_at = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO password_resets (email, token, expires_at) VALUES (?,?,?)",
                (email_role, token_hash, expires_at)
            )
            conn.commit()
            
            reset_url = f"{SITE_ORIGIN}/reset?token={token}"
            send_password_reset_email(acct["name"], email, reset_url)
            
        return jsonify({"status": "success", "message": "Password reset email sent to the intern."})
    except Exception as e:
        log_error("admin-reset-password", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CSV IMPORT / EXPORT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _csv_import_logic(file_obj):
    content = file_obj.read().decode("utf-8-sig")
    reader  = csv.DictReader(io.StringIO(content))
    total = inserted = skipped = errors = 0
    with get_db() as conn:
        for row in reader:
            total += 1
            try:
                name            = clean_text(row.get("Name") or row.get("name") or "")
                email           = clean_text(row.get("Email Address") or row.get("Email") or row.get("email") or "").lower()
                phone           = clean_text(row.get("WhatsApp number") or row.get("Phone") or row.get("phone") or "")
                raw_domain      = clean_text(row.get("Select Internship") or row.get("Domain") or row.get("domain") or "")
                college         = clean_text(row.get("College Name") or row.get("College") or row.get("college") or "") or "N/A"
                city            = clean_text(row.get("City") or row.get("city") or "") or "N/A"
                course          = clean_text(row.get("Course") or row.get("course") or "") or "B.Tech"
                year_of_passing = clean_text(row.get("Year of Passing") or row.get("year_of_passing") or "") or "2026"
                semester        = clean_text(row.get("Semester") or row.get("semester") or "1st Semester")
                raw_status      = clean_text(row.get("Status") or row.get("status") or "")
                why_join        = clean_text(row.get("Why Join") or row.get("why_join") or "") or "Imported via admin CSV."
                portfolio       = clean_text(row.get("Portfolio") or row.get("portfolio") or "")

                if not name or not email or not is_valid_email(email):
                    skipped += 1; continue
                domain = normalize_domain(raw_domain)
                if not domain:
                    skipped += 1; continue

                status = raw_status if raw_status in VALID_STATUSES else STATUS_SELECTED
                if semester not in VALID_SEMESTERS: semester = "1st Semester"
                if course not in VALID_COURSES: course = "B.Tech"
                if year_of_passing not in VALID_YEARS: year_of_passing = "2026"

                phone = re.sub(r"[\s\-\+]", "", phone)
                try:
                    if "e" in phone.lower() or ("." in phone and phone.replace(".", "").isdigit()):
                        phone = str(int(float(phone)))
                except Exception:
                    pass
                if phone.startswith("91") and len(phone) == 12:
                    phone = phone[2:]
                if len(phone) < 10:
                    phone = "0000000000"
                phone = phone[:10]

                if conn.execute(
                    "SELECT id FROM applications WHERE email=? AND domain=?", (email, domain)
                ).fetchone():
                    skipped += 1; continue

                mentor_email = assign_mentor_email(domain)
                cur = conn.execute("""
                    INSERT INTO applications (name,email,phone,city,college,course,semester,year_of_passing,
                    domain,why_join,portfolio,status,mentor_email,source,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (name, email, phone, city, college, course, semester, year_of_passing,
                      domain, why_join, portfolio, status, mentor_email, "csv", now_str(), now_str()))
                aid = cur.lastrowid
                if not conn.execute("SELECT id FROM intern_accounts WHERE email=?", (email,)).fetchone():
                    conn.execute("""
                        INSERT INTO intern_accounts (application_id,name,email,phone,city,college,course,semester,
                        year_of_passing,domain,password_hash,password_set,is_active,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (aid, name, email, phone, city, college, course, semester,
                          year_of_passing, domain, "", 0, 1, now_str(), now_str()))
                inserted += 1
            except Exception as row_err:
                log_error("csv-row", row_err)
                errors += 1; continue
        conn.commit()
    return total, inserted, skipped, errors


@app.route("/admin/upload-csv", methods=["POST"])
def admin_upload_csv():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if "csv_file" not in request.files:
            return jsonify({"status": "error", "message": "csv_file required."}), 400
        file = request.files["csv_file"]
        if not file or not file.filename.lower().endswith(".csv"):
            return jsonify({"status": "error", "message": "Only .csv files accepted."}), 400
        total, inserted, skipped, errors = _csv_import_logic(file)
        return jsonify({
            "status":  "success",
            "message": f"Import done. {inserted} inserted, {skipped} skipped, {errors} errors.",
            "stats":   {"total": total, "inserted": inserted, "skipped": skipped, "errors": errors},
        })
    except Exception as e:
        log_error("admin-upload-csv", e)
        return jsonify({"status": "error", "message": "Error"}), 500


# Track 6 addendum: bulk-import interns who are already accepted/enrolled in real
# life (e.g. an external signup sheet) with a fixed shared joining date -- distinct
# from _csv_import_logic() above, which only writes applications+intern_accounts
# and never touches enrollments. Reuses the exact same enrollments-row shape as
# auto_assign_joining_date_on_accept() for consistency with the normal Accept flow.
UI_UX_TO_FULLSTACK_ALIAS = "full stack development"  # this import's own domain remap, not global

def _csv_import_accepted_logic(file_obj, joining_date_str, admin_note=""):
    ok, msg = validate_joining_date(joining_date_str, allow_past_for_backfill=True)
    if not ok:
        raise ValueError(msg)
    content = file_obj.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    total = inserted = updated = skipped = errors = 0
    batch_label = make_batch_label(joining_date_str)
    note = admin_note or f"Bulk-imported as already-Accepted, joining {joining_date_str}."

    # BUGFIX (2026-07-07): assign_mentor_email() opens its own DB connection.
    # Calling it per-row from inside the loop below, while that loop's own
    # connection already holds an open write transaction, self-deadlocks --
    # every row stalls waiting on its own lock for up to busy_timeout (8s),
    # times every row in the file. Resolve mentors for the small set of
    # distinct domains actually in this file FIRST, before opening the write
    # transaction, and just look them up from a dict inside the loop.
    domains_seen = set()
    for row in rows:
        raw_domain = clean_text(row.get("Select Internship") or row.get("Domain") or row.get("domain") or "")
        if "ui" in raw_domain.lower() and "ux" in raw_domain.lower():
            raw_domain = UI_UX_TO_FULLSTACK_ALIAS
        d = normalize_domain(raw_domain)
        if d:
            domains_seen.add(d)
    mentor_by_domain = {d: assign_mentor_email(d) for d in domains_seen}
    to_notify = []  # (name, email, domain) tuples -- emailed only after commit, see below

    with get_db() as conn:
        for row in rows:
            total += 1
            try:
                name       = clean_text(row.get("Name") or row.get("name") or "")
                email      = clean_text(row.get("Email Address") or row.get("Email") or row.get("email") or "").lower()
                phone      = clean_text(row.get("WhatsApp number") or row.get("Phone") or row.get("phone") or "")
                raw_domain = clean_text(row.get("Select Internship") or row.get("Domain") or row.get("domain") or "")
                college    = clean_text(row.get("College Name") or row.get("College") or row.get("college") or "") or "N/A"

                if not name or not email or not is_valid_email(email):
                    skipped += 1; continue
                # This import's own domain remap: UI/UX rows count as Full Stack here.
                if "ui" in raw_domain.lower() and "ux" in raw_domain.lower():
                    raw_domain = UI_UX_TO_FULLSTACK_ALIAS
                domain = normalize_domain(raw_domain)
                if not domain:
                    skipped += 1; continue

                phone = re.sub(r"[\s\-\+]", "", phone)
                if phone.startswith("91") and len(phone) == 12:
                    phone = phone[2:]
                if len(phone) < 10:
                    phone = "0000000000"
                phone = phone[:10]
                course, semester, year_of_passing = "B.Tech", "1st Semester", "2026"
                mentor_email = mentor_by_domain.get(domain)

                existing_acct = conn.execute(
                    "SELECT id FROM intern_accounts WHERE email=?", (email,)).fetchone()
                existing_app = conn.execute(
                    "SELECT id, status FROM applications WHERE email=? AND domain=?",
                    (email, domain)).fetchone()
                just_accepted = False

                if existing_app:
                    if existing_app["status"] != STATUS_ACCEPTED:
                        conn.execute(
                            "UPDATE applications SET status=?, updated_at=? WHERE id=?",
                            (STATUS_ACCEPTED, now_str(), existing_app["id"]))
                        updated += 1
                        just_accepted = True
                    aid = existing_app["id"]
                else:
                    cur = conn.execute("""
                        INSERT INTO applications (name,email,phone,city,college,course,semester,year_of_passing,
                        domain,why_join,portfolio,status,mentor_email,source,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (name, email, phone, "N/A", college, course, semester, year_of_passing,
                          domain, "Bulk-imported as already-Accepted.", "", STATUS_ACCEPTED,
                          mentor_email, "csv-accepted", now_str(), now_str()))
                    aid = cur.lastrowid
                    inserted += 1
                    just_accepted = True

                if not existing_acct:
                    conn.execute("""
                        INSERT INTO intern_accounts (application_id,name,email,phone,city,college,course,semester,
                        year_of_passing,domain,password_hash,password_set,is_active,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (aid, name, email, phone, "N/A", college, course, semester,
                          year_of_passing, domain, "", 0, 1, now_str(), now_str()))

                existing_enr = conn.execute(
                    "SELECT id FROM enrollments WHERE email=? LIMIT 1", (email,)).fetchone()
                if not existing_enr:
                    conn.execute("""
                        INSERT INTO enrollments
                        (application_id,timestamp,name,email,phone,city,college,course,semester,
                        year_of_passing,domain,joining_date,batch_label,payment_screenshot,payment_status,
                        admin_note,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (aid, now_str(), name, email, phone, "N/A", college, course, semester,
                          year_of_passing, domain, joining_date_str, batch_label, "", STATUS_ACCEPTED,
                          note, now_str(), now_str()))

                if just_accepted:
                    to_notify.append((name, email, domain))
            except Exception as row_err:
                log_error("csv-accepted-row", row_err)
                errors += 1; continue
        conn.commit()

    # BUGFIX (2026-07-07): send_status_update_email() -> send_push_notification()
    # -> _persist_notification_for_email() also opens its own DB connection
    # synchronously (a second instance of the same deadlock class as the mentor
    # lookup above). Sending from inside the loop, while that loop's connection
    # still holds an open write transaction, stalled every row the same way.
    # The transaction is now closed and committed above -- safe to notify here.
    for name, email, domain in to_notify:
        try:
            send_status_update_email(name, email, domain, STATUS_ACCEPTED, "", joining_date_str)
        except Exception as email_err:
            log_error("csv-accepted-email", email_err)  # don't fail the import over a mailer hiccup

    return total, inserted, updated, skipped, errors


@app.route("/admin/upload-csv-accepted", methods=["POST"])
def admin_upload_csv_accepted():
    """Bulk-accept interns already enrolled in real life, with one shared joining
    date for the whole batch. Safe to re-run on the same file: existing accounts
    are never duplicated, existing applications get upgraded to Accepted rather
    than skipped, and an existing enrollment (e.g. someone who separately
    self-enrolled already) is left untouched rather than overwritten."""
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        if "csv_file" not in request.files:
            return jsonify({"status": "error", "message": "csv_file required."}), 400
        file = request.files["csv_file"]
        if not file or not file.filename.lower().endswith(".csv"):
            return jsonify({"status": "error", "message": "Only .csv files accepted."}), 400
        joining_date_str = clean_text(request.form.get("joining_date") or "")
        if not joining_date_str:
            return jsonify({"status": "error", "message": "joining_date required (YYYY-MM-DD)."}), 400
        admin_note = clean_text(request.form.get("admin_note") or "")
        total, inserted, updated, skipped, errors = _csv_import_accepted_logic(
            file, joining_date_str, admin_note)
        return jsonify({
            "status": "success",
            "message": f"Import done. {inserted} new, {updated} upgraded to Accepted, {skipped} skipped, {errors} errors.",
            "stats": {"total": total, "inserted": inserted, "updated": updated,
                      "skipped": skipped, "errors": errors},
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        log_error("admin-upload-csv-accepted", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/csv/upload", methods=["POST"])
def admin_csv_upload_legacy():
    try:
        if not require_admin():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        file = request.files.get("csv_file") or request.files.get("file")
        if not file or not file.filename.lower().endswith(".csv"):
            return jsonify({"status": "error", "message": "Only .csv files accepted."}), 400
        total, inserted, skipped, errors = _csv_import_logic(file)
        return jsonify({
            "status":   "success",
            "message":  f"Import done. {inserted} imported, {skipped} skipped.",
            "imported": inserted, "skipped": skipped,
            "stats":    {"total": total, "inserted": inserted, "skipped": skipped, "errors": errors},
        })
    except Exception as e:
        log_error("admin-csv-upload-legacy", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/admin/csv/applications")
def admin_csv_applications():
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("""
                SELECT a.*, e.joining_date AS enr_joining_date
                FROM applications a
                LEFT JOIN enrollments e ON e.email = a.email
                ORDER BY a.created_at DESC
            """).fetchall()
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["ID","Name","Email","Phone","City","College","Course","Semester",
                    "Year of Passing","Domain","Why Join","Portfolio","Status","Mentor Email",
                    "Mentor Note","Source","Rejected At","Created At","Joining Date"]])
        for r in rows:
            w.writerow([r["id"],r["name"],r["email"],r["phone"],r["city"] or "",r["college"],
                        r["course"] or "",r["semester"],r["year_of_passing"] or "",r["domain"],
                        r["why_join"],r["portfolio"] or "",r["status"],r["mentor_email"] or "",
                        r["mentor_note"] or "",r["source"] or "web",r["rejected_at"] or "",r["created_at"],
                        r["enr_joining_date"] or ""])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_applications.csv"})
    except Exception as e:
        log_error("csv-applications", e); return "Error", 500


@app.route("/admin/csv/enrollments")
def admin_csv_enrollments():
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM enrollments ORDER BY created_at DESC").fetchall()
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["ID","Name","Email","Phone","City","College","Course","Semester",
                    "Year of Passing","Domain","Joining Date","Batch Label","Payment Screenshot",
                    "Payment Status","Product","Amount","Admin Note","Created At"]])
        for r in rows:
            w.writerow([r["id"],r["name"],r["email"],r["phone"] or "",r["city"] or "",
                        r["college"] or "",r["course"] or "",r["semester"] or "",
                        r["year_of_passing"] or "",r["domain"],r["joining_date"] or "",r["batch_label"] or "",
                        r["payment_screenshot"] or "",r["payment_status"],
                        r["product"] or "free_deposit",r["amount"] if r["amount"] is not None else "",
                        r["admin_note"] or "",r["created_at"]])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_enrollments.csv"})
    except Exception as e:
        log_error("csv-enrollments", e); return "Error", 500


@app.route("/admin/csv/incomplete-signups")
def admin_csv_incomplete_signups():
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("""
                SELECT ia.id, ia.name, ia.email, ia.phone, ia.city, ia.college, ia.course,
                       ia.domain, ia.signup_stage, ia.created_at,
                       (SELECT COUNT(*) FROM applications a WHERE a.email = ia.email) AS app_count,
                       (SELECT COUNT(*) FROM post_applications pa WHERE pa.intern_id = ia.id) AS post_app_count
                FROM intern_accounts ia
                WHERE COALESCE(ia.signup_stage,3) < 3
                   OR (COALESCE(ia.signup_stage,3) = 3 AND
                       (SELECT COUNT(*) FROM applications a WHERE a.email = ia.email) = 0 AND
                       (SELECT COUNT(*) FROM post_applications pa WHERE pa.intern_id = ia.id) = 0)
                ORDER BY ia.created_at DESC
            """).fetchall()
        def _status_label(stage, app_count, post_app_count):
            stage = stage or 3
            if stage < 2:
                return "Stage 1 - account only (no academics)"
            if stage < 3:
                return "Stage 2 - academics done, never finished profile"
            return "Stage 3 - signed up, never applied to anything"
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["ID","Name","Email","Phone","Status","Domain","City","College",
                    "Course","Signup Date"]])
        for r in rows:
            w.writerow([r["id"],r["name"],r["email"],r["phone"] or "",
                        _status_label(r["signup_stage"], r["app_count"], r["post_app_count"]),
                        r["domain"] or "",r["city"] or "",r["college"] or "",r["course"] or "",
                        r["created_at"]])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_incomplete_signups.csv"})
    except Exception as e:
        log_error("csv-incomplete-signups", e); return "Error", 500


@app.route("/admin/csv/attendance")
def admin_csv_attendance():
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("""
                SELECT a.id, a.intern_id, ia.name, ia.email, ia.domain,
                       a.week_start, a.week_end, a.total_minutes, a.updated_at
                FROM attendance a LEFT JOIN intern_accounts ia ON ia.id = a.intern_id
                ORDER BY a.week_start DESC, ia.email
            """).fetchall()
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["ID","Intern ID","Name","Email","Domain","Week Start","Week End",
                    "Total Minutes","Hours","Updated At"]])
        for r in rows:
            w.writerow([r["id"],r["intern_id"],r["name"] or "",r["email"] or "",r["domain"] or "",
                        r["week_start"] or "",r["week_end"] or "",r["total_minutes"],
                        round((r["total_minutes"] or 0)/60,2),r["updated_at"] or ""])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_attendance.csv"})
    except Exception as e:
        log_error("csv-attendance", e); return "Error", 500


@app.route("/admin/csv/devices")
def admin_csv_devices():
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM device_profiles ORDER BY last_seen DESC").fetchall()
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["ID","Visitor ID","Email","IP Address","User Agent","Screen Res","Timezone",
                    "Language","Device Type","Referrer","Is Return Visit","Visit Count",
                    "Time On Page","Intent Score","Path","Last Seen","Created At"]])
        for r in rows:
            w.writerow([r["id"],r["visitor_id"] or "",r["email"] or "",r["ip_address"] or "",
                        r["user_agent"] or "",r["screen_res"] or "",r["timezone"] or "",
                        r["language"] or "",r["device_type"] or "",r["referrer"] or "",
                        r["is_return_visit"],r["visit_count"],r["time_on_page"],
                        r["intent_score"],r["path"] or "",r["last_seen"] or "",r["created_at"] or ""])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_devices.csv"})
    except Exception as e:
        log_error("csv-devices", e); return "Error", 500


@app.route("/admin/csv/interviews")
def admin_csv_interviews():
    """Every interview's questions + answers, one row per question-answer pair, for
    manual review/analysis. Section is the internal question category (technical, learning,
    commitment, â€¦). Interviews with no questions yet emit a single summary row."""
    try:
        if not is_admin_request(): return "Unauthorized", 401
        with get_db() as conn:
            rows = conn.execute("""
                SELECT iv.email, ia.name, iv.domain, iv.attempt_no, iv.status,
                       iv.started_at, iv.completed_at, iv.questions_json, iv.answers_json
                FROM interviews iv LEFT JOIN intern_accounts ia ON ia.email = iv.email
                ORDER BY iv.email, iv.attempt_no, iv.id
            """).fetchall()
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow([sanitize_csv_value(x) for x in ["Email","Name","Domain","Attempt","Status","Started At","Completed At",
                    "Q No","Section","Question","Answer"]])
        for r in rows:
            qs  = _safe_json_load(r["questions_json"], []) or []
            ans = _safe_json_load(r["answers_json"], {}) or {}
            base = [r["email"], r["name"] or "", r["domain"] or "", r["attempt_no"],
                    r["status"], r["started_at"] or "", r["completed_at"] or ""]
            if not qs:
                w.writerow(base + ["", "", "", ""])
                continue
            for q in qs:
                qid = q.get("id")
                answer = ans.get(str(qid), ans.get(qid, ""))
                w.writerow(base + [qid, q.get("type", ""), q.get("text", ""), answer])
        out.seek(0)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=dbert_interviews.csv"})
    except Exception as e:
        log_error("csv-interviews", e); return "Error", 500


@app.route("/admin/screenshot/<filename>")
def admin_screenshot(filename):
    try:
        if not is_admin_request(): return "Unauthorized", 401
        return send_from_directory(app.config["UPLOAD_FOLDER"], secure_filename(filename))
    except Exception as e:
        log_error("screenshot", e); return "Not found", 404


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# LEGACY MIGRATION ROUTES â€” for existing interns with no password
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.route("/check-email", methods=["POST"])
def check_email():
    """
    Used by the signin panel to detect legacy no-password accounts.
    Returns: no_account | no_password | has_password
    """
    try:
        data = request.get_json(force=True)
        email = clean_text(data.get("email")).lower()
        if not email or not is_valid_email(email):
            return jsonify({"status": "error", "message": "Valid email required."}), 400
        ip = get_client_ip()
        allowed, ra = rate_check(f"checkemail:ip:{ip}", *RL_CHECKEMAIL_IP)
        if not allowed:
            log_abuse(ip, "/check-email", f"checkemail:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        with get_db() as conn:
            acct = conn.execute(
                "SELECT password_set, password_hash FROM intern_accounts WHERE email=? AND is_active=1",
                (email,)
            ).fetchone()
        # P1-3: Stop check-email enumeration. Always proceed to password step.
        return jsonify({"status": "success", "result": "has_password"})
    except Exception as e:
        log_error("check-email", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/set-password", methods=["POST"])
def set_password():
    return jsonify({"status": "error", "message": "This endpoint is disabled. Please use /forgot-password."}), 410

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    """Request a password reset. Always returns a neutral success message to
    avoid account enumeration; only actually emails a link if an active account
    exists with password_set=1."""
    neutral = jsonify({"status": "success",
                       "message": "If that email exists, a reset link has been sent."})
    try:
        data = request.get_json(force=True)
        email = clean_text(data.get("email")).lower()
        if not is_valid_email(email):
            return jsonify({"status": "error", "message": "Please enter a valid email address."}), 400
        ip = get_client_ip()
        if clean_text(data.get("company_website")):  # 8.4 honeypot -> silent neutral
            log_abuse(ip, "/forgot-password", "forgot:honeypot", "honeypot", email)
            return neutral
        # IP-level abuse -> 429 (egregious flooding). Email-level -> silently skip the
        # send and return the SAME neutral message (don't reveal the throttle).
        allowed_ip, ra = rate_check(f"forgot:ip:{ip}", *RL_FORGOT_IP)
        if not allowed_ip:
            log_abuse(ip, "/forgot-password", f"forgot:ip:{ip}", "rate_limit", email)
            return too_many(ra)
        allowed_email, _ = rate_check(f"forgot:email:{email}", *RL_FORGOT_EMAIL)
        if not allowed_email:
            log_abuse(ip, "/forgot-password", f"forgot:email:{email}", "forgot_email_throttle", email)
            return neutral
        with get_db() as conn:
            acct = conn.execute(
                "SELECT * FROM intern_accounts WHERE email=? AND is_active=1 LIMIT 1", (email,)
            ).fetchone()
            if acct:
                email_role = email + "|intern"
                conn.execute("UPDATE password_resets SET used=1 WHERE email=? AND used=0", (email_role,))
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                expires_at = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT INTO password_resets (email, token, expires_at) VALUES (?,?,?)",
                    (email_role, token_hash, expires_at)
                )
                conn.commit()
                reset_url = f"{SITE_ORIGIN}/reset?token={token}"
                send_password_reset_email(acct["name"], email, reset_url)
            elif not acct:
                comp = conn.execute(
                    "SELECT * FROM companies WHERE email=? AND is_active=1 LIMIT 1", (email,)
                ).fetchone()
                if comp and comp["password_hash"]:
                    email_role = email + "|company"
                    conn.execute("UPDATE password_resets SET used=1 WHERE email=? AND used=0", (email_role,))
                    token = secrets.token_urlsafe(32)
                    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                    expires_at = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute(
                        "INSERT INTO password_resets (email, token, expires_at) VALUES (?,?,?)",
                        (email_role, token_hash, expires_at)
                    )
                    conn.commit()
                    reset_url = f"{SITE_ORIGIN}/reset?token={token}"
                    send_password_reset_email(comp["name"], email, reset_url)
        return neutral
    except Exception as e:
        log_error("forgot-password", e)
        # Still return neutral to avoid leaking failure detail / enumeration.
        return neutral


@app.route("/reset-password", methods=["POST"])
def reset_password():
    """Complete a password reset using a token. Sets new password, marks the
    token used, and auto-logs the intern in."""
    try:
        data = request.get_json(force=True)
        ip = get_client_ip()
        allowed, ra = rate_check(f"reset:ip:{ip}", *RL_RESET_IP)
        if not allowed:
            log_abuse(ip, "/reset-password", f"reset:ip:{ip}", "rate_limit")
            return too_many(ra)
        token    = clean_text(data.get("token"))
        password = clean_text(data.get("password"))
        confirm  = clean_text(data.get("confirm_password"))
        if not token:
            return jsonify({"status": "error", "message": "This reset link is invalid or has expired."}), 400
        if len(password) < 8:
            return jsonify({"status": "error", "message": "Password must be at least 8 characters."}), 400
        if password != confirm:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at>? LIMIT 1",
                (token, now_str())
            ).fetchone()
            if not row:
                return jsonify({"status": "error", "message": "This reset link is invalid or has expired."}), 400
            email = clean_text(row["email"]).lower()
            updated = conn.execute(
                "UPDATE intern_accounts SET password_hash=?, password_set=1, updated_at=? WHERE email=?",
                (set_password_hash(password), now_str(), email)
            ).rowcount
            if not updated:
                conn.execute(
                    "UPDATE companies SET password_hash=?, updated_at=? WHERE email=?",
                    (set_password_hash(password), now_str(), email)
                )
            conn.execute("UPDATE password_resets SET used=1 WHERE id=?", (row["id"],))
            conn.commit()
        token_sess = create_session(email, "intern")
        link_device_to_email(data.get("visitor_id"), email)
        resp = make_response(jsonify({
            "status": "success",
            "message": "Password reset successfully.",
            "redirect": "/profile"
        }))
        _set_session_cookie(resp, token_sess)
        return resp
    except Exception as e:
        log_error("reset-password", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/cron/enrollment-reminders", methods=["POST"])
def cron_enrollment_reminders():
    """Daily reminder to Selected-but-not-enrolled candidates. Secret-protected
    (NOT admin session): requires header X-Cron-Key or ?key= to equal CRON_SECRET.
    Stops at 6 reminders per application; drops out once enrolled."""
    key = request.headers.get("X-Cron-Key", "").strip() or request.args.get("key", "").strip()
    if not CRON_SECRET or key != CRON_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        # Skip anyone reminded within the last ~20 hours so same-day re-runs don't double-count.
        cutoff = (datetime.now() - timedelta(hours=20)).strftime("%Y-%m-%d %H:%M:%S")
        processed = 0
        with get_db() as conn:
            rows = conn.execute("""
                SELECT * FROM applications a
                WHERE a.status = ?
                  AND COALESCE(a.enroll_reminders_sent, 0) < 6
                  AND NOT EXISTS (SELECT 1 FROM enrollments e WHERE e.email = a.email)
                ORDER BY a.id
            """, (STATUS_SELECTED,)).fetchall()
            for r in rows:
                last = r["last_reminder_at"]
                if last and last > cutoff:
                    continue
                send_enrollment_reminder(r["name"], r["email"], r["domain"])
                conn.execute(
                    "UPDATE applications SET enroll_reminders_sent = COALESCE(enroll_reminders_sent,0) + 1, "
                    "last_reminder_at = ? WHERE id = ?",
                    (now_str(), r["id"])
                )
                processed += 1
            conn.commit()
        return jsonify({"status": "success", "processed": processed})
    except Exception as e:
        log_error("cron-enrollment-reminders", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@app.route("/health")
def health():
    """Lightweight liveness/readiness probe for EC2 monitoring / systemd / uptime checks.
    Verifies process is up and the DB is reachable. No auth, no heavy work."""
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        if random.random() < 0.05:
            cleanup_expired_sessions()
        return jsonify({"status": "ok"})
    except Exception as e:
        log_error("health", e)
        return jsonify({"status": "degraded"}), 503


@app.route("/internship")
@app.route("/internship/")
def _legacy_internship_root():
    """T0: collapsed dual-route migration â€” old root prefix now 301s to clean URLs."""
    return redirect("/", code=301)


@app.route("/internship/<path:rest>")
def _legacy_internship_redirect(rest):
    """T0: collapsed dual-route migration â€” old /internship/... URLs 301 to their clean equivalent."""
    return redirect("/" + rest, code=301)


@app.before_request
def _enforce_max_content_length():
    """Phase 8.5: reject oversize bodies BEFORE the route runs, so a route's broad
    try/except can't swallow the 413 (it then reaches the 413 errorhandler)."""
    maxlen = app.config.get("MAX_CONTENT_LENGTH")
    if maxlen and request.content_length and request.content_length > maxlen:
        abort(413)


@app.errorhandler(413)
def request_entity_too_large(e):
    """Phase 8.5: clean JSON for oversize uploads (MAX_CONTENT_LENGTH = 6 MB),
    instead of an HTML stack page."""
    return jsonify({"status": "error", "message": "File too large. Maximum size is 6 MB."}), 413


def _render_error(code, heading, message, tone="amber", icon="fa-circle-exclamation"):
    """Styled error page, or JSON for API callers (spec Â§9: no dead ends, no
    raw tracebacks). Falls back to plain text if even the template fails â€”
    an error handler must never raise."""
    wants_json = (request.is_json
                  or request.path.startswith(("/intern/", "/admin/", "/api/", "/r/"))
                  or request.headers.get("X-Requested-With") == "XMLHttpRequest"
                  or "application/json" in (request.headers.get("Accept") or ""))
    if wants_json:
        return jsonify({"status": "error", "message": message}), code
    try:
        return render_template("error.html", code=code, heading=heading,
                               message=message, tone=tone, icon=icon), code
    except Exception:
        return f"{code} â€” {heading}", code


@app.errorhandler(404)
def not_found(e):
    return _render_error(
        404, "Page not found",
        "That link doesn't exist, or it may have moved. Nothing has gone wrong with your account.",
        tone="amber", icon="fa-compass")


@app.errorhandler(403)
def forbidden(e):
    return _render_error(
        403, "Not allowed",
        "You don't have access to that, or your session expired. Try signing in again.",
        tone="amber", icon="fa-lock")


@app.errorhandler(500)
def internal_server_error(e):
    # Details go to the server log ONLY - never to the user (spec A 5.8).
    try:
        log_error("500", e)
    except Exception:
        pass
    wants_json = request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.path.startswith(("/intern/", "/admin/", "/company/", "/mentor/"))
    if wants_json:
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500
    return _render_error(
        500, "Something went wrong on our end",
        "We've logged the problem and will look into it. Please try again in a moment.",
        tone="red", icon="fa-triangle-exclamation")


@app.after_request
def _security_headers(resp):
    """Phase 8.7: baseline security headers. CSP is enforced and nonce-based
    (Phase 9) â€” see csp_policy_for() for the policy and the ops escape hatches."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

    # Spec Â§5.3: enforced, with an env switch back to report-only for ops.
    # The nonce must be the one the templates actually emitted, so read it from
    # `g` rather than minting a fresh one here â€” csp_nonce() caches per request.
    policy = csp_policy_for(csp_nonce())
    if CSP_ENFORCE:
        resp.headers.setdefault("Content-Security-Policy", policy)
    else:
        resp.headers.setdefault("Content-Security-Policy-Report-Only", policy)

    # Spec Â§5.6
    resp.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "magnetometer=(), gyroscope=(), interest-cohort=()"
    )
    # HSTS only when actually serving over HTTPS â€” sending it on plain HTTP is
    # ignored by browsers and would be wrong in local dev.
    if COOKIE_SECURE or request.headers.get("X-Forwarded-Proto") == "https":
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )

    # Spec Â§5.5: user-uploaded bytes are served only through this admin route.
    # Force download and forbid sniffing so a crafted "screenshot" can never be
    # rendered as HTML/script in an admin's session.
    if request.path.startswith("/admin/screenshot/"):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers.setdefault("Content-Disposition", "attachment")
    return resp


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)


