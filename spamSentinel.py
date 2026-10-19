#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spamSentinel.py — spam telemetry + abuse-report engine.

Pipeline
  1. Pull recent delivery records from cPanel (API2 EmailTrack::search),
     including failures — rejected spam never shows up otherwise.
  2. Accumulate per-(domain, sender_ip) telemetry in a local sqlite database.
     History is KEPT between runs (v1 wiped it with DROP TABLE every run).
     Delivery records are deduped across runs via seen_deliveries, because
     EmailTrack returns a rolling window — re-fetched records must not
     inflate hit counts or defeat the report cooldown.
  3. Build abuse_queue.json grouped by abuse contact. A contact is queued
     when never reported, the cooldown expired, or NEW hits arrived since
     the last report (tracked in abuse_reports) — keeps pressure on
     until the abuse stops.
  4. Email the queued abuse complaints via localhost SMTP.
  5. Export spam_telemetry.csv and email it as the daily report,
     with a section listing newly quarantined IPs.
  6. IP blocking: every identified spammer IP (non-whitelisted telemetry)
     is added to a per-account cPanel filter ("spam-ip-quarantine") whose
     action delivers matching mail to quarantine@example.com instead of
     the inbox. Nothing is silently discarded — quarantined mail is kept
     QUARANTINE_KEEP_DAYS days, then auto-purged. Blocks are recorded in
     the blocked_ips table and the filter is re-synced from that table
     every run (self-healing). To unblock an IP, remove it from
     blocked_ips (ask Drogon) — manual filter edits get re-applied.
  7. Geographic three-tier classification (geo_tier): RED senders
     (high-risk TLD or high-risk country) skip the abuse-complaint queue
     entirely — complaining to .ru/.cn abuse desks is pointless — and go
     straight to quarantine blocking, tagged "geo-blocked" in the report.
     GREEN (allowlisted country) and GRAY senders go through the normal
     pipeline. US-based means "needs further review," not safe.

State (DB tables) persists between runs: nothing is reported twice
within the cooldown window.

Credentials: fill in the CONFIG block below, then run:
    chmod 600 ~/spamSentinel.py
"""

import os, re, csv, json, socket, smtplib, time, ssl, traceback, hashlib, sys
import urllib.request, urllib.parse
import sqlite3
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
try:
    from zoneinfo import ZoneInfo
    SERVER_ZONE = ZoneInfo("America/New_York")  # mail server's timezone
except Exception:
    SERVER_ZONE = None

# ------------------------------------------------------------------ config
# YOUR SETTINGS: edit the DEFAULTS below with your own values, then
#     chmod 600 spamSentinel.py
# The placeholders here are NOT valid credentials — the script will fail
# loudly on first run until you fill them in.
HOME_DIR = os.path.expanduser("~")
LOG_PATH = os.path.join(HOME_DIR, "spamSentinel.log")
CSV_PATH = os.path.join(HOME_DIR, "spam_telemetry.csv")
QUEUE_PATH = os.path.join(HOME_DIR, "abuse_queue.json")
SENT_DIR = os.path.join(HOME_DIR, "sent_complaints")

# Log self-maintenance: when the log grows past LOG_MAX_LINES, it is
# trimmed back to LOG_KEEP_LINES at the start of the next run.
LOG_MAX_LINES = 2000
LOG_KEEP_LINES = 1000

DEFAULTS = {
    # Your cPanel URL. The https://yourdomain.com:2083 form is portable
    # (follows the account across server moves); a server hostname works
    # too but is tied to one specific machine.
    "CPANEL_URLS": ["https://example.com:2083"],
    "CPANEL_USER": "exampleuser",
    "CPANEL_PASS": "",
    # Better: create a token at cPanel >> Security >> Manage API Tokens and put
    # it here. Token auth skips the /login/ step
    # entirely and is immune to brute-force lockouts. Leave empty to use password.
    "CPANEL_API_TOKEN": "",
    "REPORT_RECIPIENT": "you@example.com",
    "EMAIL_SENDER": "quarantine@example.com",
    "SKIPPED_EMAILS": ["quarantine@example.com"],
    "REPORT_COOLDOWN_DAYS": 30,
    # All mail monitored by this script is for this domain; used when a
    # cPanel track record carries no domain value of its own.
    "MONITORED_DOMAIN": "example.com",
    # --- IP quarantine blocking ---
    # Mail from blocked IPs is delivered here instead of the inbox.
    # Check it in webmail occasionally; contents auto-purge after
    # QUARANTINE_KEEP_DAYS days. Password is for your webmail login —
    # the script itself uses the API token + filesystem, not this.
    "QUARANTINE_MAILBOX": "quarantine@example.com",
    "QUARANTINE_PASSWORD": "",
    "QUARANTINE_KEEP_DAYS": 30,
    # Per-account filter maintained by the script (one per address below).
    "FILTER_NAME": "spam-ip-quarantine",
    # Accounts that get the quarantine filter. Add more addresses here
    # if you create new mailboxes later.
    "BLOCK_ACCOUNTS": ["you@example.com"],
    # --- Geographic three-tier classification ---
    # RED = instant quarantine, no abuse complaint (sender TLD in
    # HIGH_RISK_TLDS, or sender IP geolocates to HIGH_RISK_COUNTRIES).
    # GREEN = allowlisted country: exempt from instant quarantine, goes
    # through the normal complaint+block pipeline. GRAY = everything else.
    "HIGH_RISK_TLDS": (
        "ru", "su", "cn", "by", "ua", "kz", "in", "tw",
        "cz", "vn", "th", "id", "pk", "ng", "br", "za",
        "shop", "top", "xyz", "click", "buzz", "lol",
        "gdn", "win", "bid", "loan", "men", "stream",
    ),
    "HIGH_RISK_COUNTRIES": (
        "RU", "CN", "BY", "UA", "KZ", "IN", "TW",
        "CZ", "VN", "TH", "ID", "PK", "NG", "BR", "ZA",
    ),
    "ALLOW_COUNTRIES": ("US", "CA", "GB", "AU", "NZ", "IE"),
    # --- Spamhaus ZEN DNSBL ---
    # Every newly-seen sender IP gets one ZEN lookup (result cached in the
    # DB, never re-queried). SBL/XBL listings strengthen abuse complaints
    # and mark professional spam operations; PBL alone is weak signal
    # (dynamic IP) and never triggers action by itself.
    "ZEN_ENABLED": True,
    "ZEN_ZONE": "zen.spamhaus.org",
    "ZEN_TIMEOUT": 5,
}


CFG = dict(DEFAULTS)

# cPanel uses a self-signed cert; we talk only to our own server here.
SSL_CTX = ssl._create_unverified_context()

IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def log(m):
    line = "[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), m)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def log_banner(text):
    bar = "=" * 70
    log(bar)
    log(text)
    log(bar)


def trim_log():
    """Keep the log from growing forever; runs at the start of each run."""
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return
    if len(lines) > LOG_MAX_LINES:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines[-LOG_KEEP_LINES:])
        log("Log trimmed: kept last %d of %d lines" %
            (LOG_KEEP_LINES, len(lines)))


# Abuse complaints are never filed against the big mailbox providers'
# own infrastructure — their IPs show up in your logs for your own
# outbound mail (e.g. these very report emails to your Gmail address).
PROVIDER_WHITELIST = (
    "google.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "microsoft.com",
    "yahoo.com", "aol.com",
    "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com",
    "zoho.com", "yandex.com", "gmx.com",
    "zendesk.com", "zdsys.com",
)


def _whitelisted(host):
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in PROVIDER_WHITELIST)


# Legitimate bulk senders — never treated as threats, even though they
# show up in the delivery logs (usually as backscatter/bounces to dead
# addresses). Matched on the envelope sender's domain.
SENDER_WHITELIST = (
    "uspsa.org",
    "listserv.bounces.google.com",
)


def _whitelisted_sender(sender):
    parts = (sender or "").rsplit("@", 1)
    d = parts[1].lower().strip() if len(parts) == 2 else ""
    return any(d == w or d.endswith("." + w) for w in SENDER_WHITELIST)


def _s(dt):
    """Normalize a datetime-or-string DB value to 'YYYY-MM-DD HH:MM:SS'."""
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt or "")


def _fmt_ts(ts):
    """Format a server-local 'YYYY-MM-DD HH:MM:SS' timestamp with its
    timezone, e.g. '2026-10-14 13:38:46 EDT (UTC-0400)'. Abuse desks
    explicitly ask for the time zone; the mail server runs America/New_York."""
    raw = _s(ts)[:19]
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        if SERVER_ZONE is not None:
            dt = dt.replace(tzinfo=SERVER_ZONE)
            return dt.strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")
    except Exception:
        pass
    return "%s (America/New_York)" % raw


# ------------------------------------------------------------------ database
def get_db_connection():
    return sqlite3.connect(os.path.join(HOME_DIR, "spamSentinel.db"))


# Dedup horizon for EmailTrack delivery records: the search returns a
# rolling window (same records reappear across runs), so anything older
# than this can never come back and is safe to forget.
SEEN_PRUNE_DAYS = 90


def _record_key(item):
    """Stable fingerprint of one EmailTrack delivery record."""
    blob = json.dumps(item, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def init_db(conn):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS spammer_telemetry (
        domain TEXT, sender_ip TEXT, sender_email TEXT, resolved_host TEXT,
        last_seen TEXT, hit_count INTEGER DEFAULT 1, envelope_sender TEXT,
        PRIMARY KEY (domain, sender_ip))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS abuse_reports (
        abuse_email TEXT PRIMARY KEY, last_reported TEXT)""")
    # record-level dedup for EmailTrack ingestion: keys of delivery records
    # already folded into the telemetry, so re-fetched records can't
    # inflate hit counts or defeat the report cooldown
    cur.execute("""CREATE TABLE IF NOT EXISTS seen_deliveries (
        record_key TEXT PRIMARY KEY, first_seen TEXT)""")
    # IPs diverted to the quarantine mailbox: source of truth for the
    # per-account filters (re-synced every run). provider/ptr_host/senders
    # feed the daily report's "newly blocked" section.
    cur.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, ptr_host TEXT, provider TEXT,
        abuse_email TEXT, envelope_senders TEXT,
        first_blocked TEXT, last_seen TEXT)""")
    try:
        cur.execute("ALTER TABLE blocked_ips ADD COLUMN envelope_senders TEXT")
    except Exception:
        pass  # column already exists
    try:
        # one representative raw EmailTrack record per (domain, ip), kept
        # from first sighting — rendered as the "log extract" abuse desks ask
        # for in the complaint body.
        cur.execute("ALTER TABLE spammer_telemetry ADD COLUMN sample_record TEXT")
    except Exception:
        pass  # column already exists
    try:
        # cached Spamhaus ZEN result per (domain, ip): e.g. 'SBL', 'XBL',
        # 'SBL/XBL', 'PBL', 'CLEAN' for unlisted (explicit marker so clean
        # IPs are never re-looked-up), or NULL for "lookup failed, retry
        # next run" — transient failures are never cached as clean.
        cur.execute("ALTER TABLE spammer_telemetry ADD COLUMN zen_result TEXT")
    except Exception:
        pass  # column already exists
    # schema evolution for the re-report-on-new-activity logic
    try:
        cur.execute("ALTER TABLE abuse_reports ADD COLUMN hits_at_report INT DEFAULT 0")
    except Exception:
        pass  # column already exists
    try:
        cur.execute("ALTER TABLE spammer_telemetry ADD COLUMN envelope_sender TEXT")
    except Exception:
        pass  # column already exists
    try:
        cur.execute("ALTER TABLE abuse_reports ADD COLUMN report_count INT DEFAULT 0")
    except Exception:
        pass  # column already exists
    conn.commit()


# ------------------------------------------------------- abuse-contact lookup
# RDAP over HTTPS first (port 43 WHOIS is commonly blocked on shared hosting),
# raw socket WHOIS as fallback.
RDAP_BASES = [
    "https://rdap.arin.net/registry/ip/",
    "https://rdap.db.ripe.net/ip/",
    "https://rdap.apnic.net/ip/",
    "https://rdap.lacnic.net/rdap/ip/",
    "https://rdap.afrinic.net/rdap/ip/",
]


def _extract_abuse(obj):
    for ent in obj.get("entities") or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "abuse" in roles:
            vcard = ent.get("vcardArray") or []
            if len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                        return item[3]
        nested = _extract_abuse(ent)
        if nested:
            return nested
    return None


def _rdap_abuse_email(ip):
    for base in RDAP_BASES:
        try:
            req = urllib.request.Request(base + ip, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as res:
                if res.status != 200:
                    continue
                email = _extract_abuse(json.loads(res.read().decode("utf-8")))
                if email:
                    return email
        except Exception:
            continue
    return None


def _whois_socket(ip, server="whois.arin.net"):
    try:
        s = socket.create_connection((server, 43), timeout=5)
        query = ("n " + ip + "\r\n") if "arin" in server else (ip + "\r\n")
        s.sendall(query.encode("utf-8"))
        res = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            res += chunk
        s.close()
        return res.decode("utf-8", errors="ignore")
    except Exception as e:
        log("WHOIS socket error for %s via %s: %s" % (ip, server, e))
        return ""


def _whois_abuse_email(ip):
    raw = _whois_socket(ip, "whois.arin.net")
    if not raw:
        return None
    for srv in ("whois.ripe.net", "whois.apnic.net",
                "whois.lacnic.net", "whois.afrinic.net"):
        if srv.split(".")[1] in raw.lower():
            log("Re-routing WHOIS to " + srv)
            raw = _whois_socket(ip, srv)
            break
    emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", raw)
    for e in emails:
        if "abuse" in e.lower() and "arin" not in e.lower():
            return e.strip().lower()
    if emails:
        return emails[0].strip().lower()
    return None


_abuse_cache = {}


def resolve_abuse_email(ip):
    if not ip or ip.startswith("127.") or ip.lower() == "localhost" or ":" in ip:
        return "Internal Address"
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    email = _rdap_abuse_email(ip) or _whois_abuse_email(ip)
    result = email.strip().lower() if email else "Unknown / Hidden Registry Mail"
    _abuse_cache[ip] = result
    return result


_org_cache = {}


def resolve_provider(ip):
    """Best-effort hosting provider / org name for an IP, via RDAP.
    Used in the daily report's blocked-IP section."""
    if ip in _org_cache:
        return _org_cache[ip]
    result = "Unknown"
    for base in RDAP_BASES:
        try:
            req = urllib.request.Request(base + ip, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as res:
                if res.status != 200:
                    continue
                obj = json.loads(res.read().decode("utf-8"))
                org = None
                for ent in obj.get("entities") or []:
                    roles = [r.lower() for r in (ent.get("roles") or [])]
                    if "registrant" in roles:
                        vcard = ent.get("vcardArray") or []
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                    org = item[3]
                                    break
                    if org:
                        break
                result = org or obj.get("name") or "Unknown"
                break
        except Exception:
            continue
    _org_cache[ip] = result
    return result


def _extract_country(obj):
    """Best-effort 2-letter country code from RDAP vcard adr fields.

    Looks for the 'cc' param on adr properties (RFC 6350), falling back
    to a 2-letter 7th adr component when a server puts the code there
    instead. Walks nested entities like _extract_abuse does."""
    for ent in obj.get("entities") or []:
        vcard = ent.get("vcardArray") or []
        if len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                    params = item[1] if isinstance(item[1], dict) else {}
                    cc = params.get("cc")
                    if cc and len(str(cc).strip()) == 2:
                        return str(cc).strip().upper()
                    val = item[3]
                    if isinstance(val, list) and len(val) >= 7 and val[6]:
                        comp = str(val[6]).strip()
                        if len(comp) == 2:
                            return comp.upper()
        nested = _extract_country(ent)
        if nested:
            return nested
    return None


def _rdap_country(ip):
    for base in RDAP_BASES:
        try:
            req = urllib.request.Request(base + ip, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as res:
                if res.status != 200:
                    continue
                cc = _extract_country(json.loads(res.read().decode("utf-8")))
                if cc:
                    return cc
        except Exception:
            continue
    return None


def _ipapi_country(ip):
    # Free tier is rate-limited: one call per second, and results are
    # cached in _country_cache so each IP only ever costs one call.
    time.sleep(1)
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/%s?fields=status,countryCode" % ip,
            headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as res:
            obj = json.loads(res.read().decode("utf-8"))
        if obj.get("status") == "success" and obj.get("countryCode"):
            return str(obj["countryCode"]).strip().upper()
    except Exception:
        pass
    return None


_country_cache = {}


def resolve_country(ip):
    """2-letter country code for an IP: RDAP vcard data first, ip-api.com
    as fallback. Returns None when the country can't be determined
    (treated as GRAY by geo_tier). Results are cached per run."""
    if not ip or ip.startswith("127.") or ip.lower() == "localhost" or ":" in ip:
        return None
    if ip in _country_cache:
        return _country_cache[ip]
    cc = _rdap_country(ip) or _ipapi_country(ip)
    _country_cache[ip] = cc
    return cc


def _tld_of(domain_or_host):
    """Last DNS label, lowercased — 'ru' for 'aiheart.ru'. Also works
    on a bare address ('user@aiheart.ru') since the @ stays in an
    earlier label."""
    parts = (domain_or_host or "").lower().strip().rstrip(".").split(".")
    return parts[-1] if parts and parts[-1] else ""


def geo_tier(ip, sender_domain, ptr):
    """Three-tier geographic classification of a sender.

    RED: sender TLD in HIGH_RISK_TLDS, or sender IP geolocates to a
        HIGH_RISK_COUNTRY — instant quarantine, no abuse complaint.
        NOTE: on conflict the TLD wins (a .ru domain relayed through a
        US server is still RED; the domain is the stronger signal for
        this mailbox, which has no legitimate .ru correspondents).
    GREEN: IP geolocates to an ALLOW_COUNTRY — exempt from instant
        quarantine, but still goes through the normal complaint+block
        pipeline. US-based means "needs further review," not safe.
    GRAY: everything else, including unknown country with a clean TLD.
    """
    if _tld_of(sender_domain) in CFG["HIGH_RISK_TLDS"]:
        return "RED"
    if _tld_of(ptr) in CFG["HIGH_RISK_TLDS"]:
        return "RED"
    cc = resolve_country(ip)
    if cc in CFG["HIGH_RISK_COUNTRIES"]:
        return "RED"
    if cc in CFG["ALLOW_COUNTRIES"]:
        return "GREEN"
    return "GRAY"


def ptr_host(ip):
    """Reverse-DNS hostname for the report; 'Unresolved' if none."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unresolved"


# ------------------------------------------------------- Spamhaus ZEN DNSBL
# ZEN return codes (A records). SBL/XBL = strong evidence of spam operations;
# PBL = dynamic/residential IP, weak signal on its own (never triggers action
# alone). 127.255.255.252 = query-limit block, 127.255.255.254 = internal
# failure: both mean "don't trust this answer", never cached as clean.
ZEN_CODES = {
    "127.0.0.2": "SBL",
    "127.0.0.3": "SBL-CSS",
    "127.0.0.4": "XBL",
    "127.0.0.5": "XBL",
    "127.0.0.6": "XBL",
    "127.0.0.7": "XBL",
    "127.0.0.10": "PBL",
    "127.0.0.11": "PBL",
}
ZEN_ERROR_CODES = {"127.0.0.1", "127.255.255.252", "127.255.255.254"}
ZEN_DESCRIPTIONS = {
    "SBL": "verified spam source",
    "SBL-CSS": "snowshoe spam operation",
    "XBL": "botnet/exploited host",
    "PBL": "dynamic IP (weak signal)",
}


def _zen_lookup(ip):
    """Query Spamhaus ZEN for an IPv4 address.

    Returns a '/'-joined code string ('SBL', 'XBL', 'SBL/XBL', 'PBL'),
    None if unlisted, or the string 'ERROR' on transient failure (never
    cached — retried next run). One DNS query per IP, result cached in DB.
    """
    if not CFG.get("ZEN_ENABLED", True):
        return None
    try:
        octets = ip.strip().split(".")
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            return None
        rev = ".".join(reversed(octets))
    except Exception:
        return None
    qname = "%s.%s" % (rev, CFG.get("ZEN_ZONE", "zen.spamhaus.org"))
    timeout = CFG.get("ZEN_TIMEOUT", 5)

    def _resolve():
        try:
            return socket.gethostbyname_ex(qname)[2]
        except socket.gaierror:
            return []  # NXDOMAIN = not listed
        except Exception:
            return None  # transport failure

    import concurrent.futures
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            addrs = ex.submit(_resolve).result(timeout=timeout)
    except Exception:
        return "ERROR"
    if addrs is None:
        return "ERROR"
    if not addrs:
        return None
    if any(a in ZEN_ERROR_CODES for a in addrs):
        return "ERROR"  # rate-limited or broken answer: don't cache
    codes = sorted({ZEN_CODES[a] for a in addrs if a in ZEN_CODES})
    return "/".join(codes) if codes else None


def _zen_evidence_line(zen):
    """Build a complaint evidence line from a cached ZEN result.

    SBL/SBL-CSS/XBL are corroborating evidence of spam operations.
    PBL alone (dynamic/residential IP) is never presented as proof of
    spam — a PBL-only listing yields no line at all. Returns the line
    text, or None when there's nothing worth stating.
    """
    if not zen or zen == "CLEAN":
        return None
    codes = [c for c in zen.split("/") if c and c != "PBL"]
    if not codes:
        return None  # PBL-only: weak signal, never proof
    parts = ["%s (%s)" % (c, ZEN_DESCRIPTIONS.get(c, "listed"))
             for c in codes]
    return ("Spamhaus ZEN DNSBL: %s -- independent corroboration that "
            "this host is a known spam source." % ", ".join(parts))


def _zen_code_desc(code):
    """Human-readable description of a stored ZEN code combo for reports."""
    parts = ["%s (%s)" % (c, ZEN_DESCRIPTIONS.get(c, "listed"))
             for c in code.split("/") if c]
    return " + ".join(parts)


def _zen_summary(conn):
    """Counts of ZEN-listed IPs per code combo, for the daily report."""
    cur = conn.cursor()
    cur.execute("SELECT zen_result, COUNT(*) FROM spammer_telemetry "
                "WHERE zen_result IS NOT NULL AND zen_result != 'CLEAN' "
                "GROUP BY zen_result")
    return cur.fetchall()


# ------------------------------------------------------- IP quarantine blocking
def _uapi(func, params):
    """UAPI call (e.g. Email/store_filter) using API-token auth.
    Tries each CPANEL_URLS base; returns the decoded response dict on
    success, None if every attempt failed."""
    if not CFG.get("CPANEL_API_TOKEN"):
        log("UAPI %s skipped: no API token configured" % func)
        return None
    auth = "cpanel %s:%s" % (CFG["CPANEL_USER"], CFG["CPANEL_API_TOKEN"])
    headers = {"Authorization": auth}
    qs = urllib.parse.urlencode(params)
    for base in CFG["CPANEL_URLS"]:
        try:
            req = urllib.request.Request(base + "/execute/" + func + "?" + qs,
                                         headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=25, context=SSL_CTX) as res:
                data = json.loads(res.read().decode("utf-8"))
            if data.get("status") == 1:
                return data
            log("UAPI %s rejected at %s: %s"
                % (func, base, (data.get("errors") or ["?"])[0]))
        except Exception as e:
            log("UAPI %s error at %s: %s" % (func, base, e))
    return None


def _sync_quarantine_filter(account, ips):
    """Rewrite one account's quarantine filter with the full IP set.
    Rules are OR'd 'Any Header contains <ip>'; the action delivers
    matching mail to the quarantine mailbox instead of the inbox."""
    if not ips:
        return True
    params = {"account": account, "filtername": CFG["FILTER_NAME"]}
    for n, ip in enumerate(ips, 1):
        params["part%d" % n] = "$message_headers"
        params["match%d" % n] = "contains"
        params["val%d" % n] = ip
        if n < len(ips):
            params["opt%d" % n] = "or"
    params["action1"] = "deliver"
    params["dest1"] = CFG["QUARANTINE_MAILBOX"]
    return _uapi("Email/store_filter", params) is not None


def block_spammer_ips(conn):
    """Quarantine-block every identified spammer IP.

    Candidates are the non-whitelisted telemetry IPs (a superset of
    'every IP it reports' — this also covers backfill on the first run
    and spammers whose abuse contact is unknown). Returns
    (new_blocks, total_blocked) for the report, where each new block is
    an (ip, ptr_host, provider, abuse_email, senders, tier) tuple —
    senders is a comma-joined string of the distinct envelope senders
    seen from that IP, so a legit address is recognizable at a glance,
    and tier is the geo_tier() classification ("geo-blocked" RED blocks
    are marked as such in the report). If any filter sync fails,
    nothing is recorded and the run retries next time."""
    cur = conn.cursor()
    cur.execute(
        "SELECT sender_ip, resolved_host, sender_email, envelope_sender "
        "FROM spammer_telemetry "
        "WHERE sender_email NOT IN ('Internal Address','Unknown / Hidden Registry Mail')")
    candidates = {}
    for ip, host, abuse, env_sender in cur.fetchall():
        if _whitelisted(host):
            continue  # big-provider infrastructure, never blocked
        if _whitelisted_sender(env_sender):
            continue  # known-legit mailing list, never blocked
        entry = candidates.setdefault(ip, {"host": host, "abuse": abuse,
                                           "senders": set()})
        if env_sender:
            entry["senders"].add(env_sender)
    cur.execute("SELECT ip FROM blocked_ips")
    already = set(r[0] for r in cur.fetchall())
    # Self-healing: the whitelist can grow after an IP was blocked
    # (e.g. Zendesk, added 10/11/2026). Lift those blocks now so the
    # filter re-sync below stops quarantining them — the design is
    # "whitelisted means never blocked", with no exceptions.
    lifted = []
    if already:
        cur.execute("SELECT ip, ptr_host, envelope_senders FROM blocked_ips")
        for ip, ptr, senders in cur.fetchall():
            if _whitelisted(ptr):
                lifted.append(ip)
                continue
            if any(_whitelisted_sender(s.strip())
                   for s in (senders or "").split(",")):
                lifted.append(ip)
        for ip in lifted:
            cur.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            already.discard(ip)
            log("Block phase: lifted block on %s (now whitelisted)" % ip)
    new_ips = sorted(ip for ip in candidates if ip not in already)
    total = len(already) + len(new_ips)
    if not new_ips:
        if lifted:
            # No new threats, but stale blocks were lifted — still push
            # the cleaned filter set and persist the table changes.
            all_ips = sorted(already)
            failed = [a for a in CFG["BLOCK_ACCOUNTS"]
                      if not _sync_quarantine_filter(a, all_ips)]
            if failed:
                log("Block phase: filter sync FAILED for %s — lifts not "
                    "recorded, retrying next run" % ", ".join(failed))
                conn.rollback()
                return [], total + len(lifted)
            conn.commit()
            log("Block phase: no new IPs; %d stale block(s) lifted (%d "
                "total)" % (len(lifted), total))
        else:
            log("Block phase: no new IPs (%d already blocked)" % len(already))
        return [], total
    log("Block phase: resolving provider info for %d new IPs..." % len(new_ips))
    infos = []
    for ip in new_ips:
        entry = candidates[ip]
        senders = sorted(entry["senders"])[:5]
        senders_str = ", ".join(senders) if senders else "--"
        # Tier per IP: RED dominates — any RED sender/host taints the IP.
        # (resolve_country is cached, so re-classifying here is free.)
        tiers = [geo_tier(ip, s, entry["host"]) for s in entry["senders"]]
        tier = "RED" if "RED" in tiers else (
            "GREEN" if "GREEN" in tiers else "GRAY")
        infos.append((ip, ptr_host(ip), resolve_provider(ip),
                      entry["abuse"], senders_str, tier))
    all_ips = sorted(already | set(new_ips))
    failed = [a for a in CFG["BLOCK_ACCOUNTS"] if not _sync_quarantine_filter(a, all_ips)]
    if failed:
        log("Block phase: filter sync FAILED for %s — blocks not recorded, retrying next run"
            % ", ".join(failed))
        return [], total
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for ip, ptr, provider, abuse, senders, tier in infos:
        cur.execute("INSERT OR REPLACE INTO blocked_ips "
                    "(ip, ptr_host, provider, abuse_email, envelope_senders, "
                    "first_blocked, last_seen) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (ip, ptr, provider, abuse, senders, now, now))
    conn.commit()
    log("Block phase: %d new IPs quarantined (%d total)" % (len(infos), total))
    return infos, total


def purge_quarantine():
    """Delete quarantined mail older than QUARANTINE_KEEP_DAYS days."""
    user, _, domain = CFG["QUARANTINE_MAILBOX"].partition("@")
    cutoff = time.time() - CFG["QUARANTINE_KEEP_DAYS"] * 86400
    removed = 0
    for sub in ("cur", "new"):
        d = os.path.join(HOME_DIR, "mail", domain, user, sub)
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            p = os.path.join(d, fn)
            try:
                if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except Exception as e:
                log("Quarantine purge error for %s: %s" % (p, e))
    if removed:
        log("Quarantine purged: %d messages older than %d days removed"
            % (removed, CFG["QUARANTINE_KEEP_DAYS"]))


# ------------------------------------------------------------------ cPanel
def _cpanel_api(base, token, module, func, params):
    payload = urllib.parse.urlencode(
        {"cpanel_jsonapi_apiversion": "2",
         "cpanel_jsonapi_module": module,
         "cpanel_jsonapi_func": func, **params}).encode("utf-8")
    req = urllib.request.Request(base + "/" + token + "/json-api/cpanel",
                                 data=payload, method="POST")
    with urllib.request.urlopen(req, timeout=25, context=SSL_CTX) as res:
        return json.loads(res.read().decode("utf-8"))


def fetch_delivery_logs():
    if CFG.get("CPANEL_API_TOKEN"):
        return _fetch_via_token()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    urllib.request.install_opener(opener)
    creds = urllib.parse.urlencode(
        {"user": CFG["CPANEL_USER"], "pass": CFG["CPANEL_PASS"]}).encode("utf-8")
    for base in CFG["CPANEL_URLS"]:
        try:
            log("Trying cPanel at " + base)
            req = urllib.request.Request(base + "/login/?login_only=1",
                                         data=creds, method="POST")
            with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as res:
                login = json.loads(res.read().decode("utf-8"))
            if login.get("status") != 1:
                log("cPanel login rejected at " + base)
                continue
            segs = [s for s in login.get("redirect", "").split("/") if s]
            if not segs:
                log("No session token from " + base)
                continue
            data = _cpanel_api(base, segs[0], "EmailTrack", "search",
                               {"success": "1", "defer": "1", "failure": "1"})
            logs = data.get("cpanelresult", {}).get("data", [])
            log("Fetched %d log items from %s" % (len(logs), base))
            return logs
        except Exception as e:
            log("cPanel error at %s: %s" % (base, e))
    return []


def _fetch_via_token():
    """API-token auth: no /login/ step, no password, no lockouts."""
    auth = "cpanel %s:%s" % (CFG["CPANEL_USER"], CFG["CPANEL_API_TOKEN"])
    headers = {"Authorization": auth}
    payload = urllib.parse.urlencode(
        {"cpanel_jsonapi_apiversion": "2",
         "cpanel_jsonapi_module": "EmailTrack",
         "cpanel_jsonapi_func": "search",
         "success": "1", "defer": "1", "failure": "1"}).encode("utf-8")
    for base in CFG["CPANEL_URLS"]:
        try:
            log("Trying cPanel (token) at " + base)
            req = urllib.request.Request(base + "/json-api/cpanel",
                                         data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=25, context=SSL_CTX) as res:
                data = json.loads(res.read().decode("utf-8"))
            logs = data.get("cpanelresult", {}).get("data", [])
            log("Fetched %d log items from %s" % (len(logs), base))
            return logs
        except Exception as e:
            log("cPanel token error at %s: %s" % (base, e))
    return []


# ------------------------------------------------------------------ pipeline
def upsert_telemetry(conn, logs):
    cur = conn.cursor()
    # forget dedup entries older than the horizon (EmailTrack's own window
    # is far shorter, so a pruned record can never legitimately recur)
    prune_before = (datetime.now() - timedelta(days=SEEN_PRUNE_DAYS)
                    ).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("DELETE FROM seen_deliveries WHERE first_seen < ?",
                (prune_before,))
    q = ("""INSERT OR REPLACE INTO spammer_telemetry
            (domain, sender_ip, sender_email, resolved_host, last_seen, hit_count, envelope_sender, sample_record, zen_result)
            VALUES (?,?,?,?,?,COALESCE((SELECT hit_count FROM spammer_telemetry
            WHERE domain=? AND sender_ip=?)+1,1),?,
            COALESCE((SELECT sample_record FROM spammer_telemetry
            WHERE domain=? AND sender_ip=?), ?), ?)""")
    kept = 0
    skipped_seen = 0
    skipped_invalid = 0
    total = len(logs)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log("Resolving abuse contacts for %d log items..." % total)
    for n, item in enumerate(logs, 1):
        ip = (item.get("ip") or "").strip()
        sender = item.get("sender") or ""
        if not ip or not IPV4.match(ip) or sender in CFG["SKIPPED_EMAILS"]:
            skipped_invalid += 1
            continue
        # EmailTrack returns a rolling window: identical records reappear
        # across runs. Skip ones already folded in, BEFORE the RDAP lookup.
        key = _record_key(item)
        cur.execute("SELECT 1 FROM seen_deliveries WHERE record_key=?", (key,))
        if cur.fetchone():
            skipped_seen += 1
            continue
        if n % 10 == 0:
            log("... %d/%d items processed" % (n, total))
        abuse = resolve_abuse_email(ip)
        args = (item.get("domain") or CFG["MONITORED_DOMAIN"], ip, abuse,
                item.get("host") or "Unresolved Host",
                item.get("time") or now)
        sample = json.dumps(item, default=str)
        # ZEN: one lookup per IP, cached. Only query when we have no stored
        # result. Unlisted IPs are stored as 'CLEAN' (explicit marker, never
        # re-looked-up); transient failures stay NULL so they're retried.
        cur.execute("SELECT zen_result FROM spammer_telemetry "
                    "WHERE domain=? AND sender_ip=?", (args[0], args[1]))
        zrow = cur.fetchone()
        zen = zrow[0] if zrow else None
        if zen is None:
            zen = _zen_lookup(ip)
            if zen == "ERROR":
                zen = None
                log("ZEN lookup failed for %s (transient, will retry)" % ip)
            elif zen:
                log("ZEN: %s listed (%s)" % (ip, zen))
            else:
                zen = "CLEAN"
        try:
            cur.execute(q, args + (args[0], args[1], sender,
                                   args[0], args[1], sample, zen))
            cur.execute("INSERT OR IGNORE INTO seen_deliveries "
                        "(record_key, first_seen) VALUES (?,?)", (key, now))
            kept += 1
        except Exception as e:
            log("DB fault for %s: %s" % (ip, e))
    conn.commit()
    log("Telemetry upserted: %d new records "
        "(%d already-seen skipped, %d invalid skipped)"
        % (kept, skipped_seen, skipped_invalid))


def build_abuse_queue(conn):
    """Group telemetry by abuse contact. A contact is queued when it has
    never been reported, the cooldown has expired, or new hits arrived
    since the last report — keeps pressure on until the abuse stops.
    RED-tier (geo) senders are skipped entirely: no abuse complaint is
    filed for them (complaining to .ru/.cn abuse desks is pointless);
    they still flow into block_spammer_ips for quarantine blocking."""
    cutoff = (datetime.now() - timedelta(days=CFG["REPORT_COOLDOWN_DAYS"])
              ).strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.cursor()
    cur.execute(
        "SELECT domain, sender_ip, sender_email, resolved_host, last_seen, hit_count, envelope_sender, sample_record, zen_result "
        "FROM spammer_telemetry "
        "WHERE sender_email NOT IN ('Internal Address','Unknown / Hidden Registry Mail')")
    groups = {}
    for row in cur.fetchall():
        domain, ip, abuse, host, last_seen, hits, env_sender = row[:7]
        sample = row[7] if len(row) > 7 else None
        zen = row[8] if len(row) > 8 else None
        if zen == "CLEAN":
            zen = None  # unlisted: no evidence to report
        if _whitelisted(host):
            continue  # big-provider infrastructure, not a spammer
        if _whitelisted_sender(env_sender):
            continue  # known-legit mailing list, not a threat
        if geo_tier(ip, env_sender, host) == "RED":
            continue  # geo-blocked: straight to quarantine, no complaint
        groups.setdefault(abuse, []).append({
            "ip": ip, "domain": domain, "envelope": abuse, "host": host,
            "time": _s(last_seen), "hits": hits, "sample": sample,
            "zen": zen})
    queue = {}
    prior_counts = {}
    for abuse, incidents in groups.items():
        total_hits = sum(i["hits"] for i in incidents)
        cur.execute("SELECT last_reported, hits_at_report, report_count FROM abuse_reports "
                    "WHERE abuse_email=?", (abuse,))
        row = cur.fetchone()
        prior = (row[2] or 0) if row else 0
        prior_counts[abuse] = prior
        if row and row[0]:
            within_cooldown = _s(row[0]) >= cutoff
            no_new_activity = (row[1] or 0) >= total_hits
            if within_cooldown and no_new_activity:
                continue  # reported recently and nothing new since
        queue[abuse] = incidents
    if queue:
        with open(QUEUE_PATH, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
    repeats = sum(1 for a in queue if prior_counts.get(a, 0) > 0)
    log("Queue built: %d abuse contacts, %d incidents (%d repeat offenders)" %
        (len(queue), sum(len(v) for v in queue.values()), repeats))


def _uapi_execute(func, params, retries=5):
    """Call a cPanel UAPI function via /execute/ using the API token.
    The server intermittently truncates responses (IncompleteRead), so
    transport errors are retried with backoff; API-level errors break
    to the next base immediately."""
    token = CFG.get("CPANEL_API_TOKEN")
    user = CFG.get("CPANEL_USER")
    if not token:
        return None
    import random
    payload = urllib.parse.urlencode(params).encode("utf-8")
    for base in CFG["CPANEL_URLS"]:
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    base + "/execute/" + func, data=payload, method="POST",
                    headers={"Authorization": "cpanel %s:%s" % (user, token)})
                with urllib.request.urlopen(req, timeout=25,
                                            context=SSL_CTX) as res:
                    data = json.loads(res.read().decode("utf-8"))
                if data.get("status") == 1:
                    return data.get("data")
                log("UAPI %s error at %s: %s"
                    % (func, base, data.get("errors")))
                break  # API-level error: retrying won't help
            except Exception as e:
                if attempt < retries:
                    time.sleep(2 * (attempt + 1) + random.uniform(0, 1))
                    continue
                log("UAPI %s failed at %s: %s" % (func, base, e))
    return None


def _quarantine_cur_dir():
    """maildir 'cur' path for the quarantine mailbox, derived from config.

    cPanel layout: ~/mail/<domain>/<mailbox-user>/cur
    """
    user, _, domain = CFG["QUARANTINE_MAILBOX"].partition("@")
    return os.path.join(HOME_DIR, "mail", domain, user, "cur")


# Same derivation as _quarantine_cur_dir() above: the quarantine
# mailbox's cur/new plus its .spam subfolder's cur/new.
_q_user, _, _q_domain = CFG["QUARANTINE_MAILBOX"].partition("@")
_q_base = os.path.join(HOME_DIR, "mail", _q_domain, _q_user)
QUARANTINE_MAILDIRS = (
    os.path.join(_q_base, "cur"),
    os.path.join(_q_base, "new"),
    os.path.join(_q_base, ".spam", "cur"),
    os.path.join(_q_base, ".spam", "new"),
)

_URL_RE = re.compile(r"(https?)://([A-Za-z0-9\-._~%!$&'()*+,;=]+)", re.I)


def _defang_text(text):
    """Defang URLs in quoted message content: hxxp(s) scheme and
    bracketed host dots, path untouched. A complaint pasting live
    phishing links scores as spam at the receiving desk's filter."""
    def _sub(m):
        scheme = "hxxps" if m.group(1).lower() == "https" else "hxxp"
        return scheme + "://" + m.group(2).replace(".", "[.]")
    return _URL_RE.sub(_sub, text)


def _fetch_quarantine_evidence(ips, max_fetch=60, days=7):
    """Match incident IPs to messages in the quarantine mailbox and return
    {ip: {"headers": full_headers_text, "body": defanged_body_excerpt}}.
    Reads maildir files via the Fileman UAPI (IMAP is unreachable from
    here) and matches the IP against the message headers. Scans the
    INBOX folders AND the .spam subfolder: delivered spam is filed
    there, and scanning only the root maildir silently matched nothing,
    which is why complaints fell back to 'headers available on request'.
    Bounded: only messages from the last `days` days, at most
    `max_fetch` file reads per run."""
    pending = set(ips)
    found = {}
    if not pending:
        return found
    cutoff = time.time() - days * 86400
    cands = []  # (ts, maildir, filename)
    for mdir in QUARANTINE_MAILDIRS:
        entries = _uapi_execute("Fileman/list_files", {"dir": mdir}) or []
        for e in entries:
            name = e.get("file") or ""
            m = re.match(r"(\d+)\.", name)
            if not m:
                continue
            try:
                ts = int(m.group(1))
            except ValueError:
                continue
            if ts >= cutoff:
                cands.append((ts, mdir, name))
    cands.sort(key=lambda c: c[0], reverse=True)  # newest first
    ip_res = {ip: re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])")
              for ip in pending}
    fetched = 0
    for _ts, mdir, name in cands:
        if not pending or fetched >= max_fetch:
            break
        # list_files truncates maildir names at ':' — try the common
        # ':2,<flags>' suffixes when the bare name yields nothing.
        content = ""
        for variant in (name, name + ":2,S", name + ":2,RS", name + ":2,"):
            data = _uapi_execute("Fileman/get_file_content", {
                "dir": mdir, "file": variant}) or {}
            content = data.get("content") or ""
            if content:
                break
        if not content:
            continue
        fetched += 1
        head, _sep, body = content.partition("\n\n")
        head = head[:8192]  # headers, capped
        for ip in list(pending):
            if ip_res[ip].search(head):
                excerpt = _defang_text(body.strip()[:6000]) if body else ""
                found[ip] = {"headers": head.strip(), "body": excerpt}
                pending.discard(ip)
    log("Evidence lookup: %d/%d incident IPs matched (%d files read)"
        % (len(found), len(ips), fetched))
    return found



def _log_extract(sample_json):
    """Render a one-block log extract from a stored EmailTrack record —
    the 'log extracts showing intensity and duration' abuse desks ask for."""
    if not sample_json:
        return None
    try:
        r = json.loads(sample_json)
    except Exception:
        return None
    lines = ["[%s] %s (%s)" % (
        _fmt_ts(r.get("actiontime") or r.get("time")),
        r.get("senderip") or r.get("ip") or "?",
        r.get("senderhost") or r.get("host") or "?")]
    lines.append("  envelope-from: %s"
                 % (r.get("sender") or r.get("email") or "?"))
    lines.append("  to: %s | msgid: %s"
                 % (r.get("recipient") or "?", r.get("msgid") or "?"))
    lines.append("  spam-score: %s | size: %s bytes | disposition: %s" % (
        r.get("spamscore", "?"), r.get("size", "?"), r.get("message") or "?"))
    return "\n".join(lines)


def dispatch_queue(conn):
    if not os.path.exists(QUEUE_PATH):
        log("Queue empty, nothing to dispatch")
        return
    with open(QUEUE_PATH, encoding="utf-8") as f:
        groups = json.load(f)
    if not groups:
        log("Queue empty, nothing to dispatch")
        return
    server = smtplib.SMTP("localhost")
    os.makedirs(SENT_DIR, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # match incident IPs to quarantined messages for full-header evidence
    all_ips = {i["ip"] for inc in groups.values() for i in inc}
    evidence_by_ip = _fetch_quarantine_evidence(all_ips)
    sent = 0
    try:
        for abuse_email, incidents in groups.items():
            total_hits = sum(i["hits"] for i in incidents)
            cur = conn.cursor()
            cur.execute("SELECT report_count FROM abuse_reports WHERE abuse_email=?",
                        (abuse_email,))
            rrow = cur.fetchone()
            prior_reports = (rrow[0] or 0) if rrow else 0
            complaint_no = prior_reports + 1
            if prior_reports:
                repeat_note = ("\n\nNOTE: This is complaint #%d our system has filed "
                               "regarding ongoing abuse from your network. Prior "
                               "complaints have not stopped it. Please escalate." % complaint_no)
            else:
                repeat_note = ""
            lines = []
            for i in incidents:
                block = ("Source IP: %(ip)s\n   Identity Forged: %(domain)s\n"
                         "   Resolved Host: %(host)s\n   Last Seen: %(time)s\n"
                         "   Total Volume: %(hits)s hits\n") % {
                             "ip": i["ip"], "domain": i["domain"],
                             "host": i["host"], "time": _fmt_ts(i["time"]),
                             "hits": i["hits"]}
                extract = _log_extract(i.get("sample"))
                if extract:
                    block += ("   Log extract (cPanel mail logs, "
                              "America/New_York):\n" +
                              "\n".join("     " + ln for ln in
                                        extract.split("\n")) + "\n")
                ev = evidence_by_ip.get(i["ip"])
                if ev:
                    block += ("   Full headers of sample message "
                              "(plain text, as requested):\n" +
                              "\n".join("     " + ln for ln in
                                        ev["headers"].split("\n")) + "\n")
                    if ev.get("body"):
                        block += ("   Message body of sample (plain text, "
                                  "links defanged for safe transit — read "
                                  "hxxps as https and [.] as .):\n" +
                                  "\n".join("     " + ln for ln in
                                            ev["body"].split("\n")) + "\n")
                else:
                    block += ("   Full message headers: available on request "
                              "— reply to this email.\n")
                # destination is our own MX on the standard SMTP ports
                block += ("   Destination: %s (our MX) port 25/tcp\n"
                          % CFG.get("MONITORED_DOMAIN", "example.com"))
                zline = _zen_evidence_line(i.get("zen"))
                if zline:
                    block += "   %s\n" % zline
                lines.append(block + "-" * 50)
            msg = MIMEText("Hello Abuse Team,\n\nOur system detected spam originating "
                           "from your network:\n\n" + "\n".join(lines) + repeat_note +
                           "\n\nPlease investigate. This is an automated report.")
            msg["From"] = CFG["EMAIL_SENDER"]
            msg["To"] = abuse_email
            msg["Subject"] = "Network Abuse Complaint (%d incident(s))" % len(incidents)
            server.sendmail(CFG["EMAIL_SENDER"], [abuse_email], msg.as_string())
            # archive a copy for review
            safe = re.sub(r"[^a-zA-Z0-9@._-]", "_", abuse_email)
            fname = "%s_%s.eml" % (datetime.now().strftime("%Y-%m-%d_%H%M%S"), safe)
            with open(os.path.join(SENT_DIR, fname), "w", encoding="utf-8") as f:
                f.write(msg.as_string())
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO abuse_reports "
                        "(abuse_email,last_reported,hits_at_report,report_count) VALUES (?,?,?,?)",
                        (abuse_email, now, total_hits, complaint_no))
            sent += 1
            time.sleep(2)
    finally:
        server.quit()
    conn.commit()
    os.remove(QUEUE_PATH)
    log("Dispatched %d abuse complaints" % sent)


def export_csv(conn):
    cur = conn.cursor()
    cur.execute("SELECT domain, sender_ip, sender_email, resolved_host, last_seen, hit_count, envelope_sender, zen_result "
                "FROM spammer_telemetry "
                "WHERE sender_email NOT IN ('Internal Address','Unknown / Hidden Registry Mail') "
                "ORDER BY hit_count DESC")
    rows = []
    for r in cur.fetchall():
        if _whitelisted(r[3]) or _whitelisted_sender(r[6]):
            continue
        zen = r[7] if len(r) > 7 and r[7] and r[7] != "CLEAN" else ""
        rows.append((r[0], r[1], r[2], r[3], r[4], r[5], zen))
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "sender_ip", "abuse_email", "resolved_host",
                    "last_seen", "hit_count", "zen"])
        w.writerows(rows)
    log("CSV exported: %d rows" % len(rows))


def send_report_email(new_blocks=None, total_blocked=0, zen_stats=None):
    if not os.path.exists(CSV_PATH):
        log("CSV missing, report skipped")
        return
    msg = MIMEMultipart()
    msg["From"] = CFG["EMAIL_SENDER"]
    msg["To"] = CFG["REPORT_RECIPIENT"]
    msg["Subject"] = "Spam Telemetry Report - " + datetime.now().strftime("%Y-%m-%d")
    body = "Latest telemetry attached.\n\nAutomated engine."
    if new_blocks:
        lines = ["",
                 "NEWLY QUARANTINED IPs (%d new, %d total blocked):"
                 % (len(new_blocks), total_blocked),
                 "Mail from these now goes to %s instead of your inbox. "
                 "Check it in webmail if you're ever missing something you expected."
                 % CFG["QUARANTINE_MAILBOX"]]
        for ip, ptr, provider, abuse, senders, tier in new_blocks:
            marker = " [geo-blocked]" if tier == "RED" else ""
            lines.append("  %s%s\n    From: %s\n    Host: %s\n    Provider: %s\n    Abuse contact: %s"
                         % (ip, marker, senders, ptr, provider, abuse))
        body += "\n".join(lines) + "\n"
    elif total_blocked:
        body += "\n\nNo new blocks. %d IPs currently quarantined." % total_blocked
    if zen_stats:
        total_listed = sum(n for _, n in zen_stats)
        zlines = ["",
                  "SPAMHAUS ZEN LISTINGS (%d sender IP(s) currently listed):"
                  % total_listed,
                  "ZEN is corroborating evidence only -- blocking is driven "
                  "by our own telemetry, not by ZEN."]
        for code, n in sorted(zen_stats):
            zlines.append("  %s: %d IP(s)" % (_zen_code_desc(code), n))
        body += "\n".join(zlines) + "\n"
    msg.attach(MIMEText(body, "plain"))
    with open(CSV_PATH, "rb") as fh:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(fh.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition",
                        "attachment; filename=" + os.path.basename(CSV_PATH))
        msg.attach(part)
    server = smtplib.SMTP("localhost")
    server.sendmail(CFG["EMAIL_SENDER"], [CFG["REPORT_RECIPIENT"]], msg.as_string())
    server.quit()
    log("Report emailed to " + CFG["REPORT_RECIPIENT"])


def zen_backfill(conn):
    """One-time backfill: ZEN-check every telemetry row still NULL.

    Run manually: python3 spamSentinel.py --zen-backfill
    Unlisted IPs are stored as 'CLEAN'; transient failures stay NULL
    for the next run to retry.
    """
    cur = conn.cursor()
    cur.execute("SELECT domain, sender_ip FROM spammer_telemetry "
                "WHERE zen_result IS NULL")
    rows = cur.fetchall()
    log("ZEN backfill: %d unchecked IPs" % len(rows))
    done = listed = failed = 0
    for domain, ip in rows:
        if not ip or not IPV4.match(ip):
            continue
        zen = _zen_lookup(ip)
        if zen == "ERROR":
            failed += 1
            log("ZEN lookup failed for %s (transient, left NULL)" % ip)
            continue
        if not zen:
            zen = "CLEAN"
        else:
            listed += 1
            log("ZEN: %s listed (%s)" % (ip, zen))
        cur.execute("UPDATE spammer_telemetry SET zen_result=? "
                    "WHERE domain=? AND sender_ip=?", (zen, domain, ip))
        done += 1
        if done % 25 == 0:
            conn.commit()
            log("... %d/%d backfilled" % (done, len(rows)))
        time.sleep(0.2)  # polite pace for Spamhaus
    conn.commit()
    log("ZEN backfill complete: %d updated (%d listed, %d failed)"
        % (done, listed, failed))


def main():
    trim_log()
    log_banner(">>> RUN STARTED: %s <<<" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    conn = get_db_connection()
    try:
        init_db(conn)
        if "--zen-backfill" in sys.argv:
            log("Step 0: ZEN backfill mode")
            zen_backfill(conn)
            return
        logs = fetch_delivery_logs()
        log("Step 1: collected %d log items" % len(logs))
        upsert_telemetry(conn, logs)
        log("Step 2: telemetry stored")
        build_abuse_queue(conn)
        dispatch_queue(conn)
        log("Step 3: queue dispatched")
        new_blocks, total_blocked = block_spammer_ips(conn)
        log("Step 3b: IP blocking done")
        purge_quarantine()
        log("Step 3c: quarantine purged")
        export_csv(conn)
        zen_stats = _zen_summary(conn)
        send_report_email(new_blocks, total_blocked, zen_stats)
        log("Step 4: report sent")
    except Exception:
        log("CRITICAL:\n" + traceback.format_exc())
    finally:
        conn.close()
    log_banner("<<< RUN FINISHED: %s <<<" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


if __name__ == "__main__":
    main()
