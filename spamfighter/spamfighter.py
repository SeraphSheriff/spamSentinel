#!/usr/bin/env python3
"""spamfighter.py — punish email scammers without cPanel and without
being a computer person.

HOW IT WORKS (the 10-second version):
  1. Save spam emails as .eml files into the "inbox" folder.
  2. Run this script (double-click RUN.bat on Windows).
  3. Open the "reports" folder. For each spam email you get:
       - REPORT.md ...... plain-English breakdown of who sent it
       - COMPLAINT.txt .. a ready-to-send abuse complaint (paste into
                          your email, attach the .eml, hit send)
       - NEXT-STEPS.txt . where else to report it (FTC, Google, FBI)
  4. Processed emails move to inbox/done automatically.

No accounts, no passwords, no configuration. Python only.
"""
import email
import email.policy
import json
import os
import re
import shutil
import socket
import sys
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
INBOX = os.path.join(HERE, "inbox")
DONE = os.path.join(INBOX, "done")
REPORTS = os.path.join(HERE, "reports")

RDAP_BASES = [
    "https://rdap.arin.net/registry/ip/",
    "https://rdap.db.ripe.net/ip/",
    "https://rdap.apnic.net/ip/",
    "https://rdap.lacnic.net/rdap/ip/",
    "https://rdap.afrinic.net/rdap/ip/",
]
URL_RE = re.compile(r"https?://[^\s<>\"']+")

# Never generate complaints against the big mailbox providers' own
# infrastructure — their IPs show up in headers for YOUR OWN mail too.
PROVIDER_WHITELIST = (
    "google.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "microsoft.com", "yahoo.com", "aol.com", "icloud.com",
    "me.com", "mac.com", "proton.me", "protonmail.com", "zoho.com",
)

SKETCHY_TLDS = ("shop", "top", "xyz", "click", "buzz", "lol", "gdn",
                "win", "bid", "loan", "men", "stream", "sbs", "quest")


def _is_private_ip(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return True
        a, b = parts[0], parts[1]
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except Exception:
        return True


def _origin_ip(msg):
    """First public IPv4 in the oldest Received header (ingress hop)."""
    recvd = msg.get_all("Received", []) or []
    pat = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    cands = pat.findall(recvd[-1]) if recvd else []
    if not cands:
        for h in recvd:
            cands.extend(pat.findall(h))
    for ip in cands:
        if not _is_private_ip(ip):
            return ip
    return None


def _rdap(ip):
    for base in RDAP_BASES:
        try:
            req = urllib.request.Request(base + ip,
                                         headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as res:
                if res.status == 200:
                    return json.loads(res.read().decode("utf-8"))
        except Exception:
            continue
    return None


def _extract_abuse(obj):
    for ent in obj.get("entities") or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "abuse" in roles:
            vcard = ent.get("vcardArray") or []
            if len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and \
                            item[0] == "email":
                        return item[3]
        nested = _extract_abuse(ent)
        if nested:
            return nested
    return None


def _extract_org(obj):
    for ent in obj.get("entities") or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "registrant" in roles:
            vcard = ent.get("vcardArray") or []
            if len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and \
                            item[0] == "fn":
                        return item[3]
    return obj.get("name")


def _ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"


def _body_text_and_urls(msg, cap=100000):
    chunks, urls = [], []

    def grab(u):
        u = u.rstrip(".,;!)]}\"'")
        if u and u not in urls and len(urls) < 20:
            urls.append(u)

    parts = msg.walk() if msg.is_multipart() else [msg]
    for p in parts:
        if p.is_multipart():
            continue
        if "attachment" in (p.get("Content-Disposition") or "").lower():
            continue
        try:
            payload = p.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue
        try:
            text = payload.decode(p.get_content_charset() or "utf-8",
                                  errors="replace")
        except Exception:
            text = payload.decode("utf-8", errors="replace")
        for um in URL_RE.finditer(text):
            grab(um.group(0))
        ctype = (p.get_content_type() or "").lower()
        if ctype == "text/plain":
            chunks.append(text)
        elif ctype == "text/html":
            text = re.sub(r'<img\b[^>]*\balt="([^"]*)"[^>]*>',
                          r" \1 ", text, flags=re.I)
            chunks.append(re.sub(r"<[^>]+>", " ", text))
        if sum(len(c) for c in chunks) > cap:
            break
    return "\n".join(chunks)[:cap], urls


def _whitelisted(host):
    host = (host or "").lower()
    return any(host == w or host.endswith("." + w)
               for w in PROVIDER_WHITELIST)


def _red_flags(from_addr, urls, text):
    flags = []
    m = re.search(r"@([\w.-]+)", from_addr or "")
    sender_domain = m.group(1).lower() if m else ""
    tld = sender_domain.rsplit(".", 1)[-1] if "." in sender_domain else ""
    if tld in SKETCHY_TLDS:
        flags.append("Sender uses a .%s domain — throwaway domains scammers "
                     "burn through by the dozen." % tld)
    url_hosts = set()
    for u in urls:
        hm = re.search(r"https?://([^/]+)", u)
        if hm:
            url_hosts.add(hm.group(1).lower().lstrip("www."))
    if sender_domain and url_hosts and not any(
            sender_domain in h or h in sender_domain for h in url_hosts):
        flags.append("The links go somewhere completely different from the "
                     "sender's domain — classic redirector trick.")
    low = text.lower()
    for phrase, note in (
            ("act now", "pressure tactic ('act now')"),
            ("limited time", "pressure tactic ('limited time')"),
            ("verify your account", "asks you to 'verify your account'"),
            ("suspended", "threatens your account is 'suspended'"),
            ("gift card", "mentions gift cards — huge scam marker"),
            ("{{", "contains unfilled template placeholders like "
             "{{date}} — mass-sent phish kit")):
        if phrase in low:
            flags.append("Contains %s." % note)
    return flags, sender_domain, sorted(url_hosts)


def analyze(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    from_addr = str(msg.get("From", "")).strip()
    subject = str(msg.get("Subject", "")).strip()
    date = str(msg.get("Date", "")).strip()
    text, urls = _body_text_and_urls(msg)
    ip = _origin_ip(msg)
    rdap = _rdap(ip) if ip else None
    abuse = _extract_abuse(rdap) if rdap else None
    org = _extract_org(rdap) if rdap else None
    host = _ptr(ip) if ip else None
    flags, sender_domain, url_hosts = _red_flags(from_addr, urls, text)
    skip_complaint = _whitelisted(host)
    return {
        "file": os.path.basename(path),
        "from": from_addr, "subject": subject, "date": date,
        "ip": ip, "host": host, "org": org, "abuse": abuse,
        "urls": urls, "url_hosts": url_hosts,
        "sender_domain": sender_domain, "flags": flags,
        "skip_complaint": skip_complaint,
        "body_preview": text[:1500],
    }


def write_report(a, outdir, slug):
    L = []
    L.append("# Spam report: %s" % (a["subject"] or "(no subject)"))
    L.append("")
    L.append("**From:** %s" % (a["from"] or "unknown"))
    L.append("**Date:** %s" % (a["date"] or "unknown"))
    L.append("")
    if a["ip"]:
        L.append("## Where it really came from")
        L.append("")
        L.append("- **Sending server IP:** %s" % a["ip"])
        L.append("- **Server name:** %s" % a["host"])
        L.append("- **Owned by:** %s" % (a["org"] or "unknown"))
        L.append("- **Abuse contact:** %s" % (a["abuse"] or
                                             "not published — see NEXT-STEPS"))
        L.append("")
        L.append("The 'From' address is makeup. The IP above is the face "
                 "underneath — that's who actually pushed the send button.")
        L.append("")
    else:
        L.append("_Could not determine the sending server from the headers. "
                 "The NEXT-STEPS file still applies._")
        L.append("")
    if a["urls"]:
        L.append("## Links found in the message")
        L.append("")
        for u in a["urls"]:
            L.append("- %s" % u)
        L.append("")
        L.append("Don't click these. They're listed here so you can paste "
                 "them into Google's Safe Browsing report (see NEXT-STEPS).")
        L.append("")
    if a["flags"]:
        L.append("## Red flags")
        L.append("")
        for fl in a["flags"]:
            L.append("- %s" % fl)
        L.append("")
    else:
        L.append("No automatic red flags — but you saved it, so trust your "
                 "gut.")
        L.append("")
    path = os.path.join(outdir, slug + "-REPORT.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


def write_complaint(a, outdir, slug, eml_name):
    if a["skip_complaint"] or not a["ip"] or not a["abuse"]:
        return None
    body = []
    body.append("To: %s" % a["abuse"])
    body.append("Subject: Network abuse complaint — spam from %s" % a["ip"])
    body.append("")
    body.append("HOW TO SEND: paste everything below the line into a new "
                "email to the address above, attach the file '%s', hit send."
                % eml_name)
    body.append("")
    body.append("=" * 60)
    body.append("")
    body.append("Hello Abuse Team,")
    body.append("")
    body.append("I received spam originating from your network:")
    body.append("")
    body.append("  Source IP:      %s" % a["ip"])
    body.append("  Server name:    %s" % a["host"])
    body.append("  Claimed sender: %s" % (a["from"] or "unknown"))
    body.append("  Subject:        %s" % (a["subject"] or "unknown"))
    body.append("  Date received:  %s" % (a["date"] or "unknown"))
    if a["urls"]:
        body.append("  Links in message:")
        for u in a["urls"][:10]:
            body.append("    - %s" % u)
    body.append("")
    body.append("The full original email (with headers) is attached as "
                "evidence.")
    body.append("")
    body.append("Please investigate the account or customer responsible and "
                "take appropriate action. Thank you.")
    path = os.path.join(outdir, slug + "-COMPLAINT.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(body))
    return path


NEXT_STEPS = """What else to do about this spam (5 minutes, no account needed):

1. FTC — file a fraud report (they track patterns, big cases start here):
   https://reportfraud.ftc.gov/

2. Google Safe Browsing — report any scam links from the email so
   browsers start warning people away from them:
   https://safebrowsing.google.com/safebrowsing/report_phish/

3. FBI IC3 — for the serious ones (money lost, identity theft):
   https://www.ic3.gov/

4. Your email provider — mark it as phishing in Gmail/Outlook.
   That trains their filters for everyone.

Every report raises the scammer's cost of doing business.
"""


def main():
    os.makedirs(INBOX, exist_ok=True)
    os.makedirs(DONE, exist_ok=True)
    os.makedirs(REPORTS, exist_ok=True)
    files = sorted(f for f in os.listdir(INBOX)
                   if f.lower().endswith(".eml") and
                   os.path.isfile(os.path.join(INBOX, f)))
    if not files:
        print("Inbox is empty. Save spam emails as .eml files into:")
        print("  " + INBOX)
        print("See SETUP.md for how (it's easy).")
        return
    print("Found %d email(s). Working...\n" % len(files))
    for fn in files:
        path = os.path.join(INBOX, fn)
        try:
            a = analyze(path)
        except Exception as e:
            print("  !! %s: could not read (%s) — skipped" % (fn, e))
            continue
        slug = re.sub(r"[^a-z0-9]+", "-",
                      (a["subject"] or fn)[:40].lower()).strip("-") or "email"
        slug = "%s-%s" % (datetime.now().strftime("%Y%m%d"), slug)
        rp = write_report(a, REPORTS, slug)
        cp = write_complaint(a, REPORTS, slug, fn)
        with open(os.path.join(REPORTS, slug + "-NEXT-STEPS.txt"), "w",
                  encoding="utf-8") as f:
            f.write(NEXT_STEPS)
        shutil.move(path, os.path.join(DONE, fn))
        print("  %s" % (a["subject"] or fn))
        print("    from: %s" % (a["from"] or "?"))
        print("    sent from IP: %s (%s)" % (a["ip"] or "?",
                                             a["org"] or "?"))
        if cp:
            print("    -> complaint ready for: %s" % a["abuse"])
        elif a["skip_complaint"]:
            print("    -> no complaint (big-provider infrastructure, "
                  "use NEXT-STEPS instead)")
        else:
            print("    -> no abuse contact found, use NEXT-STEPS instead")
        print("    report: %s" % os.path.basename(rp))
        print()
    print("Done. Open the reports folder:")
    print("  " + REPORTS)


if __name__ == "__main__":
    main()
