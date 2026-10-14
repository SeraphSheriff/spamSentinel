# spamSentinel.py

A self-defense system for cPanel shared hosting: watches your mail logs for
spam, quarantines the senders' IPs, and files abuse complaints with the
spammers' hosting providers — automatically.

## What it does

1. **Watches** cPanel's mail delivery logs (via the UAPI) for incoming spam
   to your monitored addresses.
2. **Quarantines** — installs per-mailbox cPanel filters that divert all
   future mail from repeat-offender IPs into a quarantine mailbox instead of
   your inbox.
3. **Reports** — looks up the abuse contact for each spammer IP (RDAP) and
   emails a detailed abuse complaint, with log extracts and message headers
   as evidence. One complaint per IP per 30 days (configurable).
4. **Corroborates** — every sender IP gets one Spamhaus ZEN DNSBL lookup;
   SBL/SBL-CSS/XBL listings are cited in complaints as independent evidence.
   (PBL alone is never cited — it's just a dynamic-IP marker.)
5. **Classifies** — three-tier geographic screening: instant-quarantine for
   high-risk TLDs/countries, allowlist for trusted countries, normal
   pipeline for everything else.
6. **Tells you** — emails a daily HTML report with the day's telemetry,
   ZEN listings, and a CSV of every tracked sender IP.

Blocking is driven by **your own observed telemetry**, not by third-party
blocklists. ZEN is corroborating evidence only.

## ⚠️ Warning: this script sends real abuse complaints

This is not a passive monitor. Once configured, it emails abuse desks at
hosting providers on your behalf. Before you let it run unsupervised:

- **Start with `BLOCK_ACCOUNTS`** set to a test mailbox, and watch the first
  few runs in the log before pointing it at real addresses.
- **Verify the quarantine mailbox** receives what you expect — false
  positives land there, not in your inbox, but check it.
- **The big-provider whitelist** (Gmail, Outlook, Yahoo, etc.) is there so
  you never file a complaint against shared infrastructure over one bad
  sender. Don't remove entries unless you understand why they're there.
- **You are responsible** for every complaint it sends. A misconfigured
  filter or a compromised mailbox could generate complaints you didn't
  intend. Keep an eye on the daily report.

## Requirements

- cPanel shared hosting with API access (UAPI Fileman + EmailTrack)
- Python 3 (standard library only — no pip packages needed)
- A cPanel API token (cPanel → Security → Manage API Tokens), or your
  cPanel password
- A dedicated quarantine mailbox (the script auto-purges it after
  `QUARANTINE_KEEP_DAYS`)

## Setup

1. Edit the `DEFAULTS` block at the top of `spamSentinel.py` with **your**
   values: `CPANEL_URLS`, `CPANEL_USER`, `CPANEL_API_TOKEN`,
   `MONITORED_DOMAIN`, `QUARANTINE_MAILBOX`, `BLOCK_ACCOUNTS`, etc.
   The placeholders are not valid — the script fails loudly until you
   fill them in.
2. Lock it down — the script now holds your credentials:
   `chmod 600 spamSentinel.py`
3. Create the quarantine mailbox in cPanel first.
4. Add a cron job in cPanel to run the script at your discretion —
   `python3 ~/spamSentinel.py`. More frequent runs quarantine new
   spammer IPs faster; less frequent runs are lighter on the server.
   Every 15 minutes is a reasonable starting point; adjust to your
   mail volume.
5. Optional one-time backfill of Spamhaus ZEN data for existing records:
   `python3 ~/spamSentinel.py --zen-backfill`

**Never share or commit your edited copy — it contains your credentials.**

## Files it creates (in your home directory)

| File | What it is |
|---|---|
| `spamSentinel.db` | SQLite: telemetry, blocklist, report history |
| `spamSentinel.log` | Run log (auto-trims past 2000 lines) |
| `spam_telemetry.csv` | Telemetry export, attached to the daily report |
| `abuse_queue.json` | Pending complaints between runs |
| `sent_complaints/` | Copies of every complaint sent |

## License

MIT — see [LICENSE](LICENSE).
