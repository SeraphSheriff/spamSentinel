# Spamfighter

Punish email scammers. No cPanel required. No expertise required.

Spamfighter takes spam emails you've saved as `.eml` files and, for
each one:

1. **Traces it** — finds the real sending server (IP, hostname, owner)
   hiding behind the forged "From" address, via RDAP.
2. **Finds the abuse contact** — the email address of the team at the
   hosting company responsible for that server.
3. **Writes your complaint for you** — a ready-to-send abuse report.
   You paste it into an email, attach the original, hit send.
4. **Hands you the next steps** — FTC, Google Safe Browsing, FBI IC3,
   with the scam's links already extracted for you.

It never sends email itself and never asks for your passwords. You
stay in control of every complaint.

## Quick start

See **SETUP.md** — five minutes, written for non-technical people.

The short version: save spam as `.eml` into `inbox/`, double-click
`RUN.bat` (Windows) or `RUN.sh` (Mac/Linux), open `reports/`.

## What it needs

- Python 3 (free, https://www.python.org/downloads/)
- An internet connection (for the RDAP lookups)
- That's it. No libraries to install, no accounts, no configuration.

## Notes

- Complaints are never generated against big mailbox providers'
  infrastructure (Gmail, Outlook, etc.) — their IPs appear in headers
  for your own legitimate mail too. For those, use the NEXT-STEPS file.
- Processed emails move to `inbox/done/` automatically.
- Built as the little sibling of
  [spamSentinel](https://github.com/SeraphSheriff/spamSentinel), which
  does all of this automatically on a cPanel server.

Hunt them back.
