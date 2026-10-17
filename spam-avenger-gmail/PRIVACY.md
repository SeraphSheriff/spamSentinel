# Privacy Policy — Spam Avenger for Gmail

Last updated: October 17, 2026

**Short version: this extension does not collect, store, transmit, or
sell any of your personal data. Period.**

## What the extension does

When you click the shield button on an open email in Gmail, the
extension:

1. Reads that email's full headers (via Gmail's "show original" view,
   which you are already logged into).
2. Extracts the originating server's IP address from the headers.
3. Looks up public registration records for that IP (RDAP) and its
   reverse-DNS name, to identify the network owner and their published
   abuse contact.
4. Generates an abuse-complaint draft that you review, copy, and send
   yourself.

## Pre-filling the FTC and Google Safe Browsing report forms

When you click "FTC fraud report" or "Google Safe Browsing" in the
panel, the extension saves that email's case details — the links it
contained, the claimed sender, the subject, and the sending server's
IP and hostname — in your browser's own local extension storage.
That saved copy exists for one reason only: when the report form
opens in the new tab, the extension uses it to pre-fill the form for
you. It is never sent anywhere by the extension, it is erased as soon
as the form is filled, and it is ignored (and deleted) if it is more
than 30 minutes old. As always, nothing is submitted automatically —
you review the filled form and send the report yourself.

## What leaves your browser

Only two kinds of requests, both about the **spammer's** infrastructure,
never about you:

- **RDAP lookups** (`rdap.arin.net`, `rdap.db.ripe.net`,
  `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`) — public
  internet-number registration records for the originating IP.
- **Reverse-DNS lookups** (`dns.google`) — the public hostname of the
  originating IP.

## What we do NOT do

- No accounts, no sign-ups, no analytics, no tracking pixels.
- Your emails, contacts, and Gmail account are never read beyond the
  single message you click the button on, and never leave your browser.
- Nothing is sent automatically. Every complaint is composed by you
  and sent by you.
- No data is sold, shared, or transmitted to the extension's author or
  any third party. There is no server — there is nowhere for your data
  to go.

## Permissions explained

- **Access to mail.google.com** — required to add the shield button to
  Gmail and read the headers of the message you choose to analyze.
- **Host access to the RDAP and DNS endpoints above** — required for
  the IP-ownership lookups described above.
- **Storage** — required to hold the case details locally, in your
  browser only, so the FTC and Google Safe Browsing report forms can
  be pre-filled as described above.
- **Access to safebrowsing.google.com and reportfraud.ftc.gov** —
  required to run that pre-filling on the report pages you open. The
  extension never submits those forms for you.

## Contact

Open an issue at https://github.com/SeraphSheriff/spamSentinel
