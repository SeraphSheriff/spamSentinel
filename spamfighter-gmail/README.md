# 🛡️ Spamfighter for Gmail

One click traces who **really** sent a spam email and writes the abuse
complaint for you. The companion to [Spamfighter](../spamfighter/) for
people who live in Gmail.

## The 10-second version

1. Open a spam email in Gmail (desktop Chrome, Edge, or Brave).
2. Click the red shield button (bottom-right corner).
3. Read who really sent it. Copy the complaint — or open it pre-addressed
   in Gmail — attach nothing, hit send.

No accounts. No passwords. No configuration. Nothing is ever sent
automatically — you review and send every complaint yourself.

## Install (2 minutes, one time)

1. Download `spamfighter-gmail.zip` and **unzip** it into a folder.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Turn on **Developer mode** (toggle, top-right).
4. Click **Load unpacked** and select the unzipped folder.
5. Open Gmail. Open any spam email. Click the red shield.

That's it. The button only appears when you're looking at an email.

## What it does when you click

- Reads the email's full headers (the "show original" view you're
  already logged into — no extra permissions needed).
- Walks the Received chain to the **originating IP** — the server that
  actually pushed the send button. The "From" address is makeup; the IP
  is the face underneath.
- Looks up who owns that IP and finds their **abuse contact**.
- Writes a ready-to-send complaint naming the IP, the claimed sender,
  the subject, the links, and the key headers as evidence.
- Flags the usual scam tells: throwaway `.shop`-style domains, links
  that go somewhere different from the sender, pressure tactics,
  "verify your account" phishing, gift-card bait, unfilled `{{date}}`
  phish-kit placeholders.
- Two one-click actions for real phish: **Report phishing to Google**
  walks Gmail's own report flow (and detects already-reported messages
  instead of opening a dead menu); **Forward phish to APWG + CISA**
  opens Gmail's forward with the phish attached, addressed to
  reportphishing@apwg.org and contact@cisa.dhs.gov — you review and send.

It will **not** generate a complaint against the big mailbox providers'
own servers (Google, Microsoft, Yahoo, etc.) — their IPs show up in
headers for your own mail too, and reporting them would hit the wrong
target. It tells you when that's the case.

## Privacy

Everything runs inside your browser. The only network requests are
lookups **about the spammer's IP address** (RDAP ownership records and
reverse DNS). Your emails, your address book, and your Gmail account
are never touched, uploaded, or sent anywhere.

## Limits (honest ones)

- Desktop Gmail on the web only. Browser buttons can't run inside the
  Gmail phone app — phone users should use the classic Spamfighter tool.
- Needs the email open in the reading pane (works on single messages;
  on long threads it analyzes the first message).
- If the spammer's IP has no published abuse contact, there's nobody
  to complain to — the panel says so and points you at Google Safe
  Browsing instead.

## Files

- `manifest.json` — extension manifest (Manifest V3)
- `content.js` — Gmail button, header fetching, results panel
- `panel.css` — button + panel styling
- `popup.html` — toolbar-icon help popup
- `lib/analyze.js` — the analysis engine (header parsing, RDAP, complaint
  builder). Also runnable under Node for tests.
- `icons/` — shield icons

## For the curious

Same fight, three weapons:

| | Spamfighter | Spamfighter for Gmail | spamSentinel |
|---|---|---|---|
| Who | Anyone with a PC | Gmail users | cPanel server owners |
| How | Save .eml files, double-click | One click in Gmail | Automatic server-side |

Built October 2026. Free forever. If it helps you punish a spammer,
that's the whole point.
