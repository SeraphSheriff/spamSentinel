// Spam Avenger v1.0.58 — header-trim + compose-fit tests.
// Run: node tests/test-compose-fit.js
"use strict";
const fs = require("fs");
const path = require("path");
const A = require("../lib/analyze.js");

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}

// ---------- trimHeaders ----------
const rawHeaders = [
  "Delivered-To: spamdodger@gmail.com",
  "ARC-Seal: i=1; a=rsa-sha256; t=1792393823; cv=none;",
  "        d=google.com; s=arc-20260327;",
  "        b=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWV09PT0=",
  "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;",
  "        d=google.com; s=arc-20260327;",
  "        b=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWV09PT0=",
  "ARC-Authentication-Results: i=1; mx.google.com;",
  "        dkim=pass header.i=@example.com;",
  "        spf=pass (google.com: domain of x@example.com designates 1.2.3.4)",
  "Authentication-Results: mx.google.com;",
  "        dkim=pass header.i=@example.com header.s=mail;",
  "        spf=pass smtp.mailfrom=x@example.com",
  "Return-Path: <x@example.com>",
  "Received: from mail.example.com (mail.example.com. [1.2.3.4])",
  "        by mx.google.com with ESMTPS id abc123",
  "        for <spamdodger@gmail.com>;",
  "        Mon, 19 Oct 2026 00:10:23 -0700 (PDT)",
  "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;",
  "        d=example.com; s=mail;",
  "        b=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWV09PT0=",
  "DomainKey-Signature: a=rsa-sha1; c=nofws; q=dns; s=mail;",
  "        b=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWV09PT0=;",
  "From: Spammer <x@example.com>",
  "Subject: Your Cloud ID has been locked",
  "Message-ID: <abc@example.com>",
  "Date: Mon, 19 Oct 2026 02:24:28 +0000"
].join("\n");

const th = A.trimHeaders(rawHeaders);
ok("trimHeaders flags stripped", th.stripped === true);
ok("no ARC-Seal line survives", !/ARC-Seal:/.test(th.text));
ok("no ARC-Message-Signature survives", !/ARC-Message-Signature:/.test(th.text));
ok("no DKIM-Signature survives", !/DKIM-Signature:/.test(th.text));
ok("no DomainKey-Signature survives", !/DomainKey-Signature:/.test(th.text));
ok("signature blob gone", th.text.indexOf("QUJDREVGR0hJ") === -1);
ok("Received kept, folded lines kept",
  /Received: from mail\.example\.com/.test(th.text) &&
  /by mx\.google\.com with ESMTPS/.test(th.text));
ok("Authentication-Results kept", /Authentication-Results: mx\.google\.com/.test(th.text));
ok("ARC-Authentication-Results kept (verdict, not a signature)",
  /ARC-Authentication-Results:/.test(th.text));
ok("From/Subject/Message-ID kept",
  /From: Spammer/.test(th.text) && /Subject: Your Cloud ID/.test(th.text) &&
  /Message-ID: <abc@example\.com>/.test(th.text));

const clean = A.trimHeaders("From: a@b.c\nSubject: hi");
ok("clean headers: stripped=false", clean.stripped === false);
ok("clean headers unchanged", clean.text === "From: a@b.c\nSubject: hi");

// ---------- buildComplaint ----------
function mkAnalysis(over) {
  const a = {
    ip: "141.11.18.118", abuse: "report@abuseradar.com",
    host: "dfusion.toms.com", from: "spamdodger <alert@vebho.example>",
    subject: "Your Cloud ID has been locked",
    date: "Mon, 19 Oct 2026 02:24:28 +0000",
    urls: ["https://storage.googleapis.com/strow/strw_v2.html#?act=cl&pid=32452"],
    fullHeaders: rawHeaders,
    bodyText: "We couldn't renew your cloud storage subscription. " +
      "Visit https://storage.googleapis.com/strow/strw_v2.html to update billing."
  };
  Object.assign(a, over || {});
  return a;
}
const SIG_LINE = /^\s+(ARC-Seal|ARC-Message-Signature|DKIM-Signature|DomainKey-Signature):/im;

const c = A.buildComplaint(mkAnalysis());
ok("complaint built", !!c);
ok("complaint has no signature header lines", !SIG_LINE.test(c.body));
ok("complaint notes the omission", c.body.indexOf("signature blocks omitted") !== -1);
ok("complaint keeps Received chain", c.body.indexOf("Received: from mail.example.com") !== -1);
ok("links defanged, path intact",
  c.body.indexOf("hxxps://storage[.]googleapis[.]com/strow/strw_v2.html#?act=cl&pid=32452") !== -1);
ok("body excerpt present", c.body.indexOf("Message body (plain text") !== -1);

// ---------- fitForCompose ----------
const planSmall = A.fitForCompose(0, mkAnalysis());
ok("small complaint: direct mode", planSmall.mode === "direct", planSmall.mode);
ok("small complaint: url within budget",
  planSmall.url.length <= A.COMPOSE_URL_BUDGET, String(planSmall.url.length));

const bigBody = "Your cloud storage is full. ".repeat(900); // ~25k chars
const bigHeaders = rawHeaders + "\nX-Custom-Bulk: " + "z".repeat(30000);
const aBig = mkAnalysis({ fullHeaders: bigHeaders, bodyText: bigBody });
const planBig = A.fitForCompose(0, aBig);
ok("monster complaint: url within budget",
  planBig.url.length <= A.COMPOSE_URL_BUDGET,
  planBig.mode + " len=" + planBig.url.length);
ok("monster complaint: shrunk or paste (not direct)",
  planBig.mode === "shrunk" || planBig.mode === "paste", planBig.mode);
if (planBig.mode === "paste") {
  ok("paste mode: url carries the paste instruction",
    planBig.url.indexOf(encodeURIComponent("copied it to your clipboard")) !== -1);
  ok("paste mode: complaint is the unshrunk build",
    planBig.complaint.body === A.buildComplaint(aBig).body);
}
if (planBig.mode === "shrunk") {
  ok("shrunk complaint keeps the defanged links",
    planBig.complaint.body.indexOf("hxxps://storage[.]googleapis[.]com") !== -1);
}

const aMid = mkAnalysis({ bodyText: "padding ".repeat(500) }); // 4000 chars
const planMid = A.fitForCompose(0, aMid);
ok("mid complaint: url within budget",
  planMid.url.length <= A.COMPOSE_URL_BUDGET,
  planMid.mode + " len=" + planMid.url.length);

// ---------- real fixture end-to-end ----------
const fixture = fs.readFileSync(
  path.join(__dirname, "..", "..", "test-samples", "storage-phish-2026-10-17.eml"), "utf8");
const fa = A.analyze(fixture);
fa.abuse = "abuse@example.com"; // RDAP normally supplies this in investigate()
const fc = A.buildComplaint(fa);
ok("fixture: complaint built", !!fc);
if (fc) {
  ok("fixture: no signature header lines in complaint", !SIG_LINE.test(fc.body));
  ok("fixture: full-headers section present",
    fc.body.indexOf("Full headers (plain text, as received):") !== -1);
  const fplan = A.fitForCompose(0, fa);
  ok("fixture: compose url within budget",
    fplan.url.length <= A.COMPOSE_URL_BUDGET,
    fplan.mode + " len=" + fplan.url.length);
  console.log("       fixture complaint chars=" + fc.body.length +
    ", compose mode=" + fplan.mode + ", url chars=" + fplan.url.length);
}

// ---------- regressions ----------
ok("defangUrl unchanged",
  A.defangUrl("https://storage.googleapis.com/a.b/c?x=1") ===
  "hxxps://storage[.]googleapis[.]com/a.b/c?x=1");
ok("defangText unchanged",
  A.defangText("go http://evil.example.com/x now") ===
  "go hxxp://evil[.]example[.]com/x now");
ok("buildComplaint null without abuse contact",
  A.buildComplaint({ ip: "1.2.3.4" }) === null);
ok("buildComplaint null when skipped",
  A.buildComplaint({ ip: "1.2.3.4", abuse: "a@b.c", skipComplaint: true }) === null);

console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
