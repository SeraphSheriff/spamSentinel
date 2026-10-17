/* Spam Avenger for Gmail — analysis engine.
 * Ported from spamfighter.py. No dependencies, no network except
 * RDAP + DNS-over-HTTPS lookups of the SPAMMER's IP.
 * Works in the browser extension and in Node (for tests).
 */
(function () {
  "use strict";

  var RDAP_BASES = [
    "https://rdap.arin.net/registry/ip/",
    "https://rdap.db.ripe.net/ip/",
    "https://rdap.apnic.net/ip/",
    "https://rdap.lacnic.net/rdap/ip/",
    "https://rdap.afrinic.net/rdap/ip/"
  ];

  // Never generate complaints against the big mailbox providers' own
  // infrastructure — their IPs show up in headers for YOUR OWN mail too.
  var PROVIDER_WHITELIST = [
    "google.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "microsoft.com", "yahoo.com", "aol.com", "icloud.com",
    "me.com", "mac.com", "apple.com", "proton.me", "protonmail.com", "zoho.com"
  ];

  var SKETCHY_TLDS = ["shop", "top", "xyz", "click", "buzz", "lol", "gdn",
    "win", "bid", "loan", "men", "stream", "sbs", "quest"];

  var URL_RE = /https?:\/\/[^\s<>"']+/g;

  function isPrivateIp(ip) {
    var parts = String(ip).split(".");
    if (parts.length !== 4) return true;
    var n = parts.map(function (p) { return parseInt(p, 10); });
    if (n.some(function (p) { return isNaN(p) || p < 0 || p > 255; })) return true;
    var a = n[0], b = n[1];
    return (a === 10 || a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168));
  }

  // Split raw message text into unfolded headers [{name, value}, ...].
  function parseHeaders(rawText) {
    var head = String(rawText).split(/\r?\n\r?\n/)[0] || "";
    var headers = [];
    var current = null;
    head.split(/\r?\n/).forEach(function (line) {
      if (/^[ \t]/.test(line) && current) {
        current.value += " " + line.trim();
      } else {
        var m = line.match(/^([^:]+):\s*(.*)$/);
        if (m) {
          current = { name: m[1].toLowerCase(), value: m[2] };
          headers.push(current);
        } else {
          current = null;
        }
      }
    });
    return headers;
  }

  function getAll(headers, name) {
    return headers.filter(function (h) { return h.name === name; })
      .map(function (h) { return h.value; });
  }

  function getFirst(headers, name) {
    var all = getAll(headers, name);
    return all.length ? all[0] : "";
  }

  // First public IPv4 in the oldest Received header (ingress hop).
  // Tries bracketed IPs first (highest confidence), then bare IPs.
  function originIp(headers) {
    var recvd = getAll(headers, "received");
    var bracketPat = /\[(\d{1,3}(?:\.\d{1,3}){3})\]/g;
    var barePat = /(?:^|[^0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9.])/g;
    function validIp(ip) {
      var parts = String(ip).split(".");
      if (parts.length !== 4) return false;
      return parts.every(function (p) {
        return /^\d{1,3}$/.test(p) && parseInt(p, 10) <= 255;
      });
    }
    function candsFrom(text, pat) {
      var cands = [], m;
      pat.lastIndex = 0;
      while ((m = pat.exec(text))) {
        if (validIp(m[1]) && !isPrivateIp(m[1])) cands.push(m[1]);
      }
      return cands;
    }
    function sweep(pat) {
      var cands = [];
      if (recvd.length) {
        cands = candsFrom(recvd[recvd.length - 1], pat);
      }
      for (var i = 0; i < recvd.length && !cands.length; i++) {
        cands = candsFrom(recvd[i], pat);
      }
      return cands;
    }
    var cands = sweep(bracketPat);
    if (!cands.length) cands = sweep(barePat);
    return cands.length ? cands[0] : null;
  }

  function fetchJson(url, timeoutMs) {
    return new Promise(function (resolve) {
      var done = false;
      var timer = setTimeout(function () {
        if (!done) { done = true; resolve(null); }
      }, timeoutMs || 8000);
      fetch(url, { headers: { "Accept": "application/json" } })
        .then(function (res) {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve(res.ok ? res.json().catch(function () { return null; }) : null);
        })
        .catch(function () {
          if (!done) { done = true; clearTimeout(timer); resolve(null); }
        });
    });
  }

  function rdapLookup(ip) {
    var chain = Promise.resolve(null);
    RDAP_BASES.forEach(function (base) {
      chain = chain.then(function (found) {
        if (found) return found;
        return fetchJson(base + encodeURIComponent(ip), 8000);
      });
    });
    return chain;
  }

  function vcardEmail(vcardArray) {
    if (!vcardArray || vcardArray.length < 2) return null;
    var props = vcardArray[1] || [];
    for (var i = 0; i < props.length; i++) {
      var item = props[i];
      if (Array.isArray(item) && item.length >= 4 && item[0] === "email") {
        return item[3];
      }
    }
    return null;
  }

  function vcardFn(vcardArray) {
    if (!vcardArray || vcardArray.length < 2) return null;
    var props = vcardArray[1] || [];
    for (var i = 0; i < props.length; i++) {
      var item = props[i];
      if (Array.isArray(item) && item.length >= 4 && item[0] === "fn") {
        return item[3];
      }
    }
    return null;
  }

  function extractAbuse(obj) {
    if (!obj || !obj.entities) return null;
    for (var i = 0; i < obj.entities.length; i++) {
      var ent = obj.entities[i];
      var roles = (ent.roles || []).map(function (r) { return String(r).toLowerCase(); });
      if (roles.indexOf("abuse") !== -1) {
        var em = vcardEmail(ent.vcardArray);
        if (em) return em;
      }
      var nested = extractAbuse(ent);
      if (nested) return nested;
    }
    return null;
  }

  function extractOrg(obj) {
    if (!obj) return null;
    (obj.entities || []).forEach(function () {});
    var ents = obj.entities || [];
    for (var i = 0; i < ents.length; i++) {
      var roles = (ents[i].roles || []).map(function (r) { return String(r).toLowerCase(); });
      if (roles.indexOf("registrant") !== -1) {
        var fn = vcardFn(ents[i].vcardArray);
        if (fn) return fn;
      }
    }
    return obj.name || null;
  }

  // Reverse DNS via DNS-over-HTTPS (no raw DNS in a browser).
  function reverseDns(ip) {
    var rev = String(ip).split(".").reverse().join(".") + ".in-addr.arpa";
    return fetchJson("https://dns.google/resolve?name=" +
      encodeURIComponent(rev) + "&type=PTR", 8000).then(function (d) {
        try {
          var ans = d.Answer || [];
          for (var i = 0; i < ans.length; i++) {
            if (ans[i].type === 12 && ans[i].data) {
              return String(ans[i].data).replace(/\.$/, "");
            }
          }
        } catch (e) {}
        return "unknown";
      });
  }

  function whitelisted(host) {
    host = String(host || "").toLowerCase();
    return PROVIDER_WHITELIST.some(function (w) {
      return host === w || host.endsWith("." + w);
    });
  }

  // When mail genuinely came from a mailbox provider, the header trail
  // ends there — but the SENDER'S ACCOUNT can still be reported. Tailored
  // advice per provider; null means use the generic message.
  function providerAdvice(host) {
    host = String(host || "").toLowerCase();
    function has(d) { return host === d || host.endsWith("." + d); }
    if (has("google.com") || has("googlemail.com")) {
      return "Sent from a real Gmail account — the header trail ends here. " +
        "To kill it, report the account itself: in Gmail, open the three-dot " +
        "menu on this message and choose \u201CReport phishing\u201D.";
    }
    if (has("outlook.com") || has("hotmail.com") || has("live.com") ||
        has("msn.com") || has("protection.outlook.com")) {
      return "Sent from a real Microsoft account — the header trail ends here. " +
        "In Outlook, select the message and use Report \u2192 Report phishing " +
        "to flag the account.";
    }
    if (has("yahoo.com") || has("aol.com")) {
      return "Sent from a real Yahoo/AOL account — the header trail ends here. " +
        "Use your mail app's \u201CReport phishing\u201D option to flag the " +
        "sender's account.";
    }
    if (has("icloud.com") || has("me.com") || has("mac.com") || has("apple.com")) {
      return "Sent from a real iCloud account — the header trail ends here. " +
        "Forward it to reportphishing@apple.com to flag the account.";
    }
    return null;
  }

  function stripTags(html) {
    return String(html)
      .replace(/<img\b[^>]*\balt="([^"]*)"[^>]*>/gi, " $1 ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&amp;/g, "&").replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  function extractUrls(text) {
    var urls = [];
    var m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text))) {
      var u = m[0].replace(/[.,;!)\]}"'=]+$/, "");
      if (u && urls.indexOf(u) === -1 && urls.length < 20) urls.push(u);
    }
    return urls;
  }

  function redFlags(fromAddr, urls, text) {
    var flags = [];
    var dm = (String(fromAddr || "").match(/@([\w.-]+)/) || [])[1] || "";
    dm = dm.toLowerCase();
    var tld = dm.indexOf(".") !== -1 ? dm.split(".").pop() : "";
    if (SKETCHY_TLDS.indexOf(tld) !== -1) {
      flags.push("Sender uses a ." + tld + " domain — throwaway domains scammers burn through by the dozen.");
    }
    var urlHosts = {};
    urls.forEach(function (u) {
      var hm = u.match(/https?:\/\/([^/]+)/);
      if (hm) urlHosts[hm[1].toLowerCase().replace(/^www\./, "")] = 1;
    });
    urlHosts = Object.keys(urlHosts);
    if (dm && urlHosts.length && !urlHosts.some(function (h) {
      return dm.indexOf(h) !== -1 || h.indexOf(dm) !== -1;
    })) {
      flags.push("The links go somewhere completely different from the sender's domain — classic redirector trick.");
    }
    var low = String(text || "").toLowerCase();
    [["act now", "pressure tactic ('act now')"],
     ["limited time", "pressure tactic ('limited time')"],
     ["verify your account", "phishing phrase ('verify your account')"],
     ["suspended", "threat that your account is 'suspended'"],
     ["gift card", "gift-card mention — huge scam marker"],
     ["{{", "unfilled template placeholders like {{date}} — mass-sent phish kit"]
    ].forEach(function (pair) {
      if (low.indexOf(pair[0]) !== -1) flags.push("Contains " + pair[1] + ".");
    });
    return { flags: flags, senderDomain: dm, urlHosts: urlHosts };
  }

  function buildComplaint(a) {
    if (a.skipComplaint || !a.ip || !a.abuse) return null;
    var L = [];
    L.push("Hello Abuse Team,");
    L.push("");
    L.push("I received spam originating from your network:");
    L.push("");
    L.push("  Source IP:      " + a.ip);
    L.push("  Server name:    " + a.host);
    L.push("  Claimed sender: " + (a.from || "unknown"));
    L.push("  Subject:        " + (a.subject || "unknown"));
    L.push("  Date received:  " + (a.date || "unknown"));
    if (a.urls && a.urls.length) {
      L.push("  Links in message:");
      a.urls.slice(0, 10).forEach(function (u) { L.push("    - " + u); });
    }
    L.push("");
    L.push("Key headers as evidence:");
    L.push("  Message-ID: " + (a.messageId || "unknown"));
    if (a.ingressReceived) L.push("  " + a.ingressReceived);
    L.push("");
    L.push("Please investigate the account or customer responsible and take appropriate action. Thank you.");
    return {
      to: a.abuse,
      subject: "Network abuse complaint — spam from " + a.ip,
      body: L.join("\n")
    };
  }

  // Decode RFC 2047 encoded-words: =?charset?Q?...?= / =?charset?B?...?=
  function decodeMimeWords(s) {
    return String(s || "").replace(/=\?([^?\s]+)\?([qQbB])\?([^?]*)\?=/g,
      function (m, charset, enc, text) {
        try {
          var bytes;
          if (enc.toUpperCase() === "B") {
            var bin = atob(text);
            bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          } else {
            var qp = text.replace(/_/g, " ");
            var arr = [];
            for (var j = 0; j < qp.length; j++) {
              if (qp[j] === "=" && j + 2 < qp.length &&
                  /^[0-9a-fA-F]{2}$/.test(qp.substr(j + 1, 2))) {
                arr.push(parseInt(qp.substr(j + 1, 2), 16));
                j += 2;
              } else {
                arr.push(qp.charCodeAt(j) & 0xff);
              }
            }
            bytes = new Uint8Array(arr);
          }
          return new TextDecoder(charset || "utf-8").decode(bytes);
        } catch (e) {
          return m;
        }
      });
  }

  // Decode quoted-printable body text (soft breaks + =XX escapes).
  function decodeQP(text) {
    return String(text || "")
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-Fa-f]{2})/g, function (m, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
  }

  function decodeBody(bodyText, headers) {
    var cte = getFirst(headers, "content-transfer-encoding").toLowerCase();
    var t = String(bodyText || "");
    try {
      if (cte.indexOf("base64") !== -1 && t.length > 100) {
        var bin = atob(t.replace(/\s+/g, ""));
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder("utf-8").decode(bytes);
      }
    } catch (e) {}
    // v1.0.33: decode quoted-printable ONLY when this entity/part
    // actually declares it, or the text shows QP soft line breaks
    // ("=" at end of line). The old bare /=[0-9A-Fa-f]{2}/ sniff
    // false-fired on innocent plain text containing "=32" etc.
    // (e.g. "pid=32344&vid=222…"): decodeQP then converted "=32" to
    // "2" and "=22" to a `"` byte, which truncated URLs at the
    // extractUrls regex — real links came out mangled.
    if (cte.indexOf("quoted-printable") !== -1 || /=\r?\n/.test(t)) {
      try { return decodeQP(t); } catch (e) {}
    }
    return t;
  }

  // --- MIME part walking (v1.0.32) ---
  // Typical spam is multipart/*: the TOP-LEVEL headers rarely declare
  // a Content-Transfer-Encoding — each MIME part carries its own.
  // decodeBody() alone only honors the top level, so a base64 HTML
  // part was never decoded and extractUrls() scanned base64 gibberish
  // (the confirmed root cause of empty link lists on multipart spam).

  // Boundary parameter out of the Content-Type header, or null.
  function mimeBoundary(headers) {
    var ct = getFirst(headers, "content-type");
    var m = ct.match(/boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
    if (!m) return null;
    return m[1] || m[2] || null;
  }

  // Split a multipart entity's body into [{headers, body}, ...].
  // Returns [] when the entity isn't multipart or has no boundary.
  function mimeParts(bodyText, headers) {
    var ct = getFirst(headers, "content-type").toLowerCase();
    if (ct.indexOf("multipart/") !== 0) return [];
    var boundary = mimeBoundary(headers);
    if (!boundary) return [];
    var segments = String(bodyText).split("--" + boundary);
    var parts = [];
    for (var i = 1; i < segments.length; i++) { // [0] is the preamble
      var seg = segments[i];
      if (/^--/.test(seg)) break; // closing delimiter; rest is epilogue
      seg = seg.replace(/^[ \t]*\r?\n/, "").replace(/\r?\n[ \t]*$/, "");
      if (!seg.trim()) continue;
      parts.push({
        headers: parseHeaders(seg),
        body: seg.split(/\r?\n\r?\n/).slice(1).join("\n\n")
      });
    }
    return parts;
  }

  // Decode every MIME part per its OWN Content-Transfer-Encoding.
  // One level of nesting is walked (e.g. multipart/alternative
  // inside multipart/mixed). Returns an array of decoded part bodies.
  function decodeMimeParts(bodyText, headers) {
    var out = [];
    mimeParts(bodyText, headers).forEach(function (p) {
      out.push(decodeBody(p.body, p.headers));
      mimeParts(p.body, p.headers).forEach(function (sub) {
        out.push(decodeBody(sub.body, sub.headers));
      });
    });
    return out;
  }

  // The Received header the traced IP actually came from (best evidence).
  function evidenceHeader(headers, ip) {
    var recvd = getAll(headers, "received");
    if (!ip || !recvd.length) {
      return recvd.length ? recvd[recvd.length - 1].slice(0, 300) : null;
    }
    for (var i = recvd.length - 1; i >= 0; i--) {
      if (recvd[i].indexOf(ip) !== -1) return recvd[i].slice(0, 300);
    }
    return recvd[recvd.length - 1].slice(0, 300);
  }

  function analyze(rawText) {
    var headers = parseHeaders(rawText);
    var rawBody = String(rawText).split(/\r?\n\r?\n/).slice(1).join("\n\n");
    var bodyText = decodeBody(rawBody, headers);
    var text = stripTags(bodyText).slice(0, 100000);
    var from = decodeMimeWords(getFirst(headers, "from"));
    var subject = decodeMimeWords(getFirst(headers, "subject"));
    var date = getFirst(headers, "date");
    var messageId = getFirst(headers, "message-id");
    // v1.0.32: also decode each MIME part on its own terms (a base64
    // or quoted-printable part inside a multipart message) and scan
    // the decoded part bodies — raw and tag-stripped — for links.
    var urlText = bodyText + " " + text;
    decodeMimeParts(rawBody, headers).forEach(function (partBody) {
      urlText += " " + partBody + " " + stripTags(partBody);
    });
    var urls = extractUrls(urlText);
    var ip = originIp(headers);
    var rf = redFlags(from, urls, text);
    return {
      from: from, subject: subject, date: date, messageId: messageId,
      ip: ip, urls: urls, urlHosts: rf.urlHosts, senderDomain: rf.senderDomain,
      flags: rf.flags,
      ingressReceived: evidenceHeader(headers, ip),
      bodyPreview: text.slice(0, 1500)
    };
  }

  // Full pipeline: analyze -> RDAP -> PTR -> complaint.
  function investigate(rawText, onProgress) {
    var a = analyze(rawText);
    function prog(s) { if (onProgress) { try { onProgress(s); } catch (e) {} } }
    if (!a.ip) {
      a.stage = "no-ip";
      return Promise.resolve(a);
    }
    prog("Looking up " + a.ip + "…");
    return rdapLookup(a.ip).then(function (rdap) {
      a.org = rdap ? extractOrg(rdap) : null;
      a.abuse = rdap ? extractAbuse(rdap) : null;
      prog("Reverse DNS…");
      return reverseDns(a.ip);
    }).then(function (host) {
      a.host = host;
      a.skipComplaint = whitelisted(host);
      a.providerAdvice = a.skipComplaint ? providerAdvice(host) : null;
      // Gmail's report flow can be driven from the page; other providers can't.
      a.gmailAutoReport = !!(a.skipComplaint &&
        /google\.com|googlemail\.com/i.test(String(host || "")));
      var c = buildComplaint(a);
      a.complaint = c;
      a.stage = "done";
      return a;
    });
  }

  var api = {
    parseHeaders: parseHeaders, originIp: originIp, isPrivateIp: isPrivateIp,
    analyze: analyze, investigate: investigate, buildComplaint: buildComplaint,
    extractAbuse: extractAbuse, extractOrg: extractOrg, whitelisted: whitelisted,
    providerAdvice: providerAdvice,
    redFlags: redFlags, RDAP_BASES: RDAP_BASES
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // Node (tests)
  } else {
    window.SpamAvenger = api; // browser
  }
})();
