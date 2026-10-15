/* Spamfighter for Gmail — analysis engine.
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
    "me.com", "mac.com", "proton.me", "protonmail.com", "zoho.com"
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
  function originIp(headers) {
    var recvd = getAll(headers, "received");
    var pat = /\[(\d{1,3}(?:\.\d{1,3}){3})\]/g;
    var cands = [];
    var m;
    if (recvd.length) {
      while ((m = pat.exec(recvd[recvd.length - 1]))) cands.push(m[1]);
    }
    if (!cands.length) {
      recvd.forEach(function (h) {
        pat.lastIndex = 0;
        while ((m = pat.exec(h))) cands.push(m[1]);
      });
    }
    for (var i = 0; i < cands.length; i++) {
      if (!isPrivateIp(cands[i])) return cands[i];
    }
    return null;
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
      var u = m[0].replace(/[.,;!)\]}"']+$/, "");
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

  function analyze(rawText) {
    var headers = parseHeaders(rawText);
    var bodyText = String(rawText).split(/\r?\n\r?\n/).slice(1).join("\n\n");
    var text = stripTags(bodyText).slice(0, 100000);
    var from = getFirst(headers, "from");
    var subject = getFirst(headers, "subject");
    var date = getFirst(headers, "date");
    var messageId = getFirst(headers, "message-id");
    var urls = extractUrls(bodyText + " " + text);
    var ip = originIp(headers);
    var rf = redFlags(from, urls, text);
    var recvd = getAll(headers, "received");
    return {
      from: from, subject: subject, date: date, messageId: messageId,
      ip: ip, urls: urls, urlHosts: rf.urlHosts, senderDomain: rf.senderDomain,
      flags: rf.flags,
      ingressReceived: recvd.length ? recvd[recvd.length - 1].slice(0, 300) : null,
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
    redFlags: redFlags, RDAP_BASES: RDAP_BASES
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // Node (tests)
  } else {
    window.Spamfighter = api; // browser
  }
})();
