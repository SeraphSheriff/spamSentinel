/* Spamfighter for Gmail — content script.
 * Injects the shield button into Gmail, fetches "show original" for the
 * open message, runs the analysis, and renders the results panel.
 * Everything runs locally in your browser. The only network calls are
 * RDAP + reverse-DNS lookups of the SPAMMER's IP.
 *
 * Note: this file deliberately never uses innerHTML. All dynamic text
 * goes through textContent, so there is no HTML-injection surface.
 */
(function () {
  "use strict";

  var SF_VERSION = "1.0.18";
  var BTN_ID = "spamfighter-btn";
  var PANEL_ID = "spamfighter-panel";

  // Tiny DOM builder: h("div", {class: "x", id: "y"}, childEl, "text", ...)
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        if (k === "class") el.className = attrs[k];
        else el.setAttribute(k, attrs[k]);
      }
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return el;
  }

  function clearEl(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  function accountIndex() {
    var m = location.pathname.match(/\/mail\/u\/(\d+)/);
    return m ? m[1] : "0";
  }

  function messageOpen() {
    // A message/thread view has a legacy message id in the DOM.
    return !!document.querySelector("[data-legacy-message-id]");
  }

  function currentMessageId() {
    var el = document.querySelector("[data-legacy-message-id]");
    return el ? el.getAttribute("data-legacy-message-id") : null;
  }

  function ikParam() {
    // Gmail's session key ("ik") is required by its show-original endpoint.
    // Hunt for it in several places; page markup varies by Gmail version.
    function scan(text) {
      if (!text) return null;
      // Note: serialized markup escapes & as &amp; — match both forms.
      var m = text.match(/[?&]ik=([a-f0-9]{6,})/) ||
              text.match(/&amp;ik=([a-f0-9]{6,})/) ||
              text.match(/"ik"\s*:\s*"([a-f0-9]{6,})"/);
      return m ? m[1] : null;
    }
    var found = null;
    try {
      // Page-context globals (classic Gmail exposes GLOBALS[9] === ik).
      // Firefox content scripts reach them via wrappedJSObject.
      var pg = (typeof wrappedJSObject !== "undefined") ? wrappedJSObject : window;
      if (pg && pg.GLOBALS && pg.GLOBALS[9] && /^[a-f0-9]{6,}$/.test(pg.GLOBALS[9])) {
        return String(pg.GLOBALS[9]);
      }
    } catch (e) {}
    try { found = scan(document.documentElement.innerHTML); } catch (e) {}
    if (found) return found;
    try {
      var scripts = document.querySelectorAll("script");
      for (var i = 0; i < scripts.length; i++) {
        found = scan(scripts[i].textContent || "");
        if (found) return found;
      }
    } catch (e) {}
    return null;
  }

  function shieldSvg() {
    var NS = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "26");
    svg.setAttribute("height", "26");
    svg.setAttribute("aria-hidden", "true");
    var paths = [
      ["#fff", "M12 2l8 3v6c0 5-3.5 9.3-8 11-4.5-1.7-8-6-8-11V5l8-3z"],
      ["#c0392b", "M12 4.2l6 2.2v4.9c0 3.9-2.7 7.3-6 8.7-3.3-1.4-6-4.8-6-8.7V6.4l6-2.2z"],
      ["#fff", "M13.2 6.5l-4.9 5.2 2.1 2.1 2.8-3 3.4 4.2 2-1.6-5.4-6.9z"]
    ];
    paths.forEach(function (pd) {
      var p = document.createElementNS(NS, "path");
      p.setAttribute("fill", pd[0]);
      p.setAttribute("d", pd[1]);
      svg.appendChild(p);
    });
    return svg;
  }

  function ensureButton() {
    if (document.getElementById(BTN_ID)) return;
    var btn = document.createElement("button");
    btn.id = BTN_ID;
    btn.title = "Spamfighter: trace who really sent this email";
    btn.setAttribute("aria-label", btn.title);
    btn.appendChild(shieldSvg());
    btn.addEventListener("click", onShieldClick);
    document.body.appendChild(btn);
  }

  function syncButton() {
    var btn = document.getElementById(BTN_ID);
    if (!btn) return;
    btn.style.display = messageOpen() ? "flex" : "none";
  }

  // Drives Gmail's own "Report phishing" flow for the open message:
  // opens the message's three-dot menu and clicks the menu item.
  // Returns {ok, dbg}; Gmail still asks the user to confirm, so nothing
  // is reported without their say-so.
  function gmailReportPhishing() {
    function fail(dbg) { return { ok: false, dbg: dbg }; }
    try {
      var msgEl = document.querySelector("[data-legacy-message-id]");
      if (!msgEl) return fail("no message element");
      var inDoc = document.querySelectorAll('[aria-label="More message options"]').length;
      var more = null, root = msgEl;
      var labels = ["More message options", "More", "More options"];
      while (root && root !== document.body && !more) {
        for (var l = 0; l < labels.length; l++) {
          more = root.querySelector('[aria-label="' + labels[l] + '"]');
          if (more) break;
        }
        root = root.parentElement;
      }
      if (!more) {
        // Diagnostics: button labels near the message, so the selector
        // can be fixed to match this Gmail layout.
        var seen = [], seenSet = {}, scope = msgEl, u, i, al;
        for (u = 0; u < 4 && scope; u++) scope = scope.parentElement;
        var btns = (scope || document).querySelectorAll("button,[role=button]");
        for (i = 0; i < btns.length && seen.length < 10; i++) {
          al = btns[i].getAttribute("aria-label");
          if (al && !seenSet[al]) { seenSet[al] = 1; seen.push(al); }
        }
        return fail("More buttons in page: " + inDoc +
          "; nearby: " + seen.join(" / "));
      }
      more.click();
      var tries = 0;
      var timer = setInterval(function () {
        tries++;
        var items = document.querySelectorAll(
          '[role="menuitem"],[role="menuitemradio"],[role="menuitemcheckbox"]');
        for (var i = 0; i < items.length; i++) {
          var mt = (items[i].textContent || "").trim().toLowerCase();
          if (mt === "report phishing") {
            clearInterval(timer);
            items[i].click();
            return;
          }
          if (mt === "report not phishing") {
            // Already reported: Gmail swaps the menu item out.
            clearInterval(timer);
            more.click(); // close the menu
            markAlreadyReported();
            return;
          }
        }
        if (tries > 25) clearInterval(timer); // ~5s: give up quietly
      }, 200);
      return { ok: true };
    } catch (e) {
      return fail("exception");
    }
  }

  // Diagnostic helper: aria-labels of buttons near the message, used to
  // fix selectors when Gmail's layout doesn't match expectations.
  function nearbyButtonLabels(msgEl, cap) {
    var seen = [], seenSet = {}, scope = msgEl, u, i, al;
    for (u = 0; u < 4 && scope; u++) scope = scope.parentElement;
    var btns = (scope || document).querySelectorAll("button,[role=button]");
    for (i = 0; i < btns.length && seen.length < (cap || 12); i++) {
      al = btns[i].getAttribute("aria-label");
      if (al && !seenSet[al]) { seenSet[al] = 1; seen.push(al); }
    }
    return seen;
  }

  // Walks up from the message to its "More message options" menu button.
  function findMoreButton(msgEl) {
    var more = null, root = msgEl;
    var labels = ["More message options", "More", "More options"];
    while (root && root !== document.body && !more) {
      for (var l = 0; l < labels.length; l++) {
        more = root.querySelector('[aria-label="' + labels[l] + '"]');
        if (more) break;
      }
      root = root.parentElement;
    }
    return more;
  }

  // Marks the report button "already reported" (message was previously
  // reported: Gmail drops "Report phishing" from the menu and shows a
  // banner instead).
  function markAlreadyReported() {
    var rb2 = document.getElementById("sf-report-phish");
    if (rb2) {
      rb2.disabled = true;
      rb2.textContent = "Already reported to Google \u2713";
      setTimeout(function () {
        rb2.disabled = false;
        rb2.textContent = "Report phishing to Google";
      }, 8000);
    }
  }

  // Forward-to addresses for phishing intake (industry + government).
  var SF_FWD_TO = ["reportphishing@apwg.org", "report@cisa.gov"];

  // Opens the message's three-dot menu, clicks its Forward item, then
  // prefills the forward compose's To field with the APWG + CISA intake
  // addresses. The user reviews the forward and hits Send themselves.
  // Updates the panel button directly.
  function gmailForwardPhish() {
    var rb = document.getElementById("sf-fwd-phish");
    function fail(dbg) {
      if (rb) {
        rb.disabled = true;
        rb.textContent = "Couldn't open forward (" + String(dbg).slice(0, 160) +
          ") \u2014 forward it manually";
      }
      return { ok: false, dbg: dbg };
    }
    function done() {
      if (rb) {
        rb.textContent = "Forward addressed \u2014 review and hit Send";
        // Re-arm: if the user closed the compose without sending,
        // they get the button back instead of a dead panel.
        setTimeout(function () {
          rb.disabled = false;
          rb.textContent = "Forward phish to APWG + CISA";
        }, 12000);
      }
      return { ok: true };
    }
    function fillCompose(before) {
      var t2 = 0;
      var timer2 = setInterval(function () {
        try {
          t2++;
          var now = document.querySelectorAll('textarea[name="to"]');
          var fresh = null, i;
          for (i = 0; i < now.length; i++) {
            if (before.indexOf(now[i]) === -1) { fresh = now[i]; break; }
          }
          if (!fresh && t2 <= 20) return; // keep waiting (~5s)
          clearInterval(timer2);
          if (!fresh) {
            fail("toFields " + before.length + "\u2192" + now.length +
              ", no new compose");
            return;
          }
          fresh.focus();
          var v = SF_FWD_TO.join(", ");
          try {
            var setter = Object.getOwnPropertyDescriptor(
              window.HTMLTextAreaElement.prototype, "value").set;
            if (setter) setter.call(fresh, v); else fresh.value = v;
          } catch (e) { fresh.value = v; }
          fresh.dispatchEvent(new Event("input", { bubbles: true }));
          fresh.dispatchEvent(new KeyboardEvent("keydown",
            { key: "Enter", keyCode: 13, which: 13, bubbles: true }));
          fresh.dispatchEvent(new KeyboardEvent("keyup",
            { key: "Enter", keyCode: 13, which: 13, bubbles: true }));
          done();
        } catch (e) {
          clearInterval(timer2);
          fail("exception");
        }
      }, 250);
    }
    try {
      var msgEl = document.querySelector("[data-legacy-message-id]");
      if (!msgEl) return fail("no message element");
      var more = findMoreButton(msgEl);
      if (!more) {
        return fail("no message menu; nearby: " +
          nearbyButtonLabels(msgEl, 12).join(" / "));
      }
      var before = Array.prototype.slice.call(
        document.querySelectorAll('textarea[name="to"]'));
      if (rb) { rb.disabled = true; rb.textContent = "Opening forward\u2026"; }
      more.click();
      var tries = 0;
      var timer = setInterval(function () {
        try {
          tries++;
          var items = document.querySelectorAll(
            '[role="menuitem"],[role="menuitemradio"],[role="menuitemcheckbox"]');
          for (var i = 0; i < items.length; i++) {
            if ((items[i].textContent || "").trim().toLowerCase() === "forward") {
              clearInterval(timer);
              items[i].click();
              fillCompose(before);
              return;
            }
          }
          if (tries > 25) { // ~5s
            clearInterval(timer);
            fail("no Forward item in menu");
          }
        } catch (e) {
          clearInterval(timer);
          fail("exception");
        }
      }, 200);
      return { ok: true, pending: true };
    } catch (e) {
      return fail("exception");
    }
  }

  // Builds the panel shell and returns its .sf-body element.
  function showPanel() {
    closePanel();
    var wrap = document.createElement("div");
    wrap.id = PANEL_ID;
    var card = h("div", { "class": "sf-card" });
    var head = h("div", { "class": "sf-head" },
      h("span", null, "\uD83D\uDEE1\uFE0F Spamfighter"));
    var x = h("button", { "class": "sf-x", "aria-label": "Close" }, "\u2715");
    x.addEventListener("click", closePanel);
    head.appendChild(x);
    var body = h("div", { "class": "sf-body" });
    card.appendChild(head);
    card.appendChild(body);
    wrap.appendChild(card);
    document.body.appendChild(wrap);
    return body;
  }

  function closePanel() {
    var p = document.getElementById(PANEL_ID);
    if (p) p.remove();
  }

  function mkRow(label, value, mono) {
    return h("div", { "class": "sf-row" },
      h("span", null, label),
      h("b", mono ? { "class": "sf-mono" } : null, String(value)));
  }

  function renderLoading(body, step) {
    clearEl(body);
    body.appendChild(
      h("div", { "class": "sf-loading" },
        h("div", { "class": "sf-spin" }),
        h("p", null, step || "Working\u2026")));
  }

  function renderResult(body, a) {
    clearEl(body);
    body.appendChild(mkRow("From", a.from || "unknown"));
    body.appendChild(mkRow("Subject", a.subject || "(no subject)"));
    if (!a.ip) {
      body.appendChild(h("p", { "class": "sf-warn" },
        "Couldn't find the sending server in the headers. " +
        "That happens with mailing lists, forwards, and some bulk senders. " +
        "Nothing to complain to directly \u2014 but the report links below still apply."));
    } else {
      body.appendChild(mkRow("Sending IP", a.ip, true));
      body.appendChild(mkRow("Server", a.host || "unknown"));
      body.appendChild(mkRow("Owned by", a.org || "unknown"));
      body.appendChild(mkRow("Abuse contact", a.abuse || "not published"));
      body.appendChild(h("p", { "class": "sf-note" },
        'The "From" address is makeup. The IP is the face underneath.'));
    }
    if (a.flags && a.flags.length) {
      var fw = h("div", { "class": "sf-flags" }, h("b", null, "Red flags"));
      var ul = h("ul");
      a.flags.forEach(function (f) { ul.appendChild(h("li", null, f)); });
      fw.appendChild(ul);
      body.appendChild(fw);
    }
    if (a.complaint) {
      var c = a.complaint;
      var cw = h("div", { "class": "sf-complaint" },
        h("b", null, "Ready-to-send complaint"));
      var ta = h("textarea", { id: "sf-complaint-text" });
      ta.readOnly = true;
      ta.value = "To: " + c.to + "\nSubject: " + c.subject + "\n\n" + c.body;
      cw.appendChild(ta);
      var copyBtn = h("button", { id: "sf-copy" }, "Copy complaint");
      var compBtn = h("button", { id: "sf-compose" }, "Open in Gmail");
      cw.appendChild(h("div", { "class": "sf-actions" }, copyBtn, compBtn));
      body.appendChild(cw);
      copyBtn.addEventListener("click", function () {
        ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        if (navigator.clipboard) navigator.clipboard.writeText(ta.value).catch(function () {});
        copyBtn.textContent = "Copied!";
        setTimeout(function () { copyBtn.textContent = "Copy complaint"; }, 1500);
      });
      compBtn.addEventListener("click", function () {
        var url = "https://mail.google.com/mail/u/" + accountIndex() +
          "/?view=cm&fs=1" +
          "&to=" + encodeURIComponent(c.to) +
          "&su=" + encodeURIComponent(c.subject) +
          "&body=" + encodeURIComponent(c.body);
        window.open(url, "_blank", "noopener");
      });
    } else if (a.ip && !a.skipComplaint) {
      body.appendChild(h("p", { "class": "sf-warn" },
        "No published abuse contact for this IP. " +
        "Report the links below via Google Safe Browsing instead."));
    } else if (a.skipComplaint) {
      body.appendChild(h("p", { "class": "sf-warn" },
        a.providerAdvice ||
        ("This came from a big mailbox provider\u2019s own servers \u2014 " +
         "no complaint generated (it would hit the wrong target).")));
      if (a.gmailAutoReport) {
        var rb = h("button", { id: "sf-report-phish" },
          "Report phishing to Google");
        rb.addEventListener("click", function () {
          // Already-reported messages show a Gmail banner ("You reported
          // this message as phishing") instead of the report dialog.
          if ((document.body.textContent || "").indexOf(
                "reported this message as phishing") !== -1) {
            markAlreadyReported();
            return;
          }
          var r = gmailReportPhishing();
          rb.disabled = true;
          if (r.ok) {
            rb.textContent = "Opening Gmail\u2019s report dialog\u2026";
            // Re-arm: if the user cancels Gmail's dialog, the button
            // comes back instead of staying dead until a page refresh.
            setTimeout(function () {
              rb.disabled = false;
              rb.textContent = "Report phishing to Google";
            }, 8000);
          } else {
            rb.textContent = "Couldn't open it (" + String(r.dbg).slice(0, 140) +
              ") \u2014 use the three-dot menu manually";
          }
        });
        body.appendChild(h("div", { "class": "sf-actions" }, rb));
      }
    }
    var links = h("div", { "class": "sf-links" },
      h("b", null, "Also report it: "));
    links.appendChild(h("a", {
      href: "https://reportfraud.ftc.gov/", target: "_blank", rel: "noopener"
    }, "FTC fraud report"));
    links.appendChild(document.createTextNode(" "));
    links.appendChild(h("a", {
      href: "https://safebrowsing.google.com/safebrowsing/report_phish/",
      target: "_blank", rel: "noopener"
    }, "Google Safe Browsing"));
    body.appendChild(links);
    var fwdBtn = h("button", { id: "sf-fwd-phish" },
      "Forward phish to APWG + CISA");
    fwdBtn.addEventListener("click", function () { gmailForwardPhish(); });
    body.appendChild(h("div", { "class": "sf-actions" }, fwdBtn));
    body.appendChild(h("p", { "class": "sf-fine" },
      "Nothing is sent automatically. You review and send the complaint yourself."));
  }

  function fetchOriginal(mid, onStep) {
    var ik = ikParam();
    var acct = accountIndex();
    var urls = [];
    if (ik) {
      urls.push("https://mail.google.com/mail/u/" + acct + "/?ui=2&ik=" + ik +
        "&view=om&th=" + encodeURIComponent(mid));
    }
    urls.push("https://mail.google.com/mail/u/" + acct + "/?ui=2&view=om&th=" +
      encodeURIComponent(mid));
    urls.push("https://mail.google.com/mail/u/" + acct + "/?view=om&th=" +
      encodeURIComponent(mid));

    function cleanErr(e) {
      try {
        if (e && e.message) return String(e.message);
        return String(e);
      } catch (x) {
        return "unknown error";
      }
    }

    function step(s) {
      if (onStep) { try { onStep(s); } catch (e) {} }
    }

    var failures = [];
    function attempt(i) {
      if (i >= urls.length) {
        throw new Error("Gmail wouldn't hand over the headers. " +
          failures.join("; "));
      }
      step("Fetching full headers (try " + (i + 1) + "/" + urls.length + ")\u2026");
      var p;
      try {
        p = fetch(urls[i], { credentials: "include" });
      } catch (e) {
        failures.push("try " + (i + 1) + ": couldn't start request");
        return attempt(i + 1);
      }
      return Promise.resolve(p).then(function (res) {
        if (!res.ok) {
          failures.push("try " + (i + 1) + ": HTTP " + res.status);
          return attempt(i + 1); // try next form
        }
        return res.text();
      }, function () {
        failures.push("try " + (i + 1) + ": network error");
        return attempt(i + 1); // network-level fail -> try next form
      }).then(function (html) {
        if (typeof html !== "string") return html; // came from attempt()
        var doc = new DOMParser().parseFromString(html, "text/html");
        var text = doc.body ? doc.body.innerText : "";
        if (text && text.indexOf("Received:") !== -1) return text;
        failures.push("try " + (i + 1) + ": page had no headers");
        return attempt(i + 1); // wrong page (login/error) -> try next form
      }).catch(function (e) {
        // Normalize to a plain string: Firefox wraps cross-compartment
        // rejection values in an unreadable wrapper otherwise.
        throw new Error(cleanErr(e));
      });
    }
    return attempt(0);
  }

  function onShieldClick() {
    var mid = currentMessageId();
    if (!mid) {
      var body0 = showPanel();
      body0.appendChild(h("p", { "class": "sf-warn" },
        "Open a single email first, then click the shield."));
      return;
    }
    var panel = showPanel();
    function prog(s) { renderLoading(panel, s); }
    prog("Finding the open message\u2026");
    var p;
    try {
      p = fetchOriginal(mid, prog);
    } catch (e) {
      p = Promise.reject(e);
    }
    Promise.resolve(p).then(function (raw) {
      return window.Spamfighter.investigate(raw, prog);
    }).then(function (a) {
      renderResult(panel, a);
    }).catch(function (err) {
      var msg;
      try {
        msg = String((err && err.message) || err);
      } catch (x) {
        msg = "unreadable error object";
      }
      clearEl(panel);
      panel.appendChild(h("p", { "class": "sf-warn" },
        "Something broke (v" + SF_VERSION + "): " + msg +
        ". Try reloading Gmail and clicking the shield again."));
    });
  }

  // Boot: inject button, keep it in sync with Gmail's SPA navigation.
  ensureButton();
  syncButton();
  var obs = new MutationObserver(function () {
    ensureButton();
    syncButton();
  });
  obs.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", syncButton);
})();
