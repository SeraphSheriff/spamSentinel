/* Spamfighter for Gmail — content script.
 * Injects the shield button into Gmail, fetches "show original" for the
 * open message, runs the analysis, and renders the results panel.
 * Everything runs locally in your browser. The only network calls are
 * RDAP + reverse-DNS lookups of the SPAMMER's IP.
 */
(function () {
  "use strict";

  var SF_VERSION = "1.0.8";
  var BTN_ID = "spamfighter-btn";
  var PANEL_ID = "spamfighter-panel";

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
      // Note: innerHTML serializes & as &amp; — match both forms.
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

  function ensureButton() {
    if (document.getElementById(BTN_ID)) return;
    var btn = document.createElement("button");
    btn.id = BTN_ID;
    btn.title = "Spamfighter: trace who really sent this email";
    btn.setAttribute("aria-label", btn.title);
    btn.innerHTML =
      '<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true">' +
      '<path fill="#fff" d="M12 2l8 3v6c0 5-3.5 9.3-8 11-4.5-1.7-8-6-8-11V5l8-3z"/>' +
      '<path fill="#c0392b" d="M12 4.2l6 2.2v4.9c0 3.9-2.7 7.3-6 8.7-3.3-1.4-6-4.8-6-8.7V6.4l6-2.2z"/>' +
      '<path fill="#fff" d="M13.2 6.5l-4.9 5.2 2.1 2.1 2.8-3 3.4 4.2 2-1.6-5.4-6.9z"/>' +
      "</svg>";
    btn.addEventListener("click", onShieldClick);
    document.body.appendChild(btn);
  }

  function syncButton() {
    var btn = document.getElementById(BTN_ID);
    if (!btn) return;
    btn.style.display = messageOpen() ? "flex" : "none";
  }

  function showPanel(html) {
    closePanel();
    var wrap = document.createElement("div");
    wrap.id = PANEL_ID;
    wrap.innerHTML =
      '<div class="sf-card">' +
      '<div class="sf-head"><span>🛡️ Spamfighter</span>' +
      '<button class="sf-x" aria-label="Close">✕</button></div>' +
      '<div class="sf-body">' + html + "</div></div>";
    wrap.querySelector(".sf-x").addEventListener("click", closePanel);
    document.body.appendChild(wrap);
    return wrap.querySelector(".sf-body");
  }

  function closePanel() {
    var p = document.getElementById(PANEL_ID);
    if (p) p.remove();
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function renderLoading(body, step) {
    body.innerHTML =
      '<div class="sf-loading"><div class="sf-spin"></div>' +
      "<p>" + esc(step || "Working…") + "</p></div>";
  }

  function renderResult(body, a) {
    var h = "";
    h += '<div class="sf-row"><span>From</span><b>' + esc(a.from || "unknown") + "</b></div>";
    h += '<div class="sf-row"><span>Subject</span><b>' + esc(a.subject || "(no subject)") + "</b></div>";
    if (!a.ip) {
      h += '<p class="sf-warn">Couldn\'t find the sending server in the headers. ' +
        "That happens with mailing lists, forwards, and some bulk senders. " +
        "Nothing to complain to directly — but the report links below still apply.</p>";
    } else {
      h += '<div class="sf-row"><span>Sending IP</span><b class="sf-mono">' + esc(a.ip) + "</b></div>";
      h += '<div class="sf-row"><span>Server</span><b>' + esc(a.host || "unknown") + "</b></div>";
      h += '<div class="sf-row"><span>Owned by</span><b>' + esc(a.org || "unknown") + "</b></div>";
      h += '<div class="sf-row"><span>Abuse contact</span><b>' +
        esc(a.abuse || "not published") + "</b></div>";
      h += '<p class="sf-note">The "From" address is makeup. The IP is the face underneath.</p>';
    }
    if (a.flags && a.flags.length) {
      h += '<div class="sf-flags"><b>Red flags</b><ul>' +
        a.flags.map(function (f) { return "<li>" + esc(f) + "</li>"; }).join("") +
        "</ul></div>";
    }
    if (a.complaint) {
      var c = a.complaint;
      h += '<div class="sf-complaint"><b>Ready-to-send complaint</b>' +
        '<textarea readonly id="sf-complaint-text">' + esc(
          "To: " + c.to + "\nSubject: " + c.subject + "\n\n" + c.body
        ) + "</textarea>" +
        '<div class="sf-actions">' +
        '<button id="sf-copy">Copy complaint</button>' +
        '<button id="sf-compose">Open in Gmail</button>' +
        "</div></div>";
    } else if (a.ip && !a.skipComplaint) {
      h += '<p class="sf-warn">No published abuse contact for this IP. ' +
        "Report the links below via Google Safe Browsing instead.</p>";
    } else if (a.skipComplaint) {
      h += '<p class="sf-warn">This came from a big mailbox provider\'s own servers — ' +
        "no complaint generated (it would hit the wrong target).</p>";
    }
    h += '<div class="sf-links"><b>Also report it:</b> ' +
      '<a href="https://reportfraud.ftc.gov/" target="_blank" rel="noopener">FTC fraud report</a>' +
      '<a href="https://safebrowsing.google.com/safebrowsing/report_phish/" target="_blank" rel="noopener">Google Safe Browsing</a></div>';
    h += '<p class="sf-fine">Nothing is sent automatically. You review and send the complaint yourself.</p>';
    body.innerHTML = h;

    var copyBtn = body.querySelector("#sf-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var ta = body.querySelector("#sf-complaint-text");
        ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        if (navigator.clipboard) navigator.clipboard.writeText(ta.value).catch(function () {});
        copyBtn.textContent = "Copied!";
        setTimeout(function () { copyBtn.textContent = "Copy complaint"; }, 1500);
      });
    }
    var compBtn = body.querySelector("#sf-compose");
    if (compBtn && a.complaint) {
      compBtn.addEventListener("click", function () {
        var c = a.complaint;
        var url = "https://mail.google.com/mail/u/" + accountIndex() +
          "/?view=cm&fs=1" +
          "&to=" + encodeURIComponent(c.to) +
          "&su=" + encodeURIComponent(c.subject) +
          "&body=" + encodeURIComponent(c.body);
        window.open(url, "_blank", "noopener");
      });
    }
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
      step("Fetching full headers (try " + (i + 1) + "/" + urls.length + ")…");
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
      var body0 = showPanel("");
      body0.innerHTML = '<p class="sf-warn">Open a single email first, then click the shield.</p>';
      return;
    }
    var panel = showPanel("");
    function prog(s) { renderLoading(panel, s); }
    prog("Finding the open message…");
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
      panel.innerHTML = '<p class="sf-warn">Something broke (v' + SF_VERSION +
        "): " + esc(msg) +
        '. Try reloading Gmail and clicking the shield again.</p>';
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
