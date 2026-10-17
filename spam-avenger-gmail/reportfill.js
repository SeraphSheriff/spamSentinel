/*
 * Spam Avenger for Gmail — report-form filler (v1.0.47)
 *
 * Runs only on the Google Safe Browsing report page and the FTC's
 * ReportFraud wizard. When the user clicks "Report to FTC" or
 * "Report to Google Safe Browsing" in the Gmail panel, content.js
 * stashes the case details (phish URLs, sender, subject, sending IP,
 * server) in chrome.storage.local and waits for the write before
 * opening the form. This script reads that stash — only if it is
 * less than 30 minutes old — and pre-fills the form with it.
 *
 * v1.0.30 hardens the Safe Browsing fill (an Angular Material app):
 * longer polling, form-field-container label lookup, and set-verify-
 * retry so a value Angular wipes gets written again.
 *
 * v1.0.31–v1.0.34 the banner was a diagnostic readout ("Spam
 * Avenger fill check") in the top-right corner, reporting each step
 * of the chain live — stash read, URL field hunt, fill
 * verification, details fill — and mirroring it to the console with
 * an [SpamAvenger] prefix, so a failed fill said WHERE it stopped
 * instead of failing silently. It caught real bugs: v1.0.32 (the
 * stash WAS saved and read back fine, but held ZERO urls on
 * multipart spam, fixed in analyze.js — a 0-link stash is valid,
 * fills the details box without a "Phishing URL:" line, and is
 * erased once that fill lands).
 *
 * v1.0.35: the banner is part of the product now. Header is just
 * "Spam Avenger"; the visible lines are plain user language at a
 * readable size — what got filled, a review-before-you-submit
 * reminder, and on the FTC wizard a standing reminder that the
 * Yes/No answers are the user's own. If a fill fails, the banner
 * shows the phishing link as copyable text so the user can paste
 * it in themselves. A × in the corner hides the banner for the
 * page (cosmetic only — the fill/watch logic keeps running). All
 * the old step-by-step diagnostics still go to the console.
 *
 * v1.0.34: on the FTC wizard the banner gains a "→ Guide:" line —
 * plain-language directions for whichever step is on screen (click
 * Report Now, pick "An impersonator", pick Email, think before the
 * payment question, keep clicking Continue until the narrative box
 * lands, then read + Submit). It only points: it still never
 * answers a personal question and never submits.
 *
 * v1.0.37: guide step ORDER fix. The step checks ran payment →
 * contact → category → homepage, and the ReportFraud HOMEPAGE has
 * impersonator-flavored links of its own, so the category check
 * fired while the user was still on the homepage — the guide said
 * "pick 'An impersonator'" before Report Now had ever been
 * clicked. Now the homepage state is detected first and the
 * wizard-step lines (and the impersonator tile auto-click) are
 * gated on the wizard actually having started: its "common
 * problems" category heading or a visible Continue button.
 *
 * v1.0.40: when a fill lands (FTC narrative, or a confirmed Safe
 * Browsing fill), the banner pulses its background dark → green
 * three times over ~1.5 s before settling — a fill can complete
 * while the user is scrolled elsewhere on the form, and a quietly
 * changed banner gets missed. Reduced-motion users get no pulse.
 *
 * v1.0.41: on the FTC pages the banner header reads "Spam
 * Avenger Guide" — that banner IS the trail guide for the
 * wizard walk, and the header should say so. Safe Browsing
 * keeps the plain "Spam Avenger" header: its banner only
 * reports a finished fill, it isn't guiding anything.
 *
 * v1.0.42: with "Guide" in the FTC header, the "→ Guide:"
 * prefix on every guide line was redundant — dropped; the
 * lines are plain sentences now. And the attention pulse is
 * no longer wired to the two fill moments alone: Diag.set()
 * fires attention() whenever the LEAD line actually changes
 * to a new non-empty value (a new wizard step, a fill
 * landing, a warning — whatever the user needs to look at
 * next), so every banner change gets noticed, not just
 * fills. The old explicit call sites are gone — one pulse
 * per genuine change, never two.
 *
 * v1.0.43: the FTC watch no longer ends at the fill. The
 * narrative text is kept in memory (the stash is still erased
 * on the first fill) and the observer keeps running — up to
 * ~15 minutes total — for the post-fill states: the user hits
 * Back and the guide says nothing is lost (refilling the
 * Comments box from memory if the wizard wiped it), the
 * review step points at Submit, and when the FTC's own
 * confirmation text shows ("thank you", a report number) the
 * banner delivers the payoff — "🎉 You did it!" — before the
 * watch stands down. It still never clicks anything past the
 * one pre-fill impersonator tile, and never submits.
 *
 * v1.0.44: the "Went back a step" state false-fired on plain
 * FORWARD walks — forward steps repeat earlier text (and
 * transition frames flash it), and v1.0.43 fired on any single
 * sighting. The post-fill pass now ranks what it sees
 * (homepage 0, category 1, question steps 2, comments 3,
 * review 4, confirmation 5), remembers the highest rank
 * reached since the fill, and calls it "back" only when the
 * current rank sits BELOW that high-water mark on 2
 * consecutive passes. Same rank or higher is never "back",
 * no matter what text is on screen.
 *
 * v1.0.45: v1.0.44 still false-fired when a SECOND walk ran
 * in the same tab — the wizard is a single-page app, so the
 * new walk ran under the old walk's post-fill state and its
 * early steps all read as "backward." Session semantics
 * now: a post-fill pass that lands on the homepage (rank 0)
 * or the category step (rank 1) is a NEW report session —
 * Back moves one step at a time, so reaching 0/1 from the
 * comments step means starting over, and a restart gets the
 * fresh guide, instantly: the watch drops back to pre-fill
 * mode and the coming fill uses the in-memory narrative.
 * The "back" state is also re-keyed on the DOM instead of
 * text ranks: the wizard's "Report details" step is one
 * scrolling page where the questions and the Comments
 * textarea coexist, so a churn pass that drops the textarea
 * from the visible scan made FORWARD clicks read as a step
 * back. Now "back" needs question signals on screen AND no
 * <textarea> anywhere in the DOM (the composite page always
 * carries its node; a genuine standalone questions page has
 * none) AND the last stable state was comments or review,
 * held for 2 consecutive passes.
 *
 * v1.0.47: a second full live walk (submitted by hand, fill
 * never landed) exposed the flip side of the state machine:
 * the wizard's LATE pages failed the "wizard started" test.
 * The final step (contact details + a big Submit button, no
 * Continue) read as "not started" and got the Report Now
 * line, and the confirmation page — reached in pre-fill
 * guide mode, which had no submitted state at all — got it
 * too, so the "🎉 You did it!" payoff never fired. Now the
 * submitted state (the FTC's "Report submitted / Thank you
 * for helping / Report Number" words) is checked FIRST in
 * both modes and stands the watch down; the final step gets
 * its own line ("Last step — hit Submit when you're
 * ready."); and the homepage line needs positive evidence —
 * the hero or a Report Now control, with no wizard progress
 * track on screen — instead of being the default for
 * anything the wizardStarted test can't see. Unrecognized
 * pages fall through to the generic details line.
 *
 * The stash is erased as soon as a form is filled. Nothing is ever
 * transmitted by this script, and it NEVER clicks Submit: the user
 * reviews the filled form and sends the report themselves.
 */
(function () {
  "use strict";

  /* ---------------- banner ---------------- */

  // v1.0.35: a user-facing banner, not a debug readout. Three
  // visible lines under a plain "Spam Avenger" header: a bold lead
  // line (the FTC guide, or what just got filled), plus up to two
  // supporting lines (a reminder, or the failure fallback text).
  // Big, readable type: 16px body, 18px bold lead. The × hides it
  // for this page — cosmetic only; it never stops the fill/watch
  // logic. Internal step detail still goes to the console with an
  // [SpamAvenger] prefix via Diag.debug(). set() takes the slot
  // names "lead", "sub1", "sub2" only — anything else is ignored.
  var Diag = (function () {
    var state = { lead: "", sub1: "", sub2: "" };
    var el = null, headEl = null, leadEl = null, sub1El = null,
      sub2El = null;
    var dismissed = false;
    // v1.0.41: the header line is settable (Diag.setHeader) so
    // the FTC pages can title the banner "Spam Avenger Guide".
    // render() re-applies it, so a watchdog-recreated banner
    // keeps the right header.
    var headerText = "Spam Avenger";

    function log(line) {
      try { console.log("[SpamAvenger] " + line); } catch (e) {}
    }

    function render() {
      if (!el) return;
      if (headEl) headEl.textContent = headerText;
      var pairs = [[leadEl, state.lead], [sub1El, state.sub1],
        [sub2El, state.sub2]];
      for (var i = 0; i < pairs.length; i++) {
        if (!pairs[i][0]) continue;
        pairs[i][0].textContent = pairs[i][1] || "";
        pairs[i][0].style.display = pairs[i][1] ? "" : "none";
      }
    }

    // v1.0.40: when a fill lands, pulse the banner's background
    // dark → green so the change catches the eye — the FTC fill
    // can land while the user is scrolled down at the Comments
    // box, and a quietly changed banner is easy to miss. Three
    // full pulses over ~1.5 s, then it settles back to the normal
    // dark. The watchdog can't stomp this: ensure() on a live
    // banner only calls render() (text lines), never rewrites the
    // banner's own style; the background is toggled with the same
    // !important priority the base style is declared with. If the
    // host page drops the banner mid-pulse, the timer sees the
    // element leave the document and stops — a recreated banner
    // carries the base dark style, which is the settle state.
    // v1.0.42: the trigger moved into set() (see below) — any
    // genuine change of the lead line pulses, fills included.
    var PULSE_DARK = "rgba(17,17,17,0.94)";
    var PULSE_GREEN = "#1e8e3e"; // the panel's action green
    var pulseTimer = null;
    function attention() {
      if (dismissed || !el) return;
      try {
        if (window.matchMedia && window.matchMedia(
            "(prefers-reduced-motion: reduce)").matches) return;
      } catch (e) {}
      if (!document.documentElement ||
          !document.documentElement.contains(el)) return;
      if (pulseTimer) { clearInterval(pulseTimer); pulseTimer = null; }
      var steps = 0;
      el.style.setProperty("background", PULSE_GREEN, "important");
      pulseTimer = setInterval(function () {
        steps++;
        if (!el || dismissed || !document.documentElement ||
            !document.documentElement.contains(el)) {
          clearInterval(pulseTimer); pulseTimer = null;
          return;
        }
        el.style.setProperty("background",
          steps % 2 ? PULSE_DARK : PULSE_GREEN, "important");
        if (steps >= 5) { // 5 toggles = 3 full pulses, ends dark
          clearInterval(pulseTimer); pulseTimer = null;
          el.style.setProperty("background", PULSE_DARK, "important");
        }
      }, 250);
    }

    function ensure() {
      if (dismissed) return;
      if (el && document.documentElement &&
          document.documentElement.contains(el)) {
        render();
        return;
      }
      el = document.createElement("div");
      el.id = "spam-avenger-banner";
      el.setAttribute("style",
        "position:fixed !important;top:12px !important;" +
        "right:12px !important;z-index:2147483647 !important;" +
        "background:rgba(17,17,17,0.94) !important;" +
        "color:#fff !important;" +
        "font-family:-apple-system,'Segoe UI',Roboto,Arial," +
        "Helvetica,sans-serif !important;" +
        "font-size:16px !important;line-height:1.45 !important;" +
        "padding:14px 16px !important;border-radius:8px !important;" +
        "pointer-events:auto !important;max-width:420px !important;" +
        "white-space:pre-wrap !important;" +
        "overflow-wrap:break-word !important;" +
        "text-align:left !important;" +
        "box-shadow:0 4px 16px rgba(0,0,0,0.45) !important;");
      var close = document.createElement("button");
      close.type = "button";
      close.textContent = "\u00D7";
      close.setAttribute("aria-label", "Dismiss");
      close.setAttribute("style",
        "position:absolute !important;top:4px !important;" +
        "right:4px !important;width:32px !important;" +
        "height:32px !important;min-width:32px !important;" +
        "min-height:32px !important;padding:0 !important;" +
        "margin:0 !important;background:transparent !important;" +
        "border:none !important;color:#fff !important;" +
        "font-size:20px !important;line-height:32px !important;" +
        "text-align:center !important;cursor:pointer !important;" +
        "font-family:inherit !important;");
      close.addEventListener("click", function () {
        dismissed = true;
        if (el && el.parentNode) el.parentNode.removeChild(el);
        el = null;
      });
      var head = document.createElement("div");
      headEl = head;
      head.textContent = headerText;
      head.setAttribute("style",
        "font-size:18px !important;font-weight:bold !important;" +
        "margin:0 24px 6px 0 !important;");
      leadEl = document.createElement("div");
      leadEl.setAttribute("style",
        "font-size:18px !important;font-weight:bold !important;" +
        "margin:0 0 6px 0 !important;");
      sub1El = document.createElement("div");
      sub1El.setAttribute("style",
        "font-size:16px !important;margin:0 0 6px 0 !important;");
      sub2El = document.createElement("div");
      sub2El.setAttribute("style",
        "font-size:16px !important;margin:0 !important;" +
        "overflow-wrap:anywhere !important;");
      el.appendChild(close);
      el.appendChild(head);
      el.appendChild(leadEl);
      el.appendChild(sub1El);
      el.appendChild(sub2El);
      (document.documentElement || document.body).appendChild(el);
      render();
    }

    return {
      init: function () {
        ensure();
        log("Spam Avenger banner ready");
        log("page: " + String(location.href).slice(0, 80));
        // The host app may re-render and drop the banner; a slow
        // watchdog keeps it on screen for the page's lifetime
        // (unless the user dismissed it — then it stays gone).
        setInterval(ensure, 2000);
      },
      set: function (key, line) {
        var leadChanged = false;
        if (Object.prototype.hasOwnProperty.call(state, key)) {
          // v1.0.42: a genuine change of the lead line is the
          // moment the user should look at the banner — a new
          // wizard step, a landed fill, a warning. Same value,
          // or clearing the line, is not news: no pulse.
          if (key === "lead" && line && line !== state.lead) {
            leadChanged = true;
          }
          state[key] = line;
        }
        ensure(); // render() puts the new text in place first
        if (leadChanged) attention();
      },
      setHeader: function (text) {
        headerText = text || "Spam Avenger";
        ensure(); // render() inside applies it to a live banner
      },
      debug: function (line) { log(line); },
      attention: attention
    };
  })();

  Diag.init();

  if (typeof chrome === "undefined" || !chrome.storage ||
      !chrome.storage.local) {
    Diag.debug("stash: READ ERROR: chrome.storage API unavailable " +
      "on this page");
    Diag.set("lead", "\u26A0 I couldn't reach your saved report " +
      "data in this browser.");
    return;
  }

  var MAX_AGE_MS = 30 * 60 * 1000; // ignore stashes older than 30 min

  chrome.storage.local.get("pendingReport", function (res) {
    if (chrome.runtime && chrome.runtime.lastError) {
      Diag.debug("stash: READ ERROR: " +
        (chrome.runtime.lastError.message || "unknown error"));
      Diag.set("lead", "\u26A0 I couldn't read your saved report " +
        "data.");
      return;
    }
    var stash = res && res.pendingReport;
    if (!stash) {
      Diag.debug("stash: none in storage");
      Diag.set("lead", "Open a phishing email in Gmail and click " +
        "one of the report buttons — I'll fill this form in for " +
        "you.");
      return;
    }
    var ageS = stash.savedAt
      ? Math.max(0, Math.round((Date.now() - stash.savedAt) / 1000))
      : -1;
    if (!stash.savedAt || Date.now() - stash.savedAt > MAX_AGE_MS) {
      Diag.debug("stash: STALE (age " +
        (ageS < 0 ? "?" : ageS) + "s)");
      Diag.set("lead", "That saved report was too old to use. Go " +
        "back to the email in Gmail and click the report button " +
        "again.");
      clearStash();
      return;
    }
    // v1.0.32: a stash with ZERO links is valid, not "none found".
    // Older builds stored urls: [] whenever analyze() couldn't see
    // into the message's MIME parts, and this gate then reported
    // "none found" even though the panel had truthfully said "Case
    // data saved ✓". A 0-link stash still fills the details box
    // (sender, subject, sending IP) — only the URL fill is skipped.
    var nUrls = (stash.urls || []).length;
    if (nUrls) {
      Diag.debug("stash: OK — " + nUrls + " urls, age " + ageS + "s");
    } else {
      Diag.debug("stash: found but 0 links — details only");
    }
    if (location.hostname === "safebrowsing.google.com") {
      fillSafeBrowsing(stash);
    } else if (location.hostname === "reportfraud.ftc.gov") {
      // v1.0.41: on the FTC pages the banner is the trail
      // guide, so its header says "Spam Avenger Guide". Set
      // here, before fillFtc runs, so the banner never shows
      // the plain header on this site.
      Diag.setHeader("Spam Avenger Guide");
      fillFtc(stash);
    }
  });

  function clearStash() {
    try { chrome.storage.local.remove("pendingReport"); } catch (e) {}
  }

  // Short factual summary for the details/narrative boxes. Extra URLs
  // are dropped first so the text fits maxLen without sawing the
  // primary URL or a sentence in half.
  function detailsText(stash, maxLen) {
    function build(extraUrls) {
      var hasUrls = !!(stash.urls && stash.urls.length);
      var L = [];
      L.push(hasUrls
        ? "I received a phishing/spam email containing a link to a " +
          "phishing page."
        : "I received a phishing/spam email.");
      // v1.0.32: omit the URL line entirely on a 0-link stash —
      // never print "Phishing URL: undefined".
      if (hasUrls) L.push("Phishing URL: " + stash.urls[0]);
      if (extraUrls.length) {
        L.push("Other links in the message:");
        extraUrls.forEach(function (u) { L.push("- " + u); });
      }
      if (stash.from) L.push("Claimed sender: " + stash.from);
      if (stash.subject) L.push("Subject: " + stash.subject);
      if (stash.ip) {
        L.push("Sending IP: " + stash.ip +
          (stash.server ? " (server: " + stash.server + ")" : ""));
      }
      return L.join("\n");
    }
    var extras = (stash.urls || []).slice(1, 6);
    var text = build(extras);
    while (text.length > maxLen && extras.length) {
      extras.pop();
      text = build(extras);
    }
    if (text.length > maxLen) text = text.slice(0, maxLen);
    return text;
  }

  // Set a field's value the way the page's framework expects: native
  // prototype setter (so React/Angular value trackers notice) plus
  // input/change events.
  function setNativeValue(el, value) {
    var proto = null;
    if (el.tagName === "TEXTAREA") proto = HTMLTextAreaElement.prototype;
    else if (el.tagName === "SELECT") proto = HTMLSelectElement.prototype;
    else proto = HTMLInputElement.prototype;
    var desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function isVisible(el) {
    if (!el || !el.getBoundingClientRect) return false;
    var r = el.getBoundingClientRect();
    if (!r.width || !r.height) return false;
    var s = window.getComputedStyle(el);
    return s.display !== "none" && s.visibility !== "hidden";
  }

  // Best-effort label for a form control: aria-label, aria-labelledby,
  // an associated <label>, or a label-ish element in a nearby wrapper
  // (Material-style form fields group label + control in one box).
  function controlLabel(el) {
    var t = el.getAttribute && (el.getAttribute("aria-label") || "");
    if (t) return t;
    var lb = el.getAttribute && el.getAttribute("aria-labelledby");
    if (lb) {
      var ref = document.getElementById(lb.split(/\s+/)[0]);
      if (ref) return ref.textContent || "";
    }
    if (el.id) {
      var lab = document.querySelector('label[for="' + el.id + '"]');
      if (lab) return lab.textContent || "";
    }
    var wrap = el.closest && el.closest("label");
    if (wrap) return wrap.textContent || "";
    var node = el;
    for (var i = 0; i < 5 && node && node.parentElement; i++) {
      node = node.parentElement;
      var cand = node.querySelector(
        "label, [class*='label'], [class*='Label']");
      if (cand && cand !== el && !cand.contains(el)) {
        var tx = (cand.textContent || "").trim();
        if (tx && tx.length < 60) return tx;
      }
    }
    return el.getAttribute && (el.getAttribute("placeholder") || "") || "";
  }

  // First visible control of the given tag names whose label matches.
  function findField(tags, labelRe) {
    var els = document.querySelectorAll(tags);
    for (var i = 0; i < els.length; i++) {
      if (isVisible(els[i]) && labelRe.test(controlLabel(els[i]))) {
        return els[i];
      }
    }
    return null;
  }

  // Pick an option in a native <select> or a Material-style custom
  // dropdown: native value-set first, else click the control open and
  // click the option whose visible text matches. Never touches any
  // submit control.
  function trySelectOption(labelRe, optionRe, done) {
    var finished = false;
    function finish(ok) {
      if (!finished) { finished = true; if (done) done(ok); }
    }
    var control = findField(
      "select, [role='combobox'], [role='listbox']", labelRe);
    if (!control) { finish(false); return; }
    if (control.tagName === "SELECT") {
      for (var i = 0; i < control.options.length; i++) {
        if (optionRe.test(control.options[i].textContent || "")) {
          setNativeValue(control, control.options[i].value);
          finish(true);
          return;
        }
      }
      finish(false);
      return;
    }
    // Custom dropdown: open it, then hunt the option list.
    try { control.click(); } catch (e) { finish(false); return; }
    var tries = 0;
    var timer = setInterval(function () {
      tries++;
      var opts = document.querySelectorAll(
        "[role='option'], [role='listbox'] *, mat-option, " +
        "[class*='option'], [class*='Option']");
      for (var j = 0; j < opts.length; j++) {
        var tx = (opts[j].textContent || "").trim();
        if (tx && tx.length < 80 && optionRe.test(tx) &&
            isVisible(opts[j])) {
          try { opts[j].click(); } catch (e) {}
          clearInterval(timer);
          finish(true);
          return;
        }
      }
      if (tries >= 10) { clearInterval(timer); finish(false); }
    }, 200);
  }

  /* ---------------- Google Safe Browsing ---------------- */

  // Text of the label inside an Angular Material form-field container
  // (mat-form-field): a <mat-label>, a real <label> (MDC renders the
  // floating label as one), or another label-ish element in the box.
  function containerLabelText(container) {
    var lab = container.querySelector(
      "mat-label, label, [class*='floating-label'], " +
      "[class*='label'], [class*='Label']");
    return lab ? (lab.textContent || "") : "";
  }

  // First control of the given tag inside a form-field container
  // whose label matches labelRe.
  function findInFormField(tag, labelRe) {
    var boxes = document.querySelectorAll(
      "mat-form-field, [class*='form-field'], [class*='formField']");
    for (var i = 0; i < boxes.length; i++) {
      if (!isVisible(boxes[i])) continue;
      if (!labelRe.test(containerLabelText(boxes[i]))) continue;
      var ctl = boxes[i].querySelector(tag);
      if (ctl && isVisible(ctl)) return ctl;
    }
    return null;
  }

  // Which strategy found the URL field on the latest hunt — read by
  // fillSafeBrowsing purely for the diagnostic banner.
  var urlFieldStrategy = "";

  // The "URL to report" input. v1.0.29 looked it up by the input's
  // own label and missed: on this Angular Material page the label
  // lives in the surrounding mat-form-field, not on the input. Try
  // strategies in order until one matches.
  function findUrlField() {
    // (a) input inside the form field labelled "URL to report"
    var f = findInFormField("input", /url to report/i);
    if (f) { urlFieldStrategy = "a"; return f; }
    var inputs = document.querySelectorAll("input");
    var i, el;
    // (b) an input whose own aria-label mentions URL
    for (i = 0; i < inputs.length; i++) {
      el = inputs[i];
      var al = el.getAttribute("aria-label") || "";
      if (al && /url/i.test(al) && isVisible(el) &&
          !el.disabled && !el.readOnly) {
        urlFieldStrategy = "b";
        return el;
      }
    }
    // (c) first visible empty text input that is not part of a
    // select/dropdown widget (Threat Type/Category are mat-selects)
    for (i = 0; i < inputs.length; i++) {
      el = inputs[i];
      var type = (el.getAttribute("type") || "text").toLowerCase();
      if (type !== "text" && type !== "url" && type !== "search") {
        continue;
      }
      if (!isVisible(el) || el.value || el.disabled || el.readOnly) {
        continue;
      }
      if (el.getAttribute("role") === "combobox") continue;
      if (el.closest && el.closest(
          "mat-select, select, [role='combobox'], [role='listbox']")) {
        continue;
      }
      urlFieldStrategy = "c";
      return el;
    }
    return null;
  }

  // Set a value, then re-read it 300 ms later: Angular change
  // detection can wipe a programmatic value it doesn't believe in,
  // so confirm the value stuck and retry — up to 3 attempts total —
  // before reporting done(ok).
  function setVerified(el, value, done) {
    var attempts = 0;
    (function attempt() {
      attempts++;
      try { el.focus(); } catch (e) {}
      setNativeValue(el, value);
      setTimeout(function () {
        if (el.value === value) { done(true); return; }
        if (attempts >= 3) { done(false); return; }
        attempt();
      }, 300);
    })();
  }

  function fillSafeBrowsing(stash) {
    // Shared tail of both paths below: fill the details box, then
    // try the threat dropdowns. eraseMode "always" erases the stash
    // when the tail runs (the URL fill already landed — that was the
    // 1.0.31 behavior); "onDetails" erases only once the details
    // text is confirmed in the box (the 0-link path, where the
    // details fill is all there is).
    function detailsThenSelects(eraseMode) {
      var details = findInFormField("textarea",
          /additional details/i) ||
        findField("textarea", /additional details/i);
      if (!details) { // fallback: the form's visible textarea
        var tas = document.querySelectorAll("textarea");
        for (var k = 0; k < tas.length; k++) {
          if (isVisible(tas[k])) { details = tas[k]; break; }
        }
      }
      // v1.0.35: the user-facing outcome line, once the details
      // step settles. detailsFound = the box is there and holds
      // text (ours, or text that was already in it).
      function finishBanner(detailsFound) {
        if (eraseMode === "onDetails") {
          // 0-link path: the details text was the whole payload.
          if (detailsFound) {
            Diag.set("lead", "\u2713 Filled in: the details from " +
              "your email.");
            Diag.set("sub1", "This email had no link in it, so " +
              "the URL box is still empty — add one yourself or " +
              "close this form.");
          } else {
            Diag.set("lead", "\u26A0 I couldn't fill this form in.");
            Diag.set("sub1", "Go back to the email in Gmail — " +
              "the panel there has the details if you want to " +
              "paste them in.");
          }
        } else if (detailsFound) {
          Diag.set("lead", "\u2713 Filled in: the phishing link " +
            "and the details from your email.");
          Diag.set("sub1", "Give it a quick review, then click " +
            "Submit when you're ready — I never submit for you.");
        } else {
          Diag.set("lead", "\u2713 Filled in: the phishing link " +
            "from your email.");
          Diag.set("sub1", "Give it a quick review, then click " +
            "Submit when you're ready — I never submit for you.");
        }
        Diag.set("sub2", "");
        // v1.0.42: no explicit flash call here anymore — the
        // lead change above pulses the banner centrally in
        // Diag.set(). (v1.0.40 wired attention() to this spot;
        // the lead line changes on every outcome branch, the
        // warning included, which is what Michael wants.)
      }
      function selects(erase) {
        // Threat Type (and Category, if offered): phishing /
        // social engineering is the honest bucket for these pages.
        trySelectOption(/threat type/i, /phishing|social engineering/i,
          function () {
            trySelectOption(/threat category/i,
              /phishing|social engineering/i, null);
          });
        if (erase) clearStash();
      }
      if (details && !details.value) {
        Diag.debug("details: found — filling…");
        setVerified(details, detailsText(stash, 800),
          function (dok) {
            Diag.debug(dok
              ? "details: set+verified"
              : "details: set but WIPED (after retries)");
            selects(eraseMode === "always" || dok);
            finishBanner(dok);
          });
      } else if (details) {
        Diag.debug("details: already had text — left alone");
        selects(eraseMode === "always");
        finishBanner(true);
      } else {
        Diag.debug("details: NOT FOUND");
        selects(eraseMode === "always");
        finishBanner(false);
      }
    }

    // v1.0.32: 0-link stash — there is no URL to hunt or fill. Say
    // so on the banner, wait for the form's details box to render,
    // and fill that instead (it still carries sender/subject/IP).
    if (!stash.urls || !stash.urls.length) {
      Diag.debug("url field: no link in case data — details only");
      Diag.set("lead", "Filling in the details from your email…");
      var zeroDeadline = Date.now() + 30000;
      var zeroTimer = setInterval(function () {
        var tas = document.querySelectorAll("textarea");
        var rendered = false;
        for (var k = 0; k < tas.length; k++) {
          if (isVisible(tas[k])) { rendered = true; break; }
        }
        if (rendered) {
          clearInterval(zeroTimer);
          detailsThenSelects("onDetails");
        } else if (Date.now() > zeroDeadline) {
          clearInterval(zeroTimer);
          Diag.debug("details: NOT FOUND after 30s");
          Diag.set("lead", "\u26A0 I couldn't fill this form in.");
          Diag.set("sub1", "The form didn't finish loading — try " +
            "refreshing this page.");
        }
      }, 450);
      return;
    }

    // v1.0.35: on failure the banner hands the user the link as
    // copyable text, so a form the filler can't drive is still a
    // 30-second manual job instead of a dead end.
    function fillFailed() {
      Diag.set("lead", "\u26A0 I couldn't fill this form in. " +
        "The link from your email is:");
      Diag.set("sub1", stash.urls[0]);
      Diag.set("sub2", "You can copy it into the box yourself.");
    }

    Diag.debug("url field: searching…");
    Diag.set("lead", "Filling in the report form from your email…");
    var deadline = Date.now() + 30000; // poll up to ~30s for the form
    var timer = setInterval(function () {
      var urlField = findUrlField();
      if (!urlField) {
        if (Date.now() > deadline) {
          clearInterval(timer);
          Diag.debug("url field: NOT FOUND after 30s");
          fillFailed();
        }
        return;
      }
      clearInterval(timer);
      Diag.debug("url field: found via strategy " + urlFieldStrategy);
      Diag.debug("url fill: setting…");
      setVerified(urlField, stash.urls[0], function (ok) {
        if (!ok) {
          Diag.debug("url fill: set but WIPED (after retries)");
          fillFailed();
          return; // no confirmed fill — leave stash to expire
        }
        Diag.debug("url fill: set+verified");
        detailsThenSelects("always");
      });
    }, 450);
  }

  /* ---------------- FTC ReportFraud wizard ---------------- */

  function fillFtc(stash) {
    Diag.debug("FTC wizard: watching for narrative box…");
    // v1.0.35: a standing reminder under the guide line, on every
    // step until the details land — the Yes/No answers are the
    // user's own statement, and the payment one is the easiest to
    // get wrong by clicking through fast.
    var REMINDER = "Reminder: the Yes/No answers are yours \u2014 " +
      "double-check them before you submit, especially the one " +
      "about sending payment.";
    Diag.set("sub1", REMINDER);
    var filled = false;
    var watchDone = false;
    var categoryTried = false;
    var startedAt = Date.now();
    var deadline = startedAt + 10 * 60 * 1000; // pre-fill hunt cap
    // v1.0.43: the watch used to END at the fill. It doesn't
    // anymore — the guide stays with the user through Back
    // presses, the review step, and the submission itself.
    // The whole watch (pre-fill hunt + post-fill states) caps
    // at ~15 minutes from here, then stops quietly.
    var watchEnd = startedAt + 15 * 60 * 1000;
    // v1.0.43: the narrative text, kept in memory at fill
    // time. The stash is still erased on that first fill (as
    // always) — this copy exists because the wizard can wipe
    // the Comments box when the user backs up and returns,
    // and the refill has to come from somewhere.
    var savedNarrative = null;

    /* v1.0.34: the banner becomes a trail guide. The wizard asks a
     * dozen questions only the user can answer; the guide line just
     * points at the right next step for whichever screen is up, so
     * nobody has to guess. It never answers a question itself. */
    // v1.0.42: no "→ Guide:" prefix anymore — the banner
    // header already says "Spam Avenger Guide" (v1.0.41), so
    // each line is just the plain instruction, capitalized.
    var G_HOME = "Click the big Report Now button to start " +
      "your report.";
    var G_CAT = "Pick 'An impersonator' \u2014 I already " +
      "selected it if I could.";
    var G_START = "This came by email \u2014 pick Email.";
    var G_PAY = "If you didn't pay them anything, pick No. " +
      "(Only you can answer this one.)";
    var G_DETAILS = "Keep clicking Continue \u2014 I'll drop " +
      "your case details into the big box when it shows up.";
    // v1.0.43: the review step gets its own line, pre- and
    // post-fill — it's the last thing the user sees before
    // the report goes out.
    var G_REVIEW = "Last step \u2014 give it a once-over, " +
      "then hit Submit.";
    // v1.0.47: the wizard's final step — contact details and
    // the big Submit button, no Continue — gets its own line
    // (it used to fall into the homepage branch; see
    // updateGuide).
    var G_SUBMIT = "Last step \u2014 hit Submit when " +
      "you're ready.";
    var guideLine = "";
    function setGuide(line) {
      if (line === guideLine) return;
      guideLine = line;
      Diag.set("lead", line);
    }
    // v1.0.35: once the narrative lands, the guide + reminder are
    // replaced by a confirmation and one last check-your-answers
    // note (this supersedes v1.0.34's G_DONE guide line).
    // v1.0.43: those three lines are now the "filled" post-fill
    // state, applied through showPostState() — at the fill, and
    // again whenever the user is back on the comments step with
    // the text in place.
    var FILLED_LEAD = "\u2713 I filled in the Comments box below " +
      "for you \u2014 the phishing link plus the sender details " +
      "from the email.";
    var FILLED_SUB1 = "That's the evidence the FTC needs, dug " +
      "out of the email so you don't have to hunt for it.";
    var FILLED_SUB2 = "Before you submit: make sure the Yes/No " +
      "answers are right \u2014 they're your words to the FTC.";
    function fillDone() {
      showPostState("filled", FILLED_LEAD, FILLED_SUB1, FILLED_SUB2);
      // v1.0.42: the lead change above pulses the banner via
      // Diag.set() — the fill may have landed while the user
      // was scrolled down at the Comments box, and the pulse
      // is what gets the change noticed.
    }
    // v1.0.47: the payoff, shared by both watch modes. The
    // submitted state used to exist only in the post-fill
    // pass — a walk whose fill never landed reached the
    // FTC's confirmation page in pre-fill guide mode, which
    // had no celebration to give. The watch stands down
    // here; the banner watchdog keeps the banner rendered.
    // (CONGRATS_* are defined with the post-fill texts
    // further down; they're assigned when fillFtc starts,
    // before the watch's first pass.)
    function celebrate() {
      guideLine = CONGRATS_LEAD;
      Diag.set("lead", CONGRATS_LEAD);
      Diag.set("sub1", CONGRATS_SUB1);
      Diag.set("sub2", "");
      Diag.debug("FTC wizard: submission confirmed \u2014 " +
        "watch standing down");
      stopAll();
    }

    // v1.0.43: post-fill banner states, deduped by key. The
    // throttled observer re-evaluates the page constantly; only
    // a genuine state transition should re-set the banner (and
    // pulse it, via the lead change in Diag.set()).
    var postState = "";
    // v1.0.45: lastStableState is the most recent STABLE
    // post-fill state — "filled" (the comments step) or
    // "review" — recorded centrally in showPostState below,
    // before its dedupe check, so it tracks where the user
    // genuinely was even when the banner didn't need to
    // change. The "back" state may only engage out of one of
    // those two states (see postFillPass). Cleared on a
    // session reset.
    var lastStableState = "";
    // backStreak counts consecutive post-fill passes meeting
    // ALL the "back" conditions in postFillPass: the banner
    // only switches once they hold twice in a row, so a
    // single transition frame can't trip it.
    var backStreak = 0;
    function showPostState(key, lead, sub1, sub2) {
      if (key === "filled" || key === "review") {
        lastStableState = key;
      }
      if (postState === key) return;
      postState = key;
      guideLine = "";
      Diag.set("lead", lead);
      Diag.set("sub1", sub1);
      Diag.set("sub2", sub2);
    }
    // Visible text of the page's headings and labels — that's where
    // the wizard puts its questions. (The banner itself is none of
    // these tags, so the guide can't trip over its own words.)
    function guideScanText() {
      var parts = [];
      var els = document.querySelectorAll(
        "h1, h2, h3, h4, legend, label");
      for (var i = 0; i < els.length; i++) {
        if (!isVisible(els[i])) continue;
        var t = (els[i].textContent || "").replace(/\s+/g, " ").trim();
        if (t) parts.push(t);
      }
      return parts.join("\n");
    }
    function anyVisibleText(re, tags) {
      var els = document.querySelectorAll(tags);
      for (var i = 0; i < els.length; i++) {
        if (isVisible(els[i]) &&
            re.test((els[i].textContent || "").trim())) return true;
      }
      return false;
    }
    // Has the wizard actually started? Its telltales: the
    // "common problems" category heading, or a visible Continue
    // button (every wizard step carries one). Until one of those
    // is on screen the user is still on the ReportFraud homepage
    // (or an in-between frame of it loading), no matter what else
    // the page contains.
    function wizardStarted(t) {
      return /common problems/i.test(t) ||
        anyVisibleText(/continue/i, "button, a, [role='button']");
    }
    // v1.0.43: visible paragraph text, in addition to the
    // heading/label scan — the FTC's confirmation screen puts
    // its thank-you and report-number lines in body paragraphs,
    // not just headings.
    function paragraphText() {
      var parts = [];
      var els = document.querySelectorAll("p");
      for (var i = 0; i < els.length; i++) {
        if (!isVisible(els[i])) continue;
        var t = (els[i].textContent || "").replace(/\s+/g, " ").trim();
        if (t) parts.push(t);
      }
      return parts.join("\n");
    }
    // The FTC's own words once a report has gone through.
    var CONFIRM_RE = /thank you|has been submitted|report (number|#)|we received your report|submission (received|complete)/i;
    // v1.0.47: the submitted state in the FTC's exact
    // confirmation-page words ("Report submitted! Thank you
    // for helping…", the "Report Number" box) — the check
    // BOTH watch modes share. CONFIRM_RE above remains the
    // post-fill pass's broader net, OR'd in alongside.
    var SUBMITTED_RE = /report submitted|thank you for helping|report number/i;
    function isSubmitted(t, p) {
      return SUBMITTED_RE.test(t) || SUBMITTED_RE.test(p);
    }
    // The earlier-step screens, recognized by their text — the
    // same signals the guide keys on — split by step rank for
    // the v1.0.44 post-fill gating: the category step is rank 1,
    // the question steps (how it started, payment) are rank 2.
    var CATEGORY_RE = /common problems/i;
    var QUESTION_RE = /did you send|did you pay|payment of any kind|how much money|how did it start|how did they contact|how were you contacted/i;
    function hasSubmitControl() {
      return anyVisibleText(/submit/i, "button, a, [role='button']");
    }
    // v1.0.47: the wizard's final step — a control whose text
    // STARTS with "Submit" (the contact page's big "Submit →";
    // anchored so progress labels and stray links don't
    // count) with actual form fields on screen alongside it.
    function submitStepUp() {
      if (!anyVisibleText(/^\s*submit\b/i,
          "button, a, [role='button']")) return false;
      var fields = document.querySelectorAll(
        "input, select, textarea");
      for (var i = 0; i < fields.length; i++) {
        if (isVisible(fields[i])) return true;
      }
      return false;
    }
    // v1.0.47: the wizard's progress track (Start … Submit /
    // Submitted) — positive proof the user is INSIDE the
    // wizard. Looked for on progress-flavored elements and
    // their near ancestors, whose combined text carries both
    // end labels; kept narrow so the scan stays cheap.
    function progressUp() {
      var els = document.querySelectorAll(
        "[role='progressbar'], [class*='progress'], " +
        "[class*='step']");
      for (var i = 0; i < els.length; i++) {
        var node = els[i];
        for (var up = 0; up < 3 && node; up++) {
          var tx = (node.textContent || "")
            .replace(/\s+/g, " ").trim();
          if (tx.length <= 80 && /\bstart\b/i.test(tx) &&
              /\bsubmit/i.test(tx)) return true;
          node = node.parentElement;
        }
      }
      return false;
    }

    function updateGuide() {
      var t = guideScanText();
      // v1.0.47 priority: confirmation → review → submit
      // step → payment → how-it-started → category →
      // homepage → fallback. Two structural breaks with the
      // v1.0.37 homepage-first order:
      //
      // (1) The submitted state is checked FIRST, here in
      // pre-fill mode too — it used to live only in the
      // post-fill pass, so a hand-walked submission (fill
      // never landed) reached the confirmation page with no
      // celebration to give.
      //
      // (2) The homepage line is no longer the fate of
      // anything wizardStarted() can't see. That test is
      // false on the wizard's own late pages — the final
      // step has a Submit button and no Continue — and the
      // old order sent those pages to "Click the big Report
      // Now button." Now Report Now needs POSITIVE
      // evidence: the homepage hero or a Report Now control
      // on screen, AND no wizard progress track up. A page
      // that merely lacks Continue/category signals falls
      // through to the generic details line. The step lines
      // no longer gate on wizardStarted either — except
      // the category line's impersonator-TILE fallback,
      // which still does: the homepage carries
      // impersonator-flavored links of its own (the
      // v1.0.37 trap), and those must never read as the
      // category step. The category HEADING test needs no
      // gate: "common problems" only heads the wizard's
      // first step.
      if (isSubmitted(t, paragraphText())) {
        celebrate();
        return;
      }
      if (/review/i.test(t) && hasSubmitControl()) {
        // The review step — the last screen before the
        // report goes out. Checked before the question
        // lines: a review page repeats the earlier questions
        // and answers, and could trip them.
        setGuide(G_REVIEW);
      } else if (submitStepUp()) {
        // v1.0.47: the final step gets its own line.
        setGuide(G_SUBMIT);
      } else if (/did you send|did you pay|payment of any kind|how much money/i
          .test(t)) {
        setGuide(G_PAY);
      } else if (/how did it start|how did they contact|how were you contacted/i
          .test(t)) {
        setGuide(G_START);
      } else if (/common problems/i.test(t) ||
          (wizardStarted(t) && anyVisibleText(/impersonat/i,
            "button, a, label, [role='radio'], [role='option']"))) {
        setGuide(G_CAT);
      } else if ((/report to help fight fraud/i.test(t) ||
          anyVisibleText(/report now/i,
            "button, a, [role='button']")) && !progressUp()) {
        setGuide(G_HOME);
      } else {
        setGuide(G_DETAILS);
      }
    }

    // v1.0.43: the post-fill pass — runs on the same observer
    // after the narrative has landed. Priority: the FTC's
    // confirmation screen first (the payoff), then the comments
    // step (refilling from memory if the wizard wiped the box),
    // then the review step, then an earlier step or the
    // homepage (Back was pressed). Anything else leaves the
    // banner exactly as it stands.
    // v1.0.44: the "back" state is rank-gated (see the header
    // note): each pass ranks what it sees, and "back" requires
    // the current rank to sit below the highest rank reached
    // since the fill, on 2 consecutive passes. Forward motion
    // and flicker can no longer trip it.
    // v1.0.45: between the review branch and the "back" check
    // sits the session reset — rank 0 or 1 in post-fill mode
    // means a new report session, handled instantly (see the
    // header note) — and the "back" check itself is keyed on
    // the DOM (textarea existence), not on text ranks.
    var BACK_LEAD = "Went back a step? No problem \u2014 " +
      "nothing's lost.";
    var BACK_SUB1 = "Your answers and your filled details " +
      "stay put. Just click Continue forward when you're ready.";
    var CONGRATS_LEAD = "\uD83C\uDF89 You did it!";
    var CONGRATS_SUB1 = "You just made the internet a better " +
      "place \u2014 every report helps protect the next person " +
      "who gets that email.";
    function postFillPass() {
      var t = guideScanText();
      // Rank this pass, checking signals in the same priority
      // order as the states below. rank stays null on screens
      // we don't recognize (transition frames, unknown steps):
      // they never touch the banner and they break the
      // backward streak — the condition must HOLD, unbroken,
      // for 2 passes.
      // v1.0.47: the shared submitted check (isSubmitted)
      // OR'd with this pass's broader CONFIRM_RE net.
      var pText = paragraphText();
      var confirm = isSubmitted(t, pText) ||
        CONFIRM_RE.test(t) || CONFIRM_RE.test(pText);
      var box = null;
      var areas = document.querySelectorAll("textarea");
      for (var j = 0; j < areas.length; j++) {
        if (isVisible(areas[j])) { box = areas[j]; break; }
      }
      var reviewUp = /review/i.test(t) && hasSubmitControl();
      var continueUp = anyVisibleText(/continue/i,
        "button, a, [role='button']");
      var rank = null;
      if (confirm) rank = 5;
      else if (box) rank = 3;
      else if (reviewUp) rank = 4;
      else if (CATEGORY_RE.test(t)) rank = 1;
      else if (QUESTION_RE.test(t)) rank = 2;
      else if (!wizardStarted(t) ||
          (!continueUp && /report to help fight fraud/i.test(t))) {
        rank = 0;
      }
      if (confirm) {
        showPostState("done", CONGRATS_LEAD, CONGRATS_SUB1, "");
        Diag.debug("FTC wizard: submission confirmed \u2014 " +
          "watch standing down");
        stopAll();
        return;
      }
      if (box) {
        if (!box.value && savedNarrative) {
          // The wizard wiped the box while the user was off on
          // an earlier step — put the narrative back from the
          // in-memory copy. Only an EMPTY box is refilled:
          // text the user typed or edited is never overwritten.
          setNativeValue(box, savedNarrative);
          Diag.debug("details: refilled from memory after Back");
        }
        backStreak = 0;
        fillDone();
        return;
      }
      if (reviewUp) {
        backStreak = 0;
        showPostState("review", G_REVIEW,
          "Your details are in the Comments section of this " +
          "report.", "");
        return;
      }
      // v1.0.45: session restart. The wizard's Back moves one
      // step at a time, so from the comments step (rank 3+)
      // the user can only land on the homepage (0) or the
      // category step (1) by starting a NEW report — and a
      // fresh walk in the same tab must not inherit this
      // session's post-fill state, or every early step of the
      // new walk reads as "backward" (the v1.0.44 false-fire
      // on plain forward walks). No streak, no debate: drop
      // back to pre-fill guide/hunt mode on the spot. The
      // coming fill uses the in-memory savedNarrative (the
      // stash is long cleared), categoryTried re-arms so the
      // new walk gets the same impersonator-tile help as any
      // fresh walk, and the hunt deadline refreshes — the
      // ~15-minute total watch cap still bounds everything.
      if (rank === 0 || rank === 1) {
        filled = false;
        backStreak = 0;
        lastStableState = "";
        postState = "";
        categoryTried = false;
        deadline = Date.now() + 10 * 60 * 1000;
        Diag.debug("FTC wizard: restart detected \u2014 back " +
          "to guide mode");
        Diag.set("sub1", REMINDER);
        Diag.set("sub2", "");
        updateGuide();
        return;
      }
      // v1.0.45: the "back" state, keyed on the DOM — not on
      // text ranks. The rank model (v1.0.44) can't tell this
      // wizard's steps apart: its "Report details" step is
      // ONE scrolling page where the question text and the
      // Comments textarea coexist, so any re-render pass that
      // drops the textarea out of the visible scan reads as
      // "questions right after comments" — a fake step back
      // while the user is clicking around going FORWARD.
      // The discriminator is the DOM: the composite details
      // page always carries its <textarea> node, while a
      // genuine standalone questions page has none anywhere.
      // "Back" engages only when ALL of these hold:
      //   (a) question-step signals are on screen;
      //   (b) NO <textarea> exists anywhere in the DOM
      //       (querySelector, regardless of visibility);
      //   (c) the last stable post-fill state was the comments
      //       step ("filled") or the review step ("review");
      //   (d) (a)-(c) hold for 2 consecutive passes.
      // A textarea that exists but fails the visible-comments
      // check above (churn on the composite page) changes
      // NOTHING: the banner stays exactly as it stands and
      // the streak resets. The rank 0/1 reset above is
      // evaluated before this block, so a restart is never
      // blocked by a lingering textarea node; refills still
      // happen only in the comments branch, only into a
      // visible, empty box.
      var anyTextarea = !!document.querySelector("textarea");
      if (anyTextarea || !QUESTION_RE.test(t) ||
          (lastStableState !== "filled" &&
           lastStableState !== "review")) {
        backStreak = 0;
        return;
      }
      backStreak++;
      if (backStreak >= 2) {
        showPostState("back", BACK_LEAD, BACK_SUB1, REMINDER);
      }
    }


    function attempt() {
      if (watchDone) return;
      if (filled) {
        // v1.0.43: post-fill — the watch stays alive (see
        // postFillPass) until the ~15-minute total cap, then
        // stands down quietly, banner untouched.
        if (Date.now() > watchEnd) {
          Diag.debug("FTC wizard: watch cap reached \u2014 " +
            "standing down");
          stopAll();
          return;
        }
        postFillPass();
        return;
      }
      if (Date.now() > deadline) {
        // v1.0.47: even at the buzzer, a submitted report
        // gets its celebration — the confirmation state
        // outranks the not-found warning too.
        if (isSubmitted(guideScanText(), paragraphText())) {
          celebrate();
          return;
        }
        Diag.debug("details: NOT FOUND (wizard watched 10 min)");
        Diag.set("sub1", "\u26A0 I couldn't spot the Comments box. " +
          "If you reach it, you can paste the case details from " +
          "the panel in Gmail.");
        stopAll();
        return;
      }
      updateGuide();
      if (watchDone) return; // updateGuide may have celebrated

      // Best effort, once: if the first-step category tiles are up
      // and one plainly says "impersonator", pick it — these phish
      // almost always pretend to be a real company or agency.
      // v1.0.37: only once the wizard's category step is actually
      // on screen (same wizardStarted gate as the guide) — the
      // homepage has impersonator-flavored links too, and clicking
      // one would yank the user somewhere they didn't ask to go.
      // categoryTried stays false until the gate passes, so the
      // click is retried on a later pass once the wizard renders.
      if (!categoryTried && wizardStarted(guideScanText())) {
        categoryTried = true;
        var tiles = document.querySelectorAll(
          "button, a, label, [role='radio'], [role='option']");
        for (var i = 0; i < tiles.length; i++) {
          var tx = (tiles[i].textContent || "").trim();
          if (tx && tx.length <= 40 && /impersonat/i.test(tx) &&
              isVisible(tiles[i])) {
            try { tiles[i].click(); } catch (e) {}
            break;
          }
        }
      }

      // The must-have: when the wizard reaches its narrative/details
      // step, fill the textarea with the case summary.
      var areas = document.querySelectorAll("textarea");
      for (var j = 0; j < areas.length; j++) {
        if (isVisible(areas[j]) && !areas[j].value) {
          // v1.0.43: keep the exact text in memory BEFORE the
          // stash is erased — the post-fill watch refills from
          // this copy if the wizard wipes the box later.
          // v1.0.45: after a session reset the stash is already
          // gone, so an existing in-memory copy IS the payload
          // (same case, same text) — only compute from the
          // stash when there is no copy yet.
          savedNarrative = savedNarrative ||
            detailsText(stash, 3000);
          setNativeValue(areas[j], savedNarrative);
          filled = true;
          // The fill lands on the comments step: fillDone()
          // (just below) applies the "filled" state, which
          // showPostState records as the stable state the
          // post-fill "back" rule keys on.
          Diag.debug("details: set (narrative filled)");
          fillDone();
          clearStash();
          // NOT stopAll() — v1.0.43 keeps the observer running
          // for the post-fill states (Back, review, submitted).
          return;
        }
      }
    }

    var lastRun = 0;
    var observer = new MutationObserver(function () {
      var now = Date.now();
      if (now - lastRun < 250) return; // wizard pages mutate a lot
      lastRun = now;
      attempt();
    });
    function stopAll() {
      watchDone = true;
      try { observer.disconnect(); } catch (e) {}
    }
    observer.observe(document.documentElement, {
      childList: true, subtree: true
    });
    attempt(); // the step might already be on screen
    setTimeout(stopAll, 15 * 60 * 1000); // the ~15-min total cap
  }
})();
