/* Spam Avenger for Gmail — data-deletion demand generator (v1.0.55).
 *
 * Drafts a formal personal-data deletion demand to the company that
 * sent an email, modeled on Michael's Mighty Networks letter of
 * 2026-10-16. The user's name / email / ZIP / state are asked once,
 * stored ONLY in chrome.storage.local, and used only to fill in
 * demands the user drafts. Nothing is transmitted by the extension;
 * the finished letter opens in the user's own Gmail compose, and the
 * USER reviews and sends it — never auto-sent, same rule as the
 * abuse complaints.
 *
 * Pure logic (letter builder, ZIP->state, registrable domain) is
 * dependency-free and Node-testable, like lib/analyze.js. The DOM
 * details-form builder runs only in a browser and is shared by the
 * toolbar popup and the results panel, so both write the same keys.
 */
(function () {
  "use strict";

  // --- storage keys (single source of truth for popup + panel) ---
  var DETAIL_KEYS = {
    name: "sa_user_name",
    email: "sa_user_email",
    zip: "sa_user_zip",
    state: "sa_user_state"
  };

  // --- ZIP3 -> state -------------------------------------------------
  // First three ZIP digits -> state/territory, as [lo, hi, code]
  // ranges (public USPS sectional-center data, condensed).
  // v1.0.53: the ZIP is the ONLY source of state (the form's state
  // picker is gone — Michael's live-test call). Gaps and oddballs
  // are fine: an unresolvable ZIP yields no state, and the letter
  // falls back to the general U.S. framing.
  var ZIP3_RANGES = [
    [5, 5, "NY"],       // 005xx: IRS processing center, NY
    [6, 7, "PR"], [8, 8, "VI"], [9, 9, "PR"],
    [10, 27, "MA"], [28, 29, "RI"], [30, 38, "NH"], [39, 49, "ME"],
    [50, 59, "VT"], [60, 69, "CT"], [70, 89, "NJ"], [90, 98, "AE"],
    [100, 149, "NY"], [150, 196, "PA"], [197, 199, "DE"],
    [200, 205, "DC"], [206, 219, "MD"], [220, 246, "VA"],
    [247, 268, "WV"], [270, 289, "NC"], [290, 299, "SC"],
    [300, 319, "GA"], [320, 339, "FL"], [340, 340, "AE"],
    [341, 349, "FL"], [350, 369, "AL"], [370, 385, "TN"],
    [386, 397, "MS"], [398, 399, "GA"], [400, 427, "KY"],
    [430, 459, "OH"], [460, 479, "IN"], [480, 499, "MI"],
    [500, 528, "IA"], [530, 549, "WI"], [550, 569, "MN"],
    [570, 577, "SD"], [580, 588, "ND"], [590, 599, "MT"],
    [600, 629, "IL"], [630, 658, "MO"], [660, 679, "KS"],
    [680, 693, "NE"], [700, 714, "LA"], [716, 729, "AR"],
    [730, 749, "OK"], [750, 799, "TX"], [800, 816, "CO"],
    [820, 831, "WY"], [832, 838, "ID"], [840, 847, "UT"],
    [850, 865, "AZ"], [870, 884, "NM"], [885, 885, "TX"],
    [889, 898, "NV"], [900, 961, "CA"], [962, 966, "AP"],
    [967, 968, "HI"], [969, 969, "GU"], [970, 979, "OR"],
    [980, 994, "WA"], [995, 999, "AK"]
  ];

  function stateForZip(zip) {
    // v1.0.53: strict shape — a clean 5-digit ZIP, or ZIP+4 (only
    // the first five digits count). Anything else is unresolvable
    // ON PURPOSE: a 4-digit string like "6017" is almost always a
    // leading-zero ZIP that lost its 0 (06017 = Connecticut), and
    // guessing Illinois (601xx) from it would put the wrong
    // state's law in a legal letter. Leading zeros survive because
    // the match runs on the string: "06017" -> CT, "01001" -> MA,
    // "00901" -> PR.
    var m = String(zip == null ? "" : zip).trim()
      .match(/^(\d{5})(?:-\d{4})?$/);
    if (!m) return null;
    var z3 = parseInt(m[1].slice(0, 3), 10);
    for (var i = 0; i < ZIP3_RANGES.length; i++) {
      if (z3 >= ZIP3_RANGES[i][0] && z3 <= ZIP3_RANGES[i][1]) {
        return ZIP3_RANGES[i][2];
      }
    }
    return null;
  }

  // [code, full name] for all 50 states + DC (the name table —
  // the v1.0.53 form has no picker; this list feeds STATE_NAMES).
  var US_STATES = [
    ["AL", "Alabama"], ["AK", "Alaska"], ["AZ", "Arizona"],
    ["AR", "Arkansas"], ["CA", "California"], ["CO", "Colorado"],
    ["CT", "Connecticut"], ["DE", "Delaware"], ["DC", "District of Columbia"],
    ["FL", "Florida"], ["GA", "Georgia"], ["HI", "Hawaii"],
    ["ID", "Idaho"], ["IL", "Illinois"], ["IN", "Indiana"],
    ["IA", "Iowa"], ["KS", "Kansas"], ["KY", "Kentucky"],
    ["LA", "Louisiana"], ["ME", "Maine"], ["MD", "Maryland"],
    ["MA", "Massachusetts"], ["MI", "Michigan"], ["MN", "Minnesota"],
    ["MS", "Mississippi"], ["MO", "Missouri"], ["MT", "Montana"],
    ["NE", "Nebraska"], ["NV", "Nevada"], ["NH", "New Hampshire"],
    ["NJ", "New Jersey"], ["NM", "New Mexico"], ["NY", "New York"],
    ["NC", "North Carolina"], ["ND", "North Dakota"], ["OH", "Ohio"],
    ["OK", "Oklahoma"], ["OR", "Oregon"], ["PA", "Pennsylvania"],
    ["RI", "Rhode Island"], ["SC", "South Carolina"], ["SD", "South Dakota"],
    ["TN", "Tennessee"], ["TX", "Texas"], ["UT", "Utah"],
    ["VT", "Vermont"], ["VA", "Virginia"], ["WA", "Washington"],
    ["WV", "West Virginia"], ["WI", "Wisconsin"], ["WY", "Wyoming"]
  ];

  var STATE_NAMES = {};
  US_STATES.forEach(function (s) { STATE_NAMES[s[0]] = s[1]; });
  STATE_NAMES.PR = "Puerto Rico";
  STATE_NAMES.VI = "U.S. Virgin Islands";
  STATE_NAMES.GU = "Guam";
  STATE_NAMES.AE = "Armed Forces Europe";
  STATE_NAMES.AP = "Armed Forces Pacific";

  function stateName(code) {
    return STATE_NAMES[String(code || "").toUpperCase()] || "";
  }

  // --- state privacy-law table ---------------------------------------
  // Only states whose comprehensive privacy act grants a deletion
  // right get a statutory citation; the letter then also cites
  // Section 5 of the FTC Act (15 U.S.C. § 45), as in Michael's
  // template. All listed states use a 45-day response window.
  //
  // UTAH IS SPECIAL, and the code says so plainly: the Utah Consumer
  // Privacy Act grants access, portability, and opt-out rights but NO
  // right to deletion. The Utah letter therefore does NOT claim a
  // statutory deletion right — it demands deletion under the FTC Act
  // and exercises the UCPA opt-outs. Inventing a UCPA deletion cite
  // would be a false legal claim in the user's own sent mail.
  //
  // MONTANA: the Act is cited by name only. The MCDPA's pinpoint
  // section for consumer rights was not verified to the standard a
  // legal demand letter deserves, so no section number is printed —
  // the Act name + FTC Act carry the demand.
  var STATE_LAWS = {
    CO: { act: "the Colorado Privacy Act", cite: "C.R.S. § 6-1-1306", days: 45 },
    CA: { act: "the California Consumer Privacy Act, as amended by the California Privacy Rights Act",
          cite: "Cal. Civ. Code § 1798.105", days: 45 },
    TX: { act: "the Texas Data Privacy and Security Act", cite: "Tex. Bus. & Com. Code § 541.103", days: 45 },
    VA: { act: "the Virginia Consumer Data Protection Act", cite: "Va. Code § 59.1-577", days: 45 },
    CT: { act: "the Connecticut Data Privacy Act", cite: "Conn. Gen. Stat. § 42-518", days: 45 },
    OR: { act: "the Oregon Consumer Privacy Act", cite: "ORS 646A.574", days: 45 },
    MT: { act: "the Montana Consumer Data Privacy Act", cite: null, days: 45 },
    UT: { utah: true, days: 45 }
  };

  // Registrable domain ("eTLD+1") of a host or email address:
  // last two labels, or three when the last two are a known
  // multi-label public suffix (co.uk style). Kept small on purpose.
  var MULTI_LABEL_SUFFIXES = [
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
    "org.au", "co.nz", "com.br", "com.cn", "com.tw", "co.jp",
    "co.kr", "co.in", "com.mx", "com.sg", "com.hk", "co.za"
  ];

  function registrableDomain(host) {
    var s = String(host == null ? "" : host).toLowerCase().trim();
    var at = s.lastIndexOf("@");
    if (at !== -1) s = s.slice(at + 1);
    s = s.replace(/^www\./, "").replace(/\.+$/, "");
    var labels = s.split(".").filter(function (x) { return !!x; });
    if (labels.length <= 2) return labels.join(".");
    var last2 = labels.slice(-2).join(".");
    if (MULTI_LABEL_SUFFIXES.indexOf(last2) !== -1) {
      return labels.slice(-3).join(".");
    }
    return last2;
  }

  var MONTHS = ["January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"];

  function dateLine(d) {
    var dt = (d instanceof Date) ? d : new Date();
    return MONTHS[dt.getMonth()] + " " + dt.getDate() + ", " + dt.getFullYear();
  }

  // The letter generator. Pure: {name, email, state, companyDomain,
  // companyName?, date?} -> {subject, body}. `date` is injectable
  // for tests; the browser passes nothing and gets today.
  function buildDemand(input) {
    input = input || {};
    var name = String(input.name || "").trim();
    var email = String(input.email || "").trim();
    var state = String(input.state || "").trim().toUpperCase();
    var sName = stateName(state);
    var domain = String(input.companyDomain || "").trim();
    var company = String(input.companyName || "").trim() || domain;
    var law = STATE_LAWS[state] || null;

    var subject = "FORMAL DATA DELETION REQUEST \u2013 " + name + " / " + email;

    var L = [];
    L.push("To the Privacy Team at " + company + ",");
    L.push("");
    L.push("My name is " + name + ", and I am writing to demand the " +
      "deletion of the personal data you hold about me.");
    L.push("Requester: " + name + " \u2014 account email " + email +
      (sName ? " \u2014 resident of " + sName : "") + ".");
    L.push("");
    if (law && law.utah) {
      // Honest Utah framing (see the STATE_LAWS note): UCPA has no
      // deletion right, so none is claimed. The deletion demand rests
      // on the FTC Act; the UCPA is cited only for its opt-outs.
      L.push("Pursuant to Section 5 of the FTC Act (15 U.S.C. \u00A7 45), " +
        "and exercising my opt-out rights under the Utah Consumer " +
        "Privacy Act, I demand the actions below. I note that the Utah " +
        "Act does not itself grant a deletion right; this deletion " +
        "demand is made under federal law prohibiting unfair practices, " +
        "and I expect it to be honored in full.");
    } else if (law) {
      L.push("Pursuant to " + law.act +
        (law.cite ? ", " + law.cite : "") +
        ", and Section 5 of the FTC Act (15 U.S.C. \u00A7 45), I exercise " +
        "my right to have my personal data deleted, and I demand the " +
        "actions below.");
    } else {
      L.push("Pursuant to Section 5 of the FTC Act (15 U.S.C. \u00A7 45) " +
        "and my state's consumer protection law, I demand the actions " +
        "below.");
    }
    L.push("");
    L.push("I require you to:");
    L.push("1. Delete all personal data you hold about me, in any form \u2014 " +
      "contact details, account records, usage and behavioral data, and " +
      "any inferences or profiles derived from them.");
    L.push("2. Opt me out of any sale, sharing, processing, tracking, and " +
      "profiling of my personal data, now and permanently.");
    L.push("3. Purge my personal data from your active databases and from " +
      "your backups and archives on your normal rotation cycle.");
    L.push("4. Direct all processors, sub-processors, vendors, and hosts " +
      "holding my data on your behalf to delete it as well, and confirm " +
      "to me that they have done so.");
    L.push("");
    L.push("Provide written confirmation that these steps are complete " +
      "within 45 days of this request" +
      (law && !law.utah
        ? " \u2014 the response window provided under " + law.act
        : "") +
      ", sent to " + email + ".");
    L.push("");
    L.push("If you deny any portion of this request on legal-retention " +
      "grounds, cite the exact statute or regulation you rely on for " +
      "each category of data you retain.");
    L.push("");
    L.push("If this matter is not resolved, I will refer it to " +
      (sName
        ? "the " + sName + " Attorney General's consumer protection division"
        : "my state Attorney General") +
      " and pursue every remedy available to me.");
    L.push("");
    L.push("Respectfully,");
    L.push("Submitted by: " + name + " (" + email + ")");
    L.push("Date: " + dateLine(input.date));

    return { subject: subject, body: L.join("\n") };
  }

  // --- stored user details (browser only) -----------------------------
  function storageArea() {
    try {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        return chrome.storage.local;
      }
    } catch (e) {}
    return null;
  }

  function loadDetails() {
    return new Promise(function (resolve) {
      var empty = { name: "", email: "", zip: "", state: "" };
      var area = storageArea();
      if (!area) { resolve(empty); return; }
      try {
        area.get([DETAIL_KEYS.name, DETAIL_KEYS.email,
                  DETAIL_KEYS.zip, DETAIL_KEYS.state], function (items) {
          items = items || {};
          var out = {
            name: String(items[DETAIL_KEYS.name] || ""),
            email: String(items[DETAIL_KEYS.email] || ""),
            zip: String(items[DETAIL_KEYS.zip] || ""),
            state: String(items[DETAIL_KEYS.state] || "")
          };
          // v1.0.53: the ZIP is the only source of state now.
          // A state stored by the picker-era form must not
          // override what the ZIP says: a resolvable ZIP
          // re-derives the state, and a present-but-unresolvable
          // ZIP clears it ("" -> the general U.S. letter),
          // regardless of any old stored value.
          if (out.zip.trim()) out.state = stateForZip(out.zip) || "";
          resolve(out);
        });
      } catch (e) { resolve(empty); }
    });
  }

  function saveDetails(d) {
    return new Promise(function (resolve) {
      var area = storageArea();
      if (!area) { resolve(false); return; }
      var obj = {};
      obj[DETAIL_KEYS.name] = String(d.name || "");
      obj[DETAIL_KEYS.email] = String(d.email || "");
      obj[DETAIL_KEYS.zip] = String(d.zip || "");
      obj[DETAIL_KEYS.state] = String(d.state || "");
      try {
        area.set(obj, function () {
          resolve(!(typeof chrome !== "undefined" && chrome.runtime &&
                    chrome.runtime.lastError));
        });
      } catch (e) { resolve(false); }
    });
  }

  // Details count as complete when the letter can be generated:
  // a name and an account email. State may legitimately be ""
  // (an unresolvable ZIP) — the letter then uses the general
  // U.S. framing instead of a state statute (v1.0.53: there is
  // no picker left to rescue a bad ZIP, and blocking on it
  // would strand the user entirely).
  function detailsComplete(d) {
    return !!(d && String(d.name || "").trim() &&
              String(d.email || "").trim());
  }

  // --- recipient mail-server sanity check (v1.0.53) -------------------
  // The demand's Send-to address comes from the domain's RDAP
  // registration record when it publishes one, or is pasted in by
  // the user from the company's website (v1.0.55). Either way,
  // before the user sends, check whether the DOMAIN can receive
  // email at all, via DNS-over-HTTPS (Google's JSON API — the same
  // endpoint lib/analyze.js already uses for reverse DNS). This
  // can only prove a domain has mail servers; it can NEVER prove
  // a mailbox exists, and the UI copy says so. Advisory only: the
  // result never blocks the compose button.
  //
  // checkRecipientMx(address, fetchFn?) -> Promise<{kind, domain,
  // text}> with kind one of "ok" | "uncertain" | "bounce" |
  // "error" | "none". fetchFn is injectable for Node tests; the
  // browser passes nothing and gets the global fetch. Every
  // failure resolves to the neutral "error" state — this function
  // never rejects.
  function mxDomainOf(address) {
    var s = String(address == null ? "" : address).trim().toLowerCase();
    var at = s.lastIndexOf("@");
    if (at === -1) return "";
    return s.slice(at + 1).trim();
  }

  function dnsHasType(json, type) {
    var ans = (json && json.Answer) || [];
    for (var i = 0; i < ans.length; i++) {
      if (ans[i] && ans[i].type === type) return true;
    }
    return false;
  }

  function checkRecipientMx(address, fetchFn) {
    var domain = mxDomainOf(address);
    if (!domain) {
      return Promise.resolve({ kind: "none", domain: "", text: "" });
    }
    var f = fetchFn ||
      (typeof fetch !== "undefined" ? fetch : null);
    var errorResult = {
      kind: "error", domain: domain,
      text: "Couldn't check " + domain + "'s mail servers \u2014 " +
            "the address is a best guess."
    };
    if (!f) return Promise.resolve(errorResult);
    function query(type) {
      return f("https://dns.google/resolve?name=" +
               encodeURIComponent(domain) + "&type=" + type,
               { headers: { "Accept": "application/dns-json" } })
        .then(function (r) {
          if (!r || !r.ok) throw new Error("dns http");
          return r.json();
        });
    }
    return query("MX").then(function (mx) {
      if (dnsHasType(mx, 15)) {
        return { kind: "ok", domain: domain,
          text: "\u2713 " + domain + " accepts email \u2014 mail " +
                "servers found. (The exact mailbox can't be " +
                "confirmed from a browser.)" };
      }
      return query("A").then(function (a) {
        if (dnsHasType(a, 1) || dnsHasType(a, 28)) {
          return { kind: "uncertain", domain: domain,
            text: "\u26A0 " + domain + " has no mail servers " +
                  "listed, but the domain itself answers \u2014 " +
                  "delivery is uncertain." };
        }
        return { kind: "bounce", domain: domain,
          text: "\u26A0 No mail servers found for " + domain +
                " \u2014 this address will likely bounce. Try the " +
                "other suggestion or the company's privacy page." };
      });
    }).catch(function () { return errorResult; });
  }

  // --- domain registration contact lookup (v1.0.55) --------------------
  // The recipient guess system (ranked privacy@/role candidates,
  // v1.0.53-54) is GONE from the panel: Michael's verdict was that
  // guessed addresses are worse than none — the first real letter
  // nearly went out addressed to a guessed info@. Instead, the
  // panel consults a real published record — the sender root
  // domain's RDAP registration data — and, when the record
  // yields a contact, OFFERS it as a one-click suggestion under
  // the (always initially empty) Send-to field. Even a real
  // record contact is only suggested, never auto-filled:
  // registrar contacts are iffy, and the user stays the one
  // who decides where their demand goes.
  //
  // Chain: the IANA RDAP bootstrap (https://data.iana.org/rdap/
  // dns.json — cached in a module variable for the page session)
  // maps the TLD to its registry's RDAP base URL; then
  // <base>domain/<domain>. If the bootstrap is unreachable or
  // doesn't list the TLD, fall back to https://rdap.org/domain/
  // <domain>, which redirects to the authoritative server.
  // Registry RDAP servers are a public-data protocol and serve
  // Access-Control-Allow-Origin: *, so the manifest needs host
  // permission only for the two entry points (data.iana.org,
  // rdap.org), not for every registry.
  //
  // Extraction walks the response's entities RECURSIVELY (an
  // abuse contact is typically a sub-entity nested inside the
  // registrar), collecting every vCard email with its entity's
  // roles. Preference: registrant > administrative > technical
  // > registrar's abuse sub-entity > anything else. The org name
  // reported is the nearest enclosing "primary" entity's name
  // (registrant/administrative/technical/registrar), so the
  // Civic Dialogues record reads "Amazon Registrar, Inc.", not
  // whatever the abuse sub-entity calls itself.
  //
  // fetchRegistrationContact(domain, fetchFn?) ->
  //   Promise<{email, role, org} | null>. NEVER rejects: a
  // redacted record, a failed fetch, malformed JSON — all just
  // resolve null, and the panel falls back to the website
  // errand (the user pastes the published address themselves).
  var rdapServicesCache = null;
  var rdapBootstrapInflight = null;

  function loadRdapServices(f) {
    if (rdapServicesCache) return Promise.resolve(rdapServicesCache);
    if (rdapBootstrapInflight) return rdapBootstrapInflight;
    rdapBootstrapInflight = f("https://data.iana.org/rdap/dns.json",
        { headers: { "Accept": "application/rdap+json" } })
      .then(function (r) {
        if (!r || !r.ok) throw new Error("iana http");
        return r.json();
      })
      .then(function (json) {
        rdapServicesCache = (json && json.services) || null;
        rdapBootstrapInflight = null;
        return rdapServicesCache;
      })
      .catch(function () {
        // Not cached on failure: the caller falls back to
        // rdap.org for THIS lookup, and a later lookup may
        // retry the bootstrap.
        rdapBootstrapInflight = null;
        return null;
      });
    return rdapBootstrapInflight;
  }

  function rdapBaseFor(services, tld) {
    if (!services) return "";
    for (var i = 0; i < services.length; i++) {
      var tlds = services[i][0] || [];
      var urls = services[i][1] || [];
      if (tlds.indexOf(tld) !== -1 && urls.length) {
        return String(urls[0]).replace(/\/?$/, "/");
      }
    }
    return "";
  }

  function rdapVcardProps(entity) {
    var emails = [];
    var name = "";
    var vc = entity && entity.vcardArray;
    if (Array.isArray(vc) && Array.isArray(vc[1])) {
      vc[1].forEach(function (prop) {
        if (!Array.isArray(prop)) return;
        var pname = String(prop[0] || "").toLowerCase();
        var value = prop[3];
        if (typeof value !== "string") return;
        if (pname === "email" && value.indexOf("@") !== -1) {
          emails.push(value.trim());
        } else if ((pname === "fn" || pname === "org") && !name) {
          name = value.trim();
        }
      });
    }
    return { emails: emails, name: name };
  }

  var RDAP_PRIMARY_ROLES = ["registrant", "administrative",
    "technical", "registrar"];

  function walkRdapEntity(ent, ctx, out) {
    if (!ent || typeof ent !== "object") return;
    var roles = (ent.roles || []).map(function (r) {
      return String(r).toLowerCase();
    });
    var props = rdapVcardProps(ent);
    // The reportable org name comes from the nearest enclosing
    // primary entity — an abuse sub-entity's own label (often
    // just "Abuse Contact") must not shadow its registrar's.
    var namedOrg = ctx.namedOrg;
    var isPrimary = roles.some(function (r) {
      return RDAP_PRIMARY_ROLES.indexOf(r) !== -1;
    });
    if (isPrimary && props.name) namedOrg = props.name;
    var org = namedOrg || props.name || "";
    props.emails.forEach(function (email) {
      var rank = 0;
      var label = roles.length ? roles[0] : "registration";
      if (roles.indexOf("registrant") !== -1) {
        rank = 4; label = "registrant";
      } else if (roles.indexOf("administrative") !== -1) {
        rank = 3; label = "administrative";
      } else if (roles.indexOf("technical") !== -1) {
        rank = 2; label = "technical";
      } else if (roles.indexOf("abuse") !== -1 &&
                 (ctx.registrarAbove ||
                  roles.indexOf("registrar") !== -1)) {
        rank = 1; label = "registrar abuse";
      }
      out.push({ email: email, rank: rank, role: label, org: org });
    });
    var childCtx = {
      namedOrg: namedOrg,
      registrarAbove: ctx.registrarAbove ||
        roles.indexOf("registrar") !== -1
    };
    var subs = ent.entities || [];
    for (var i = 0; i < subs.length; i++) {
      walkRdapEntity(subs[i], childCtx, out);
    }
  }

  // Known dead ends (Michael's ruling, 2026-10-17): contacts
  // that technically exist in a registration record but go
  // nowhere for a privacy demand. Amazon Registrar's abuse
  // desk — trustandsafety@support.aws.com — is an AWS abuse
  // intake, not a channel that acts on demands against a
  // domain's owner, and the first real target's record
  // (civicdialogues.org, via Public Interest Registry) points
  // exactly there. A dead-end match makes the lookup behave
  // as if the record published NOTHING: no suggestion, the
  // website errand is the story. Append future dead ends as
  // {domain} (the email's own domain) and/or {namePattern}
  // (matched against the contact's org name) entries.
  var DEAD_END_RDAP_CONTACTS = [
    { domain: "support.aws.com" },
    { namePattern: /amazon/i }
  ];

  function isDeadEndRdapContact(c) {
    if (!c) return false;
    var dom = String(c.email || "").split("@").pop()
      .trim().toLowerCase();
    var org = String(c.org || "");
    for (var i = 0; i < DEAD_END_RDAP_CONTACTS.length; i++) {
      var rule = DEAD_END_RDAP_CONTACTS[i];
      if (rule.domain && dom === rule.domain) return true;
      if (rule.namePattern && rule.namePattern.test(org)) return true;
    }
    return false;
  }

  // Pure extractor (Node-testable with canned payloads):
  // RDAP domain JSON -> {email, role, org} | null. Dead-end
  // contacts (above) are skipped during selection — a lower-
  // ranked live contact still wins over a dead-end one, and
  // if every contact in the record is a dead end the result
  // is null, exactly like a fully redacted record.
  function extractRdapContact(json) {
    if (!json || typeof json !== "object") return null;
    var out = [];
    var entities = json.entities || [];
    for (var i = 0; i < entities.length; i++) {
      walkRdapEntity(entities[i],
        { namedOrg: "", registrarAbove: false }, out);
    }
    if (!out.length) return null;
    // Stable sort: highest rank wins; ties keep record order.
    out.sort(function (a, b) { return b.rank - a.rank; });
    for (var j = 0; j < out.length; j++) {
      if (!isDeadEndRdapContact(out[j])) {
        return { email: out[j].email, role: out[j].role,
                 org: out[j].org || "" };
      }
    }
    return null;
  }

  function fetchRegistrationContact(rootDomain, fetchFn) {
    var domain = String(rootDomain || "").trim().toLowerCase();
    if (!domain) return Promise.resolve(null);
    var f = fetchFn ||
      (typeof fetch !== "undefined" ? fetch : null);
    if (!f) return Promise.resolve(null);
    function getJson(url) {
      return f(url, { headers: { "Accept": "application/rdap+json" } })
        .then(function (r) {
          if (!r || !r.ok) throw new Error("rdap http");
          return r.json();
        });
    }
    var tld = domain.split(".").pop();
    return loadRdapServices(f).then(function (services) {
      var base = rdapBaseFor(services, tld);
      var url = base
        ? base + "domain/" + encodeURIComponent(domain)
        : "https://rdap.org/domain/" + encodeURIComponent(domain);
      return getJson(url);
    }).then(function (json) {
      return extractRdapContact(json);
    }).catch(function () { return null; });
  }

  // --- demand recipient candidates (v1.0.53, amended) -----------------
  // v1.0.55: RETIRED from the panel — nothing renders these any
  // more (see the RDAP section above for what replaced them).
  // The functions stay exported for the record and for their
  // unit tests; the panel fills Send-to from the RDAP record or
  // leaves it empty for the user's own paste.
  // privacy@<domain> is a GUESS, and at the first real target
  // (civicdialogues.org) it did not exist — Michael hand-checked.
  // So the step now ranks every plausible recipient and lets the
  // user pick; the MX check above vets whichever is in the field:
  //   (a) root twin — the sender's own local part moved from a
  //       subdomain to the registrable root
  //       (info@e.civicdialogues.org -> info@civicdialogues.org);
  //   (b) the sender's exact address — a human mailbox that wrote
  //       to the user is a plausible privacy contact;
  //   (c) privacy@<registrable sender domain> (the old default);
  //   (d) privacy@<abuse-contact domain>, when different.
  // (a) and (b) are skipped when the local part looks automated
  // (noreply and friends): the root twin of a noreply mailbox is
  // still a noreply mailbox. The result is deduped, rank order
  // preserved; element 0 is the default To, the rest are chips.
  var AUTOMATED_LOCALS = ["noreply", "no-reply", "donotreply",
    "do-not-reply", "bounce", "bounces", "mailer-daemon",
    "postmaster"];

  function addressOf(fromHeader) {
    var s = String(fromHeader == null ? "" : fromHeader);
    var angle = s.match(/<([^<>]+)>/);
    var addr = (angle ? angle[1] : s).trim();
    var m = addr.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    return m ? m[0].toLowerCase() : "";
  }

  function isAutomatedLocal(local) {
    var base = String(local || "").toLowerCase().split("+")[0];
    for (var i = 0; i < AUTOMATED_LOCALS.length; i++) {
      var p = AUTOMATED_LOCALS[i];
      if (base === p || base.indexOf(p + "-") === 0 ||
          base.indexOf(p + ".") === 0 || base.indexOf(p + "_") === 0) {
        return true;
      }
    }
    return false;
  }

  function demandCandidates(fromHeader, abuseAddr, fallbackDomain) {
    var out = [];
    function push(addr) {
      if (addr && out.indexOf(addr) === -1) out.push(addr);
    }
    var addr = addressOf(fromHeader);
    var host = mxDomainOf(addr);
    if (!host && fallbackDomain) {
      host = String(fallbackDomain).toLowerCase().trim();
    }
    var root = host ? registrableDomain(host) : "";
    var local = addr ? addr.slice(0, addr.lastIndexOf("@")) : "";
    var automated = !local || isAutomatedLocal(local);
    if (host && root && host !== root && !automated) {
      push(local + "@" + root); // (a) root twin
    }
    if (addr && !automated) push(addr); // (b) exact sender
    if (root) push("privacy@" + root); // (c) privacy@ root
    var abuseDom = abuseAddr ? registrableDomain(abuseAddr) : "";
    if (abuseDom) push("privacy@" + abuseDom); // (d) — dedupe drops
    // it when it equals (c), which is the "when different" rule.
    return out;
  }

  // v1.0.54: the "Also try:" chip list for a candidate set.
  // Starts from the ranked candidates past the default, then
  // adds the role mailboxes companies actually staff at the
  // root domain — contact@, info@, support@ — skipping any
  // address already present as the default or as a chip (when
  // the sender's own local part IS one of those roles, the
  // root twin already produced it). Michael's first-target
  // check is why these exist: Civic Dialogues' footer and its
  // privacy notice both name contact@<root> for data requests,
  // while privacy@<root> did not exist there. Capped at 6
  // chips so the row stays a row; rank order preserved,
  // extras dropped.
  var ROLE_LOCALS = ["contact", "info", "support"];
  var MAX_DEMAND_CHIPS = 6;

  function demandChips(cands, rootDomain) {
    var all = cands || [];
    var list = all.slice(1);
    var root = String(rootDomain || "").toLowerCase().trim();
    if (root) {
      ROLE_LOCALS.forEach(function (role) {
        var addr = role + "@" + root;
        if (all.indexOf(addr) === -1 && list.indexOf(addr) === -1) {
          list.push(addr);
        }
      });
    }
    return list.slice(0, MAX_DEMAND_CHIPS);
  }

  // --- shared details form (browser only; popup + panel) --------------
  // Builds the Name / Email / ZIP mini-form into a fresh
  // <div class="sa-df"> element. v1.0.53: ZIP-only — there is no
  // state picker; the state comes from the ZIP or the letter uses
  // the general U.S. framing. On successful save, calls
  // onSaved(details) with the stored values. Uses
  // textContent/createElement only — no innerHTML, matching the
  // no-injection rule content.js follows.
  var detailsFormSeq = 0;
  function buildDetailsForm(onSaved) {
    function el(tag, cls, text) {
      var n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    }
    var form = el("div", "sa-df");
    // Per-instance id prefix so each label's `for` points at its own
    // input even if the form is ever built twice in one document.
    var pfx = "sa-df-" + (++detailsFormSeq) + "-";

    var nameIn = el("input", "sa-df-input");
    nameIn.id = pfx + "name";
    nameIn.type = "text";
    nameIn.setAttribute("autocomplete", "name");
    nameIn.setAttribute("aria-label", "Your full name");
    var emailIn = el("input", "sa-df-input");
    emailIn.id = pfx + "email";
    emailIn.type = "email";
    emailIn.setAttribute("autocomplete", "email");
    emailIn.setAttribute("aria-label", "Your account email");
    var zipIn = el("input", "sa-df-input");
    zipIn.id = pfx + "zip";
    zipIn.type = "text";
    zipIn.setAttribute("inputmode", "numeric");
    zipIn.setAttribute("autocomplete", "postal-code");
    zipIn.setAttribute("aria-label", "Your ZIP code");

    // Labels are child NODEs (appendChild via row()) — passing one
    // as el()'s text argument stringified it to
    // "[object HTMLLabelElement]" (the v1.0.49 live-test bug).
    var stateNote = el("p", "sa-df-note");

    var status = el("p", "sa-df-status");
    var saveBtn = el("button", "sa-df-save", "Save");
    saveBtn.type = "button";

    function row(label, input) {
      var r = el("div", "sa-df-row");
      var lab = el("label", "sa-df-label", label);
      if (input.id) lab.htmlFor = input.id;
      r.appendChild(lab);
      r.appendChild(input);
      return r;
    }
    form.appendChild(row("Name", nameIn));
    form.appendChild(row("Email", emailIn));
    form.appendChild(row("ZIP", zipIn));
    form.appendChild(stateNote);
    form.appendChild(saveBtn);
    form.appendChild(status);

    // The note under the ZIP is the only state UI left (v1.0.53):
    // a resolved ZIP names its state; an empty ZIP says nothing;
    // a non-empty ZIP that won't resolve explains that the letter
    // will use the general U.S. version instead of a state law.
    var UNRESOLVED_NOTE = "That ZIP didn't resolve to a state " +
      "\u2014 the letter will use the general U.S. version. " +
      "Double-check the ZIP if that looks wrong.";
    function refreshState() {
      var raw = zipIn.value.trim();
      var z = stateForZip(raw);
      if (z) {
        stateNote.style.display = "";
        stateNote.textContent = "State: " + stateName(z) + " (from your ZIP)";
      } else if (raw) {
        stateNote.style.display = "";
        stateNote.textContent = UNRESOLVED_NOTE;
      } else {
        stateNote.style.display = "none";
        stateNote.textContent = "";
      }
      return z;
    }
    zipIn.addEventListener("input", refreshState);

    loadDetails().then(function (d) {
      nameIn.value = d.name;
      emailIn.value = d.email;
      zipIn.value = d.zip;
      refreshState();
    });

    saveBtn.addEventListener("click", function () {
      // The ZIP is the only source of state: derived here, never
      // read from a picker and never carried over from an old
      // stored value. Unresolvable ZIP -> "" -> general letter.
      var d = {
        name: nameIn.value.trim(),
        email: emailIn.value.trim(),
        zip: zipIn.value.trim(),
        state: stateForZip(zipIn.value) || ""
      };
      refreshState();
      if (!d.name || !d.email) {
        status.textContent = "Add your name and email so the demand can name you.";
        return;
      }
      saveBtn.disabled = true;
      saveDetails(d).then(function (ok) {
        saveBtn.disabled = false;
        status.textContent = ok
          ? "Saved \u2713 \u2014 kept only in this browser."
          : "Couldn't save in this browser \u2014 the demand can still be drafted, but you'll re-enter these next time.";
        if (ok && typeof onSaved === "function") onSaved(d);
      });
    });

    return form;
  }

  var api = {
    buildDemand: buildDemand,
    stateForZip: stateForZip,
    stateName: stateName,
    registrableDomain: registrableDomain,
    STATE_LAWS: STATE_LAWS,
    US_STATES: US_STATES,
    DETAIL_KEYS: DETAIL_KEYS,
    loadDetails: loadDetails,
    saveDetails: saveDetails,
    detailsComplete: detailsComplete,
    buildDetailsForm: buildDetailsForm,
    mxDomainOf: mxDomainOf,
    checkRecipientMx: checkRecipientMx,
    demandCandidates: demandCandidates,
    demandChips: demandChips,
    extractRdapContact: extractRdapContact,
    fetchRegistrationContact: fetchRegistrationContact,
    DEAD_END_RDAP_CONTACTS: DEAD_END_RDAP_CONTACTS,
    isDeadEndRdapContact: isDeadEndRdapContact
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // Node (tests)
  } else if (typeof window !== "undefined") {
    window.SpamDemand = api; // browser
  }

  // Toolbar popup auto-init: the popup carries an empty slot div and
  // this wires the shared details form into it. Runs nowhere else —
  // Gmail pages never contain the slot, and Node has no document.
  if (typeof document !== "undefined" && document.addEventListener) {
    document.addEventListener("DOMContentLoaded", function () {
      var slot = document.getElementById("sa-details-slot");
      if (slot && typeof api.buildDetailsForm === "function") {
        slot.appendChild(api.buildDetailsForm(null));
      }
    });
  }
})();
