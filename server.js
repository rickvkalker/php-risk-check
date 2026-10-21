// php2shell exposure checker: a small zero-dependency Node server.
// Serves public/index.html and a JSON API at /api/scan?url=...
// Run: node server.js   (PORT env var optional, default 3000)

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns/promises");
const net = require("node:net");

const PORT = Number(process.env.PORT) || 3000;
const TIMEOUT_MS = 8000;
const MAX_BODY = 512 * 1024;
const MAX_REDIRECTS = 5;

// The php2shell fix floor: the first release on each branch that contains the
// CVE-2026-109618/109619 fix. Used to flag the critical RCE specifically, and
// as the offline fallback if php.net can't be reached. Confirm at php.net.
const PHP2SHELL_FIXED = { "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12" };

const ADVISORY = {
  name: "php2shell",
  cves: ["CVE-2026-109618", "CVE-2026-109619"],
  cvss: "9.2 (CVSS v4.0)",
  impact: "Unauthenticated remote code execution",
  affected: "PHP 5 onwards (per CERT-EU)",
  updated: "2026-10-21",
};

// ---------- live PHP release data (php.net) ----------
//
// php.net publishes the currently-supported branches and their latest release
// as JSON. We cache it for a day so the tool is never stale and we don't need
// to hand-edit version numbers. If the fetch fails we fall back to the
// php2shell floor above, so the tool still works offline.
const RELEASES_URL = process.env.RELEASES_URL || "https://www.php.net/releases/active.php?json";
const RELEASES_TTL = 24 * 60 * 60 * 1000;
let releaseCache = { at: 0, data: null };

async function getSupportedReleases() {
  if (releaseCache.data && Date.now() - releaseCache.at < RELEASES_TTL) {
    return releaseCache.data;
  }
  try {
    const res = await fetch(RELEASES_URL, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "User-Agent": "php-risk-check/1.0" },
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const raw = await res.json();
    // Shape: { "8": { "8.3": { "version": "8.3.12", ... }, ... }, ... }
    const latest = {};
    for (const major of Object.values(raw)) {
      for (const [branch, info] of Object.entries(major)) {
        if (info && info.version) latest[branch] = info.version;
      }
    }
    if (Object.keys(latest).length === 0) throw new Error("empty release list");
    // Never let live data regress below the known php2shell fix.
    for (const [branch, floor] of Object.entries(PHP2SHELL_FIXED)) {
      if (!latest[branch] || cmpVersion(latest[branch], floor) < 0) latest[branch] = floor;
    }
    releaseCache = { at: Date.now(), data: { latest, live: true } };
    return releaseCache.data;
  } catch (e) {
    // Fall back to the hardcoded floor; mark it as not live so callers can say so.
    const fallback = { latest: { ...PHP2SHELL_FIXED }, live: false };
    // Cache the fallback briefly so a flaky network doesn't fetch on every request.
    releaseCache = { at: Date.now() - RELEASES_TTL + 5 * 60 * 1000, data: fallback };
    return fallback;
  }
}

// ---------- SSRF guard: only scan public internet hosts ----------

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  const v = ip.toLowerCase();
  if (v.startsWith("::ffff:")) return isPrivateIp(v.slice(7));
  return (
    v === "::" || v === "::1" ||
    v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb") ||
    v.startsWith("ff")
  );
}

async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (/^localhost$/i.test(host) || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new UserError("That address is not a public website.");
  }
  let addrs;
  try {
    addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  } catch {
    throw new UserError(`Could not find the domain "${host}". Check the spelling.`);
  }
  if (addrs.some((a) => isPrivateIp(a.address))) {
    throw new UserError("That address points to a private network and can't be scanned.");
  }
}

class UserError extends Error {}

function normaliseUrl(input) {
  let s = String(input || "").trim();
  if (!s) throw new UserError("Enter a website address.");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new UserError("That doesn't look like a valid website address.");
  }
  if (!/^https?:$/.test(u.protocol)) throw new UserError("Only http and https sites can be scanned.");
  if (u.username || u.password) throw new UserError("Remove the username/password from the address.");
  if (u.port && !["80", "443", "8080", "8443"].includes(u.port)) {
    throw new UserError("Only standard web ports (80, 443, 8080, 8443) can be scanned.");
  }
  return u;
}

// ---------- fetching ----------

async function readCapped(res) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  reader.cancel().catch(() => {});
  return Buffer.concat(chunks).toString("utf8");
}

// GET with manual redirects so every hop is checked against the SSRF guard.
async function safeGet(startUrl) {
  let url = new URL(startUrl);
  const hops = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    await assertPublicHost(url.hostname);
    const res = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        "User-Agent": "php2shell-exposure-checker/1.0 (passive header check)",
        Accept: "text/html,*/*;q=0.8",
      },
    });
    hops.push({ url: url.href, status: res.status, headers: res.headers });
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      res.body?.cancel().catch(() => {});
      url = new URL(loc, url);
      if (!/^https?:$/.test(url.protocol)) break;
      continue;
    }
    const body = await readCapped(res);
    return { finalUrl: url.href, status: res.status, hops, body };
  }
  throw new UserError("The site redirected too many times.");
}

// ---------- analysis ----------

function parsePhpVersion(str) {
  const m = /PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i.exec(str || "");
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: m[3] != null ? +m[3] : null, raw: m[0].slice(4) };
}

function cmpVersion(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

function detectWebServer(hops) {
  for (const h of hops) {
    const s = h.headers.get("server") || "";
    if (/litespeed/i.test(s)) return "LiteSpeed";
    if (/apache/i.test(s)) return "Apache";
    if (/nginx/i.test(s)) return "nginx";
    if (/caddy/i.test(s)) return "Caddy";
    if (/microsoft-iis/i.test(s)) return "IIS";
    if (/openresty/i.test(s)) return "OpenResty";
  }
  return null;
}

function detectPhp(main, probes) {
  const probeList = Array.isArray(probes) ? probes : probes ? [probes] : [];
  const evidence = [];
  let version = null;

  const allHops = [...main.hops, ...probeList.flatMap((p) => p.hops)];
  for (const h of allHops) {
    const xpb = h.headers.get("x-powered-by");
    const server = h.headers.get("server");
    for (const [name, val] of [["X-Powered-By", xpb], ["Server", server]]) {
      if (val && /php/i.test(val)) {
        evidence.push(`${name} header: "${val}"`);
        version = version || parsePhpVersion(val);
      }
    }
    const cookies = h.headers.getSetCookie?.() || [];
    if (cookies.some((c) => /^PHPSESSID=/i.test(c))) evidence.push("PHPSESSID session cookie set");
  }

  // PHP versions also leak in the body of error/default pages (e.g. a 404 or a
  // PHP error footer). Scan every retrieved body for a "PHP/x.y.z" string.
  for (const doc of [main, ...probeList]) {
    const found = parsePhpVersion(doc.body || "");
    if (found) {
      version = version || found;
      evidence.push(`PHP version in page content: "${found.raw}"`);
    }
  }

  const webServer = detectWebServer(allHops);
  const html = main.body || "";
  // Combined body text (homepage + all probe pages) for fingerprinting.
  const allBodies = [html, ...probeList.map((p) => p.body || "")].join("\n");

  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(allBodies)
    || /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i.exec(allBodies);
  const platforms = [
    [/wordpress/i, "WordPress"], [/drupal/i, "Drupal"], [/joomla/i, "Joomla"],
    [/typo3/i, "TYPO3"], [/magento/i, "Magento"], [/prestashop/i, "PrestaShop"],
  ];
  let platform = null;
  if (gen) {
    for (const [re, name] of platforms) if (re.test(gen[1])) platform = name;
    if (platform) evidence.push(`Site generator: "${gen[1]}"`);
  }
  // Framework / app fingerprints found anywhere across the fetched pages.
  const fingerprints = [
    [/\/wp-(content|includes)\/|wp-login\.php/i, "WordPress", "WordPress files/paths"],
    [/\/sites\/(default|all)\/(files|modules|themes)\//i, "Drupal", "Drupal asset paths"],
    [/Mage\.Cookies|\/static\/version\d+\/frontend\//i, "Magento", "Magento asset paths"],
    [/option=com_|Joomla!/i, "Joomla", "Joomla paths"],
    [/laravel_session|\/vendor\/laravel\//i, "Laravel", "Laravel framework"],
    [/_sf2_|\/bundles\/framework\//i, "Symfony", "Symfony framework"],
    [/phpbb|style_cookiesettings/i, "phpBB", "phpBB forum"],
    [/Nextcloud|data-requesttoken/i, "Nextcloud", "Nextcloud"],
    [/MediaWiki/i, "MediaWiki", "MediaWiki"],
  ];
  for (const [re, name, why] of fingerprints) {
    if (!platform && re.test(allBodies)) {
      platform = name;
      evidence.push(`${why} detected`);
    }
  }
  if (/(href|action|src)=["'][^"']*\.php(\?|["'#])/i.test(allBodies)) {
    evidence.push("Page links to .php files");
  }
  // De-duplicate (cookies and headers can repeat across redirect hops).
  const unique = [...new Set(evidence)];
  return { usesPhp: unique.length > 0, version, platform, webServer, evidence: unique };
}

function behindCdn(hops) {
  const h = hops[hops.length - 1].headers;
  if (h.get("cf-ray")) return "Cloudflare";
  if (h.get("x-akamai-transformed") || /akamai/i.test(h.get("server") || "")) return "Akamai";
  if (h.get("x-sucuri-id")) return "Sucuri";
  if (/fastly/i.test(h.get("x-served-by") || "") || h.get("x-fastly-request-id")) return "Fastly";
  if (h.get("x-amz-cf-id")) return "Amazon CloudFront";
  return null;
}

// Is this branch still getting security support? <= 8.1 is end-of-life as of
// late 2026; live php.net data refines the upper boundary for newer branches.
function branchStatus(major, minor, releases) {
  if (major < 8 || (major === 8 && minor <= 1)) return "eol";
  const branch = `${major}.${minor}`;
  if (releases.latest[branch]) return "supported";
  if (releases.live) {
    // Live data lists every supported branch. Not listed and newer than all
    // known branches => a release we don't know yet (treat as current).
    const minors = Object.keys(releases.latest)
      .filter((b) => b.startsWith("8."))
      .map((b) => Number(b.split(".")[1]));
    const maxKnown = minors.length ? Math.max(...minors) : 5;
    return minor > maxKnown ? "future" : "eol";
  }
  // Offline fallback only knows the affected branches; assume newer is current.
  return minor > 5 ? "future" : "eol";
}

// A ready-to-send message the owner can copy and paste to whoever looks after
// their website (hosting company or developer). This is the main "action you can
// take right now" for non-technical owners.
function hostMessage(site, urgent, target) {
  const safe = Object.values(target).join(", ");
  if (urgent) {
    return (
      `Hi, I'm the owner of ${site}.\n\n` +
      `I've read that there's a serious security problem in PHP (the software many websites run on) that could let hackers take over websites. Could you please:\n\n` +
      `1. Check which version of PHP my website is using.\n` +
      `2. Update it to a safe version (${safe}, or newer) as soon as possible — ideally today.\n` +
      `3. If it can't be updated today, please take my site offline or put it in maintenance mode until it can.\n\n` +
      `Please let me know once it's done. Thank you.`
    );
  }
  return (
    `Hi, I'm the owner of ${site}.\n\n` +
    `My website is running an older version of PHP. It's not an emergency, but could you update it to the latest version (${safe}, or newer) when you get a chance? Thanks.`
  );
}

function assess(det, cdn, releases, siteUrl) {
  const v = det.version;
  const site = (() => {
    try { return new URL(siteUrl).hostname; } catch { return "my website"; }
  })();
  const liveNote = releases.live
    ? null
    : "Note: we couldn't reach php.net to double-check the latest versions, so this is based on our records from 21 October 2026.";
  const base = (extra = []) => [...extra, liveNote].filter(Boolean);

  // No PHP found.
  if (!det.usesPhp) {
    return {
      level: "low",
      verdict: "Looks fine — no action needed",
      headline: "We didn't find PHP on your site",
      summary:
        "We couldn't see any sign that your website uses PHP, so this security issue probably doesn't affect you. Some sites hide this, so it's not a guarantee.",
      actions: [
        "You don't need to do anything right now.",
        "If you're not sure what your website is built with, ask whoever built or hosts it to confirm it doesn't use PHP.",
      ],
      notes: base(),
    };
  }

  const platformBit = det.platform ? ` (${det.platform})` : "";

  // PHP present but version hidden — treat as risky.
  if (!v) {
    return {
      level: "high",
      verdict: "Act today to be safe",
      headline: `Your site uses PHP${platformBit}, but we couldn't see the version`,
      confidence: "low",
      summary:
        "Your website runs PHP, but it doesn't show which version — so we can't tell if it's safe. Because a serious PHP security issue is going around, it's best to treat it as at-risk until someone confirms otherwise.",
      actions: [
        "Send the message below to your hosting company or web developer today.",
        "Ask them to confirm your PHP version is up to date, and to update it if it isn't.",
        "If they can't confirm it quickly, ask them to take the site offline until they can.",
      ],
      contactMessage: hostMessage(site, true, releases.latest),
      notes: base(),
    };
  }

  const branch = `${v.major}.${v.minor}`;
  const label = `PHP ${v.raw}${platformBit}`;
  const status = branchStatus(v.major, v.minor, releases);
  const latest = releases.latest[branch];
  const floor = PHP2SHELL_FIXED[branch];
  const full = v.patch != null ? `${v.major}.${v.minor}.${v.patch}` : null;
  const vulnPhp2shell = floor && full && cmpVersion(full, floor) < 0;
  const outdated = latest && full && cmpVersion(full, latest) < 0;
  const confidence = full ? "high" : "medium";

  // End-of-life PHP.
  if (status === "eol") {
    return {
      level: "critical",
      verdict: "Act now — your site is at risk",
      headline: `Your site runs ${label}, which is no longer supported`,
      confidence,
      summary:
        "Your website is on a very old version of PHP that no longer gets security updates. It won't be protected against this issue or future ones, so it's a real risk for hackers to take control of your site.",
      actions: [
        "Send the message below to your hosting company or web developer now.",
        "Ask them to take your site offline or into maintenance mode until it's fixed.",
        "Ask them to move your site to a current, supported version of PHP (they'll know how).",
      ],
      contactMessage: hostMessage(site, true, releases.latest),
      notes: base([
        "If they tell you your site is already protected, ask them to confirm that in writing.",
      ]),
    };
  }

  // Vulnerable to php2shell.
  if (vulnPhp2shell) {
    return {
      level: "high",
      verdict: "Act today — your site is at risk",
      headline: `Your site runs ${label}, which needs updating`,
      confidence,
      summary:
        "Your website is running a version of PHP affected by this security issue. Until it's updated, hackers could potentially take control of your site.",
      actions: [
        "Send the message below to your hosting company or web developer today.",
        "Ask them to update your PHP to a safe version as soon as possible.",
        "If they can't do it today, ask them to take the site offline until they can.",
      ],
      contactMessage: hostMessage(site, true, releases.latest),
      notes: base([
        "If they tell you your site is already protected, ask them to confirm that in writing.",
      ]),
    };
  }

  // Branch known but exact release not visible.
  if (!full) {
    return {
      level: "high",
      verdict: "Act today to be safe",
      headline: `Your site runs ${label}, but we couldn't confirm the exact version`,
      confidence: "low",
      summary:
        "We can see roughly which PHP your site uses, but not exactly — so we can't be sure it's up to date. With a serious issue going around, it's safest to check today.",
      actions: [
        "Send the message below to your hosting company or web developer today.",
        "Ask them to confirm your PHP is on the latest version, and update it if not.",
      ],
      contactMessage: hostMessage(site, true, releases.latest),
      notes: base(),
    };
  }

  // Safe from php2shell but behind the latest release.
  if (outdated) {
    return {
      level: "medium",
      verdict: "You're safe for now, but update soon",
      headline: `Your site runs ${label} — safe from this issue, but a bit out of date`,
      confidence,
      summary:
        "Good news: your site is protected against this particular issue. But it's not on the very latest version of PHP, which means it's missing some other security updates. It's worth updating soon — this isn't urgent.",
      actions: [
        "No emergency action needed today.",
        "When you have a moment, send the message below to your hosting company or web developer.",
      ],
      contactMessage: hostMessage(site, false, releases.latest),
      notes: base(),
    };
  }

  // Up to date.
  return {
    level: "low",
    verdict: "You're all good — no action needed",
    headline: `Your site runs ${label}, which is up to date`,
    confidence,
    summary:
      "Your website is on the latest version of PHP and is protected against this security issue. Nothing to do right now.",
    actions: [
      "No action needed.",
      "Keep letting your host or developer apply updates as they come out.",
    ],
    notes: base(),
  };
}

async function scan(input) {
  const u = normaliseUrl(input);
  let main;
  try {
    main = await safeGet(u.href);
  } catch (e) {
    if (e instanceof UserError) throw e;
    if (u.protocol === "https:") {
      // Fall back to plain http for sites without TLS.
      try {
        u.protocol = "http:";
        main = await safeGet(u.href);
      } catch (e2) {
        if (e2 instanceof UserError) throw e2;
        throw new UserError("The site didn't respond. It may be down, or it may be blocking automated checks.");
      }
    } else {
      throw new UserError("The site didn't respond. It may be down, or it may be blocking automated checks.");
    }
  }

  // Standard, benign paths that commonly leak a PHP version or confirm a PHP
  // app. These are ordinary GET requests to well-known public URLs — no
  // payloads, nothing exploit-like. A random path triggers a 404 page, which
  // often carries the Server/X-Powered-By version banner.
  const probePaths = [
    "/index.php",
    "/wp-login.php",
    "/administrator/",
    "/user/login",
    "/robots.txt",
    "/php2shell-check-" + Math.random().toString(36).slice(2, 10),
  ];
  const probes = (
    await Promise.all(
      probePaths.map((p) =>
        safeGet(new URL(p, main.finalUrl).href).catch(() => null)
      )
    )
  ).filter(Boolean);

  const det = detectPhp(main, probes);
  const cdn = behindCdn(main.hops);
  const releases = await getSupportedReleases();
  return {
    url: main.finalUrl,
    scannedAt: new Date().toISOString(),
    detection: {
      ...det,
      version: det.version ? det.version.raw : null,
      cdn,
      pathsChecked: probePaths.length + 1,
    },
    assessment: assess(det, cdn, releases, main.finalUrl),
    advisory: {
      ...ADVISORY,
      php2shellFixed: PHP2SHELL_FIXED,
      currentReleases: releases.latest,
      versionsLive: releases.live,
    },
  };
}

// ---------- HTTP server ----------

const PUBLIC = path.join(__dirname, "public");
const INDEX = path.join(PUBLIC, "index.html");

// Static files we serve by name. The .php script is served as plain text so the
// browser shows/saves the source rather than trying to execute it.
const STATIC = {
  "/self-check": { file: "self-check.html", type: "text/html; charset=utf-8" },
  "/php2shell-selfcheck.php": {
    file: "php2shell-selfcheck.php",
    type: "text/plain; charset=utf-8",
    download: true,
  },
};

// Simple per-IP rate limit so the checker can't be used as a scanner farm.
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 60_000);
  list.push(now);
  hits.set(ip, list);
  return list.length > 10;
}

function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      fs.createReadStream(INDEX).pipe(res);
      return;
    }
    if (req.method === "GET" && STATIC[url.pathname]) {
      const s = STATIC[url.pathname];
      const headers = { "Content-Type": s.type };
      if (s.download) headers["Content-Disposition"] = `attachment; filename="${s.file}"`;
      res.writeHead(200, headers);
      fs.createReadStream(path.join(PUBLIC, s.file)).pipe(res);
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/scan") {
      if (rateLimited(req.socket.remoteAddress)) {
        return sendJson(res, 429, { error: "Too many checks. Wait a minute and try again." });
      }
      try {
        sendJson(res, 200, await scan(url.searchParams.get("url")));
      } catch (e) {
        if (e instanceof UserError) return sendJson(res, 400, { error: e.message });
        console.error(e);
        sendJson(res, 500, { error: "Something went wrong while checking that site." });
      }
      return;
    }
    res.writeHead(404).end("Not found");
  })
  .listen(PORT, () => console.log(`php2shell checker on http://localhost:${PORT}`));
