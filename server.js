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

function assess(det, cdn, releases) {
  const v = det.version;
  const liveNote = releases.live
    ? null
    : "We couldn't reach php.net for the latest version list, so we used the built-in list from 21 October 2026. It may be out of date.";
  const cdnNote = cdn
    ? `The site is behind ${cdn}. Some CDNs/WAFs have pushed emergency rules, but those are not a substitute for patching.`
    : null;
  const base = (extra = []) => [...extra, liveNote, cdnNote].filter(Boolean);

  if (!det.usesPhp) {
    return {
      level: "low",
      verdict: "Safe to keep online",
      headline: "No sign of PHP found",
      summary:
        "We found no public sign that this site runs PHP. Many sites hide it, though, so this is not proof. If you aren't sure what your site is built on, ask your developer or hosting company.",
      actions: [
        "Confirm with your host or developer that no PHP runs on this server (including admin panels, contact forms or subdomains).",
        "If PHP does run, keep it on a current, supported release.",
      ],
      notes: base(),
    };
  }

  const platformBit = det.platform ? ` (${det.platform})` : "";

  if (!v) {
    return {
      level: "high",
      verdict: "Patch today. If you can't, take the site offline",
      headline: `Runs PHP${platformBit}, but the version is hidden`,
      confidence: "low",
      summary:
        "This site runs PHP, but it hides the version number, so we can't tell whether it is patched. Until you have confirmed it, treat it as vulnerable. CERT-EU says all versions from PHP 5 onward may be affected by php2shell.",
      actions: [
        "Ask your hosting company or developer which PHP version is running and whether it includes the 21 October 2026 security fix.",
        `Make sure it's on a current release: ${Object.values(releases.latest).join(", ")} or newer.`,
        "If you can't confirm quickly, CERT-EU advises taking the site offline until you can.",
      ],
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

  if (status === "eol") {
    return {
      level: "critical",
      verdict: "Take offline, or upgrade now",
      headline: `${label}: end-of-life`,
      confidence,
      summary: `PHP ${branch} no longer receives security updates. It will not get a fix for php2shell or any future flaw, so the server is exposed to unauthenticated remote code execution.`,
      actions: [
        "Take the site offline, or put it into maintenance mode, until PHP is upgraded.",
        `Upgrade to a supported branch on a current release: ${Object.values(releases.latest).join(", ")} or newer.`,
        "Test your site on the new version before bringing it back online. Old plugins and themes can break.",
        "Check the server for signs of compromise: unknown files, new admin users, web processes spawning shells.",
      ],
      notes: base([
        "Some Linux distributions (RHEL, Debian LTS) backport fixes to old PHP, so the version can look EOL but still be supported. Confirm with your host.",
      ]),
    };
  }

  if (vulnPhp2shell) {
    return {
      level: "high",
      verdict: "Patch today. If you can't, take the site offline",
      headline: `${label}: vulnerable to php2shell`,
      confidence,
      summary: `This is older than ${floor}, the release that fixes php2shell on PHP ${branch}. It is exposed to unauthenticated remote code execution.`,
      actions: [
        `Upgrade PHP to ${latest || floor} or newer today. Most hosts let you do this from the control panel, or will do it if you ask.`,
        "If you can't patch quickly, CERT-EU advises taking the site offline until you can.",
        "Interim hardening only (not a fix): set session.upload_progress.enabled = 0 and session.use_strict_mode = 1, then restart PHP-FPM.",
        "After patching, check for signs of compromise: unknown files, new admin users, web processes spawning shells.",
      ],
      notes: base([
        "Your host may backport fixes without changing the version number. If they say you're patched, ask them to confirm it in writing.",
      ]),
    };
  }

  if (!full) {
    return {
      level: "high",
      verdict: "Check your exact version",
      headline: `${label}: patch level unknown`,
      confidence: "low",
      summary: `We can see the ${branch} branch but not the exact release. The current release is ${latest || floor}.`,
      actions: [
        `Confirm the server runs ${latest || floor} or newer.`,
        "If it's behind and you can't update quickly, take the site offline.",
      ],
      notes: base(),
    };
  }

  if (outdated) {
    return {
      level: "medium",
      verdict: "Update available — plan an upgrade",
      headline: `${label}: patched against php2shell, but out of date`,
      confidence,
      summary: `This is safe from php2shell, but PHP ${branch} has since moved on to ${latest}. Older releases miss later security fixes, so update when you can.`,
      actions: [
        `Update PHP to ${latest} to pick up the latest security fixes.`,
        "This isn't an emergency for php2shell, but don't leave it for months.",
      ],
      notes: base(),
    };
  }

  return {
    level: "low",
    verdict: "Safe to keep online",
    headline: `${label}: up to date`,
    confidence,
    summary: `This is the current release for PHP ${branch}${latest ? ` (${latest})` : ""}, and it includes the php2shell fix.`,
    actions: [
      "No action needed right now. Keep applying PHP updates as they're released.",
      "Hide the version header (expose_php = Off in php.ini) so attackers can't fingerprint your server.",
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
    assessment: assess(det, cdn, releases),
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
