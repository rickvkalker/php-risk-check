# PHP Risk Check (php2shell)

Enter a website and get a risk level for CVE-2026-109618 / CVE-2026-109619 ("php2shell"), plus a clear verdict: keep online, patch now, or take offline.

Run: `node server.js` (Node 18+, no dependencies), then open http://localhost:3000. Set `PORT` to change the port.

The check is passive. It requests the homepage and `/index.php`, then reads the `X-Powered-By`/`Server` headers, `PHPSESSID` cookies and CMS fingerprints.
It blocks private/internal addresses (SSRF guard) and limits each IP to 10 checks per minute.

The current release list is fetched live from php.net (cached 24h) and falls back to the built-in
`PHP2SHELL_FIXED` snapshot if php.net is unreachable. Keep that snapshot roughly current as a floor.

## Two levels of check

1. **Quick check (`/`)** — passive. Loads several standard pages (homepage, `/index.php`,
   `/wp-login.php`, `/administrator/`, `/user/login`, a 404 page) and reads the PHP version,
   session cookie, web server and CMS from the responses. Never sends anything exploit-like.
2. **Self-check (`/self-check`)** — definitive. Serves `php2shell-selfcheck.php` for the site
   owner to upload to their own server; it reads the local PHP version and php.ini settings
   and reports Patched / Vulnerable / Critical.

The self-check PHP script shares the `FIXED` version list; update both when php.net confirms the numbers.
