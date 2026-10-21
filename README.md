# PHP Risk Check (php2shell)

Enter a website and get a risk level for CVE-2026-109618 / CVE-2026-109619 ("php2shell"), plus a clear verdict: keep online, patch now, or take offline.

Run: `node server.js` (Node 18+, no dependencies), then open http://localhost:3000. Set `PORT` to change the port.

The check is passive. It requests the homepage and `/index.php`, then reads the `X-Powered-By`/`Server` headers, `PHPSESSID` cookies and CMS fingerprints.
It blocks private/internal addresses (SSRF guard) and limits each IP to 10 checks per minute.

Update `FIXED` in `server.js` once php.net publishes the official fixed versions.
