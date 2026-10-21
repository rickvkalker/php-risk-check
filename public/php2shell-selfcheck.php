<?php
/**
 * php2shell self-check  --  CVE-2026-109618 / CVE-2026-109619
 *
 * Upload this file to your own website, then open it in a browser
 * (e.g. https://yoursite.com/php2shell-selfcheck.php). It reads the PHP
 * version and settings on THIS server and tells you if you're patched.
 *
 * It only reads local information. It changes nothing and attacks nothing.
 *
 * DELETE this file once you're done -- leaving diagnostic scripts online
 * is itself a small risk.
 *
 * Fixed versions below are from reporting around the 21 Oct 2026 release.
 * Confirm against https://www.php.net/ and edit if they differ.
 */

$FIXED = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];

$v = PHP_VERSION;                 // e.g. "8.3.30"
$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$sapi = PHP_SAPI;                 // fpm-fcgi, apache2handler, cgi-fcgi, cli...

$status = 'unknown';
$headline = '';
$detail = '';

if (PHP_MAJOR_VERSION < 8 || ($branch === '8.0' || $branch === '8.1')) {
    $status = 'critical';
    $headline = "PHP $v is end-of-life";
    $detail = "This branch no longer gets security fixes, so it will NOT be patched for php2shell. "
            . "Upgrade to a supported branch (8.2+) or take the site offline.";
} elseif (!isset($FIXED[$branch])) {
    if (version_compare($v, '8.5.0', '>=')) {
        $status = 'ok';
        $headline = "PHP $v is newer than the affected branches";
        $detail = "Keep applying security releases as normal.";
    } else {
        $status = 'critical';
        $headline = "PHP $v is end-of-life";
        $detail = "No fix is coming for this branch. Upgrade to 8.2+ or take the site offline.";
    }
} elseif (version_compare($v, $FIXED[$branch], '>=')) {
    $status = 'ok';
    $headline = "PHP $v is patched";
    $detail = "This is at or above $FIXED[$branch], the fixed release for the $branch branch. "
            . "Note: if your Linux distribution backports fixes, the number may stay the same "
            . "but still include the fix -- this check trusts the running version.";
} else {
    $status = 'vulnerable';
    $headline = "PHP $v is VULNERABLE";
    $detail = "The fixed release for $branch is $FIXED[$branch]. Upgrade today, or take the site "
            . "offline until you can. IMPORTANT: your distro may have backported the fix without "
            . "changing the version number -- if you applied updates today, confirm with your host "
            . "before assuming you're exposed.";
}

// Interim hardening settings (not a fix, but reduce exposure).
$uploadProgress = ini_get('session.upload_progress.enabled');
$strictMode = ini_get('session.use_strict_mode');
$exposePhp = ini_get('expose_php');

$colors = ['ok' => '#067647', 'vulnerable' => '#b54708', 'critical' => '#b42318', 'unknown' => '#6b6a66'];
$labels = ['ok' => 'PATCHED', 'vulnerable' => 'VULNERABLE', 'critical' => 'CRITICAL', 'unknown' => 'UNKNOWN'];
$c = $colors[$status];

header('Content-Type: text/html; charset=utf-8');
?><!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>php2shell self-check</title>
<style>
  body{font:16px/1.55 system-ui,sans-serif;max-width:620px;margin:40px auto;padding:0 16px;color:#1d1d1b;background:#f6f5f2}
  .badge{display:inline-block;font-weight:700;color:#fff;background:<?= $c ?>;padding:4px 12px;border-radius:6px;letter-spacing:.05em}
  h1{font-size:24px;margin:14px 0 4px}
  .card{background:#fff;border:1px solid #e3e1dc;border-radius:12px;padding:20px;margin-top:16px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  td{padding:6px 0;border-bottom:1px solid #eee}
  td:first-child{color:#6b6a66}
  code{background:#f0efec;padding:1px 5px;border-radius:4px}
  .warn{color:#b42318;font-weight:600}
</style></head><body>
  <span class="badge"><?= $labels[$status] ?></span>
  <h1><?= htmlspecialchars($headline) ?></h1>
  <p><?= htmlspecialchars($detail) ?></p>

  <div class="card">
    <table>
      <tr><td>PHP version</td><td><code><?= htmlspecialchars($v) ?></code></td></tr>
      <tr><td>Branch</td><td><code><?= htmlspecialchars($branch) ?></code></td></tr>
      <tr><td>Fixed release for branch</td><td><code><?= htmlspecialchars($FIXED[$branch] ?? 'n/a (EOL)') ?></code></td></tr>
      <tr><td>Server interface (SAPI)</td><td><code><?= htmlspecialchars($sapi) ?></code></td></tr>
      <tr><td>session.upload_progress.enabled</td><td><?= $uploadProgress ? '<span class="warn">on</span>' : 'off' ?></td></tr>
      <tr><td>session.use_strict_mode</td><td><?= $strictMode ? 'on' : '<span class="warn">off</span>' ?></td></tr>
      <tr><td>expose_php</td><td><?= $exposePhp ? '<span class="warn">on (version is public)</span>' : 'off' ?></td></tr>
    </table>
  </div>

  <div class="card">
    <strong>Next steps</strong>
    <ol>
      <li>If this says VULNERABLE or CRITICAL, upgrade PHP now, or take the site offline until you can.</li>
      <li>Interim hardening (not a fix): set <code>session.upload_progress.enabled = 0</code> and
          <code>session.use_strict_mode = 1</code> in php.ini, then restart PHP-FPM.</li>
      <li><strong>Delete this file</strong> (<code>php2shell-selfcheck.php</code>) when you're finished.</li>
    </ol>
  </div>
</body></html>
