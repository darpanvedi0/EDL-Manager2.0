<?php
// feed.php - Serve a blocklist to firewalls and record the fetch for the
// Impact page.
//
// The Docker image routes /edl-files/ip_blocklist.txt (and the domain and URL
// lists) here, so firewall URLs don't change. On other installs, point
// firewalls at feed.php?list=ip|domain|url or add the rewrite in README.md.

define('EDL_NO_SESSION', true);
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/edl_lists.php';
require_once __DIR__ . '/includes/fetch_stats.php';

$list = is_string($_GET['list'] ?? null) ? $_GET['list'] : '';
$path = isset(EDL_LIST_FILES[$list]) ? EDL_FILES_DIR . '/' . EDL_LIST_FILES[$list] : null;
$body = $path !== null ? @file_get_contents($path) : false;

if ($body === false) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Unknown list\n";
    exit;
}

clearstatcache(true, $path);
$published_at = filemtime($path);
$etag = '"' . sha1($body) . '"';

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache');
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $published_at) . ' GMT');
header('ETag: ' . $etag);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET') {
    $entries = $body === '' ? 0 : substr_count($body, "\n") + 1;
    fetch_stats_record($list, $published_at, $entries, $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
}

$if_none_match = $_SERVER['HTTP_IF_NONE_MATCH'] ?? null;
$if_modified_since = isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) ? strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) : false;
if (($if_none_match !== null && trim($if_none_match) === $etag)
    || ($if_none_match === null && $if_modified_since !== false && $if_modified_since >= $published_at)) {
    http_response_code(304);
    exit;
}

header('Content-Length: ' . strlen($body));
if ($method !== 'HEAD') {
    echo $body;
}
