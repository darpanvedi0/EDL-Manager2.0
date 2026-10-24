<?php
// tests/run.php - Unit tests for the request service, API keys, fetch
// tracking, and metrics. They use a temporary data directory, not a web
// server. Run: php tests/run.php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

error_reporting(E_ALL);
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false; // silenced with @
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

$tmp = sys_get_temp_dir() . '/edl-tests-' . bin2hex(random_bytes(4));
mkdir("$tmp/data", 0700, true);
mkdir("$tmp/lists", 0700, true);
define('DATA_DIR', "$tmp/data");
define('EDL_FILES_DIR', "$tmp/lists");
define('APP_VERSION', 'test');

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/requests.php';
require_once __DIR__ . '/../includes/api_keys.php';
require_once __DIR__ . '/../includes/metrics.php';

$checks = 0;
$failures = 0;

function check($condition, $message) {
    global $checks, $failures;
    $checks++;
    if (!$condition) {
        $failures++;
        echo "  FAIL $message\n";
    }
}

function same($expected, $actual, $message) {
    check($expected === $actual, $message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')');
}

function test($name, callable $body) {
    global $failures;
    foreach (array_merge(glob(DATA_DIR . '/{,.}*.json', GLOB_BRACE), glob(EDL_FILES_DIR . '/*')) as $file) {
        unlink($file);
    }
    $before = $failures;
    try {
        $body();
    } catch (Throwable $e) {
        check(false, get_class($e) . ': ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
    }
    echo ($failures === $before ? 'ok   ' : 'FAIL ') . $name . "\n";
}

function submit(array $entries, array $fields = []) {
    $items = array_map(fn($e) => is_array($e) ? $e : ['entry' => $e], $entries);
    return edl_submit_requests($items, $fields + [
        'justification' => 'Test',
        'servicenow_ticket' => 'INC1234567',
        'priority' => 'high',
    ], 'api:test');
}

function list_file($type) {
    return (string) @file_get_contents(EDL_FILES_DIR . '/' . EDL_LIST_FILES[$type]);
}

// ------------------------------------------------------------ requests

test('detects entry types', function () {
    same('ip', edl_detect_type('198.51.100.7'), 'IPv4');
    same('ip', edl_detect_type('2001:db8::1'), 'IPv6');
    same('ip', edl_detect_type('10.0.0.0/24'), 'CIDR');
    same('domain', edl_detect_type('evil.example.com'), 'domain');
    same('url', edl_detect_type('https://bad.example.net/x'), 'URL');
    same(null, edl_detect_type('not valid!'), 'junk');
});

test('rejects submissions missing required fields', function () {
    $result = edl_submit_requests([['entry' => '198.51.100.7']], ['servicenow_ticket' => 'BAD1', 'priority' => 'urgent'], 'api:test');
    same(3, count($result['errors'] ?? []), 'justification, ticket, and priority errors');
    same(1, count(submit([])['errors'] ?? []), 'no entries');
    same(1, count(submit(array_fill(0, 501, '198.51.100.7'))['errors'] ?? []), 'more than 500 entries');
    same([], read_json_file(DATA_DIR . '/pending_requests.json'), 'nothing written');
});

test('queues valid entries and skips the rest with reasons', function () {
    $result = submit([
        '198.51.100.7',
        '198.51.100.7',
        'evil.example.com',
        ['entry' => '999.1.1.1', 'type' => 'ip'],
        'https://x.example.com/?a=1&b=2',
        'not valid!',
        ['entry' => 'evil.example.org', 'type' => 'hash'],
    ]);
    same(['198.51.100.7', 'evil.example.com'], array_column($result['created'], 'entry'), 'created entries');
    same(5, count($result['skipped']), 'skipped count');
    same('Duplicate in this submission', $result['skipped'][0]['reason'], 'duplicate reason');
    $created = $result['created'][0];
    same('api:test', $created['submitted_by'], 'submitter');
    same('bulk', $created['submission_type'], 'submission type');
    same('pending', $created['status'], 'status');
    same(2, count(read_json_file(DATA_DIR . '/pending_requests.json')), 'pending file');

    $again = submit(['198.51.100.7']);
    same([], $again['created'], 'pending entry not resubmitted');
    same('Already pending approval', $again['skipped'][0]['reason'], 'pending reason');
});

test('stores free text escaped, like the web form', function () {
    $result = submit(['198.51.100.7'], ['justification' => '<b>C2</b>', 'comment' => 'a & b']);
    same('&lt;b&gt;C2&lt;/b&gt;', $result['created'][0]['justification'], 'justification');
    same('a &amp; b', $result['created'][0]['comment'], 'comment');
});

test('approving publishes the entry and blocks a second decision', function () {
    $id = submit(['198.51.100.7'])['created'][0]['id'];
    $result = edl_decide_request($id, true, 'api:approver', 'confirmed');
    same('active', $result['record']['status'] ?? null, 'approved status');
    same('api:approver', $result['record']['approved_by'], 'approver');
    same($id, $result['record']['request_id'], 'request id kept');
    same('198.51.100.7', list_file('ip'), 'ip list');
    same([], read_json_file(DATA_DIR . '/pending_requests.json'), 'removed from pending');
    same('approved', edl_find_request($id)['status'], 'request status');
    same('conflict', edl_decide_request($id, true, 'api:approver', '')['error'] ?? null, 'second approval');
    same('not_found', edl_decide_request('req_missing', true, 'api:approver', '')['error'] ?? null, 'unknown request');
    same('Already in the blocklist', submit(['198.51.100.7'])['skipped'][0]['reason'], 'active entry not resubmitted');

    $log = read_json_file(DATA_DIR . '/audit_logs.json');
    same(['request_submitted', 'approve'], array_column($log, 'action'), 'audit log');
});

test('denying needs a reason and blocks resubmission', function () {
    $id = submit(['evil.example.com'])['created'][0]['id'];
    same('invalid', edl_decide_request($id, false, 'api:approver', ' ')['error'] ?? null, 'blank reason');
    $result = edl_decide_request($id, false, 'api:approver', 'false positive');
    same('false positive', $result['record']['reason'] ?? null, 'reason');
    same('denied', edl_find_request($id)['status'], 'request status');
    same('', list_file('domain'), 'domain list unchanged');
    same('Previously denied: false positive', submit(['evil.example.com'])['skipped'][0]['reason'], 'resubmission');
});

test('removing an entry republishes the list and allows resubmission', function () {
    $id = submit(['198.51.100.7', '203.0.113.9'])['created'][0]['id'];
    $entry = edl_decide_request($id, true, 'api:approver', '')['record'];
    $removed = edl_remove_entry($entry['id'], 'api:cleanup', 'expired');
    same('deleted', $removed['record']['status'] ?? null, 'status');
    same('expired', $removed['record']['deletion_reason'], 'reason');
    same('', list_file('ip'), 'ip list emptied');
    same('deleted', edl_find_request($id)['status'], 'request status');
    same('conflict', edl_remove_entry($entry['id'], 'api:cleanup', '')['error'] ?? null, 'second removal');
    same('not_found', edl_remove_entry('app_missing', 'api:cleanup', '')['error'] ?? null, 'unknown entry');
    same(1, count(submit(['198.51.100.7'])['created']), 'resubmitted');
});

test('write_edl_lists publishes only active entries, by type', function () {
    write_json_file(DATA_DIR . '/approved_entries.json', [
        ['id' => 'a', 'entry' => '198.51.100.7', 'type' => 'ip', 'status' => 'active'],
        ['id' => 'b', 'entry' => '203.0.113.9', 'type' => 'ip', 'status' => 'active'],
        ['id' => 'c', 'entry' => 'old.example.com', 'type' => 'domain', 'status' => 'deleted'],
        ['id' => 'd', 'entry' => 'https://bad.example.net/', 'type' => 'url', 'status' => 'active'],
    ]);
    $result = write_edl_lists();
    same(true, $result['written'], 'written');
    same([2, 0, 1, 3], [$result['ip_count'], $result['domain_count'], $result['url_count'], $result['total_active']], 'counts');
    same("198.51.100.7\n203.0.113.9", list_file('ip'), 'ip list');
    same('', list_file('domain'), 'domain list');
});

// ------------------------------------------------------------ API keys

test('API keys authenticate until revoked', function () {
    $created = api_key_create('xsoar', ['view', 'submit', 'bogus'], 'admin');
    same(['view', 'submit'], $created['key']['permissions'], 'unknown permissions dropped');
    check(!isset($created['key']['secret_hash']), 'public record has no hash');
    check((bool) preg_match('/^edl_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/', $created['token']), 'token format');

    same('xsoar', api_key_authenticate($created['token'])['name'] ?? null, 'valid token');
    same(null, api_key_authenticate(substr($created['token'], 0, -1) . 'A'), 'wrong secret');
    same(null, api_key_authenticate('edl_000000000000_' . str_repeat('A', 43)), 'unknown id');
    same(null, api_key_authenticate(null), 'no token');
    check(api_key_list()[0]['last_used_at'] !== null, 'last use recorded');

    check(api_key_revoke($created['key']['id'], 'admin'), 'revoke');
    same(null, api_key_authenticate($created['token']), 'revoked token');
    check(!api_key_revoke($created['key']['id'], 'admin'), 'second revoke');

    foreach ([['', ['view']], ['name', []]] as [$name, $permissions]) {
        try {
            api_key_create($name, $permissions, 'admin');
            check(false, 'invalid key accepted');
        } catch (InvalidArgumentException $e) {
            check(true, 'invalid key rejected');
        }
    }
});

// ------------------------------------------------------------ fetch tracking

test('fetch tracking records clients, versions, and intervals', function () {
    $t = 1700000000;
    $stats = fetch_stats_apply([], 'ip', $t, 3, '10.0.0.1', 'PAN-OS', $t + 10);
    same($t + 10, $stats['tracking_since']['ip'], 'tracking start');
    same(1, count($stats['clients']), 'one client');
    same([['published_at' => $t, 'entries' => 3, 'first_fetch_at' => $t + 10, 'first_fetch_by' => fetch_stats_client_id('10.0.0.1', 'PAN-OS')]],
        $stats['versions']['ip'], 'version recorded');

    check(!fetch_stats_needs_write($stats, 'ip', $t, '10.0.0.1', 'PAN-OS', $t + 30), 'repeat fetch within a minute skipped');
    check(fetch_stats_needs_write($stats, 'ip', $t + 20, '10.0.0.1', 'PAN-OS', $t + 30), 'new version recorded');
    check(fetch_stats_needs_write($stats, 'ip', $t, '10.0.0.2', 'PAN-OS', $t + 30), 'new client recorded');
    check(fetch_stats_needs_write($stats, 'domain', $t, '10.0.0.1', 'PAN-OS', $t + 30), 'new list recorded');

    $stats = fetch_stats_apply($stats, 'ip', $t, 3, '10.0.0.1', 'PAN-OS', $t + 310);
    $client = $stats['clients'][fetch_stats_client_id('10.0.0.1', 'PAN-OS')];
    same(300, $client['lists']['ip']['interval'], 'interval');
    same($t + 10, $client['lists']['ip']['first_seen'], 'first seen kept');
    same(1, count($stats['versions']['ip']), 'same version not duplicated');
});

test('fetch tracking caps clients and versions', function () {
    $stats = [];
    for ($i = 0; $i <= FETCH_STATS_MAX_CLIENTS; $i++) {
        $stats = fetch_stats_apply($stats, 'ip', 1000, 0, "10.0.$i.1", 'fw', 2000 + $i);
    }
    same(FETCH_STATS_MAX_CLIENTS, count($stats['clients']), 'client cap');
    check(!isset($stats['clients'][fetch_stats_client_id('10.0.0.1', 'fw')]), 'least recently seen client dropped');

    $stats = [];
    for ($i = 0; $i <= FETCH_STATS_MAX_VERSIONS; $i++) {
        $stats = fetch_stats_apply($stats, 'ip', 1000 + $i, 0, '10.0.0.1', 'fw', 5000 + $i);
    }
    same(FETCH_STATS_MAX_VERSIONS, count($stats['versions']['ip']), 'version cap');
    same(1000, $stats['pruned_before']['ip'], 'pruned marker');
});

test('fetch_stats_record writes the stats file and survives corruption', function () {
    fetch_stats_record('ip', 1000, 1, '10.0.0.1', "PAN-OS\x00\n");
    $stats = read_json_file(fetch_stats_file());
    same('PAN-OS', array_values($stats['clients'])[0]['user_agent'], 'control characters stripped');
    file_put_contents(fetch_stats_file(), '{broken');
    fetch_stats_record('ip', 1000, 1, '10.0.0.1', 'PAN-OS');
    same(1, count(read_json_file(fetch_stats_file())['clients']), 'corrupt file replaced');
});

// ------------------------------------------------------------ metrics

test('formats durations and percentiles', function () {
    same('45 s', edl_format_duration(45), 'seconds');
    same('2 min', edl_format_duration(90), 'minutes');
    same('1 h', edl_format_duration(3600), 'hour');
    same('1 h 2 min', edl_format_duration(3720), 'hours and minutes');
    same('1 d 1 h', edl_format_duration(90000), 'days');
    same('n/a', edl_format_duration(null), 'none');
    same(null, edl_percentile([], 50), 'empty percentile');
    same(5, edl_percentile([5], 90), 'single value');
    same(200, edl_percentile([600, 200], 50), 'median of two');
    same(600, edl_percentile([600, 200], 90), 'p90 of two');
});

test('computes time to block, time to enforcement, and firewall status', function () {
    $now = 1700000000;
    $iso = fn($offset) => date('c', $now + $offset);
    $in = [
        'approved' => [
            // Approved 10 min after submission; first fetch 100 s after approval.
            ['entry' => 'a', 'type' => 'ip', 'status' => 'active', 'priority' => 'high',
             'submitted_at' => date('Y-m-d H:i:s', $now - 3600), 'approved_at' => $iso(-3000)],
            // Approved 200 s after submission; first fetch 600 s after approval.
            ['entry' => 'b', 'type' => 'ip', 'status' => 'active', 'priority' => 'critical',
             'submitted_at' => $iso(-7200), 'approved_at' => $iso(-7000)],
            // Approved before tracking started: not measured for enforcement.
            ['entry' => 'c', 'type' => 'domain', 'status' => 'active', 'priority' => 'low',
             'submitted_at' => $iso(-9000), 'approved_at' => $iso(-8000)],
            // Removed before any firewall fetched it: not measured.
            ['entry' => 'd', 'type' => 'url', 'status' => 'deleted', 'priority' => 'medium',
             'submitted_at' => $iso(-5000), 'approved_at' => $iso(-4000), 'deleted_at' => $iso(-3900)],
            // Outside the 30-day window.
            ['entry' => 'e', 'type' => 'ip', 'status' => 'active', 'priority' => 'high',
             'submitted_at' => $iso(-40 * 86400), 'approved_at' => $iso(-40 * 86400 + 60)],
        ],
        'denied' => [
            ['entry' => 'f', 'type' => 'ip', 'submitted_at' => $iso(-500), 'denied_at' => $iso(-400)],
        ],
        'pending' => [
            ['entry' => 'g', 'type' => 'ip', 'status' => 'pending', 'submitted_at' => $iso(-600)],
        ],
        'fetch_stats' => [
            'tracking_since' => ['ip' => $now - 10000, 'domain' => $now - 5000, 'url' => $now - 10000],
            'pruned_before' => [],
            'versions' => [
                'ip' => [
                    ['published_at' => $now - 7000, 'entries' => 1, 'first_fetch_at' => $now - 6400, 'first_fetch_by' => 'x'],
                    ['published_at' => $now - 3000, 'entries' => 2, 'first_fetch_at' => $now - 2900, 'first_fetch_by' => 'x'],
                ],
                'domain' => [
                    ['published_at' => $now - 4000, 'entries' => 1, 'first_fetch_at' => $now - 3000, 'first_fetch_by' => 'x'],
                ],
                'url' => [
                    ['published_at' => $now - 3900, 'entries' => 0, 'first_fetch_at' => $now - 3800, 'first_fetch_by' => 'x'],
                ],
            ],
            'clients' => [
                'c1' => ['ip' => '10.0.0.1', 'user_agent' => 'fw', 'first_seen' => $now - 9000, 'last_seen' => $now - 100,
                         'lists' => ['ip' => ['first_seen' => $now - 9000, 'last_seen' => $now - 100, 'interval' => 300]]],
                'c2' => ['ip' => '10.0.0.2', 'user_agent' => 'fw', 'first_seen' => $now - 9000, 'last_seen' => $now - 5000,
                         'lists' => ['ip' => ['first_seen' => $now - 9000, 'last_seen' => $now - 5000, 'interval' => 300]]],
                'c3' => ['ip' => '10.0.0.3', 'user_agent' => 'curl', 'first_seen' => $now - 90000, 'last_seen' => $now - 90000,
                         'lists' => ['url' => ['first_seen' => $now - 90000, 'last_seen' => $now - 90000, 'interval' => null]]],
            ],
        ],
        'lists' => [
            'ip' => ['published_at' => $now - 3000, 'entries' => 2],
            'domain' => ['published_at' => $now - 4000, 'entries' => 1],
            'url' => null,
        ],
    ];
    $m = edl_compute_metrics($in, $now, 30);

    same(['total' => 4, 'ip' => 3, 'domain' => 1, 'url' => 0], $m['indicators']['active'], 'active indicators');
    same(4, $m['indicators']['added'], 'added in window');
    same(1, $m['indicators']['removed'], 'removed in window');
    same(['submitted' => 6, 'approved' => 4, 'denied' => 1, 'approval_rate' => 0.8, 'pending' => 1, 'oldest_pending_age_seconds' => 600],
        $m['requests'], 'requests');

    // 200, 600, 1000, 1000 seconds: nearest-rank median 600, p90 1000.
    same([4, 600, 1000], [$m['time_to_block']['count'], $m['time_to_block']['median_seconds'], $m['time_to_block']['p90_seconds']], 'time to block');
    same(600, $m['time_to_block']['by_priority']['high']['median_seconds'], 'high priority');
    same(200, $m['time_to_block']['by_priority']['critical']['median_seconds'], 'critical priority');

    same([2, 100, 600, 0.5], [
        $m['time_to_enforcement']['count'],
        $m['time_to_enforcement']['median_seconds'],
        $m['time_to_enforcement']['p90_seconds'],
        $m['time_to_enforcement']['coverage'],
    ], 'time to enforcement');
    same([2, 700, 800], [
        $m['request_to_enforcement']['count'],
        $m['request_to_enforcement']['median_seconds'],
        $m['request_to_enforcement']['p90_seconds'],
    ], 'request to enforcement');

    same([3, 1, 2], [$m['firewalls']['total'], $m['firewalls']['polling'], $m['firewalls']['stale']], 'firewall counts');
    same('10.0.0.1', $m['firewalls']['clients'][0]['ip'], 'most recent client first');
    same(false, $m['firewalls']['clients'][0]['stale'], 'polling client');

    same(true, $m['lists']['ip']['current_version_fetched'], 'current ip version fetched');
    same(2, $m['lists']['ip']['clients_last_24h'], 'ip clients in 24 h');
    same(null, $m['lists']['url']['entries'], 'missing list');

    $summary = implode("\n", $m['summary']);
    check(strpos($summary, 'Blocked right now: 4 indicators (3 IP addresses, 1 domain, 0 URLs).') !== false, 'summary: blocked');
    check(strpos($summary, 'Request to approval: median 10 min, 90% within 17 min.') !== false, 'summary: time to block');
    check(strpos($summary, 'Firewall clients polling the lists: 1 (2 more stopped polling).') !== false, 'summary: firewalls');
});

test('reports no data rather than zeros when nothing is measured', function () {
    $m = edl_compute_metrics(['approved' => [], 'denied' => [], 'pending' => [], 'fetch_stats' => [], 'lists' => []], 1700000000, 7);
    same(null, $m['time_to_block']['median_seconds'], 'no time to block');
    same(null, $m['time_to_enforcement']['coverage'], 'no coverage');
    same(null, $m['requests']['approval_rate'], 'no approval rate');
    same(false, $m['firewalls']['tracking'], 'not tracking');
    check(in_array('No firewall fetches recorded yet.', $m['summary'], true), 'summary says so');
});

// ------------------------------------------------------------ done

array_map('unlink', array_filter(array_merge(glob("$tmp/data/{,.}*", GLOB_BRACE) ?: [], glob("$tmp/lists/*") ?: []), 'is_file'));
@rmdir("$tmp/data");
@rmdir("$tmp/lists");
@rmdir($tmp);

echo "\n$checks checks, $failures failed\n";
exit($failures ? 1 : 0);
