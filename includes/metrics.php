<?php
// includes/metrics.php - Impact metrics: how fast blocks are approved, how
// fast they reach firewalls, and which firewalls are polling.
//
// edl_compute_metrics() is a pure function of the data passed in, so it can
// be tested without files; edl_collect_metrics() reads the data directory.

require_once __DIR__ . '/edl_lists.php';
require_once __DIR__ . '/fetch_stats.php';

const METRICS_PRIORITIES = ['critical', 'high', 'medium', 'low'];

// A client counts as stale after this many of its usual polling intervals.
const METRICS_STALE_INTERVALS = 3;

function edl_metrics_inputs() {
    $lists = [];
    foreach (EDL_LIST_FILES as $type => $file) {
        $path = EDL_FILES_DIR . '/' . $file;
        $body = is_file($path) ? @file_get_contents($path) : false;
        $lists[$type] = $body === false ? null : [
            'published_at' => filemtime($path),
            'entries' => $body === '' ? 0 : substr_count($body, "\n") + 1,
        ];
    }
    return [
        'pending' => read_json_file(DATA_DIR . '/pending_requests.json') ?: [],
        'approved' => read_json_file(DATA_DIR . '/approved_entries.json') ?: [],
        'denied' => read_json_file(DATA_DIR . '/denied_entries.json') ?: [],
        'fetch_stats' => read_json_file(fetch_stats_file()) ?: [],
        'lists' => $lists,
    ];
}

function edl_collect_metrics($days) {
    return edl_compute_metrics(edl_metrics_inputs(), time(), $days);
}

// Unix time for a stored timestamp (ISO 8601 or "Y-m-d H:i:s"), or null.
function edl_timestamp($value) {
    if ($value === null || $value === '') {
        return null;
    }
    if (is_int($value)) {
        return $value;
    }
    $time = strtotime((string) $value);
    return $time === false ? null : $time;
}

// Nearest-rank percentile, or null for no values.
function edl_percentile(array $values, $percent) {
    if (!$values) {
        return null;
    }
    sort($values);
    $rank = (int) ceil($percent / 100 * count($values));
    return $values[max(0, $rank - 1)];
}

function edl_duration_stats(array $seconds) {
    return [
        'count' => count($seconds),
        'median_seconds' => edl_percentile($seconds, 50),
        'p90_seconds' => edl_percentile($seconds, 90),
    ];
}

function edl_format_duration($seconds) {
    if ($seconds === null) {
        return 'n/a';
    }
    $seconds = (int) round($seconds);
    if ($seconds < 60) {
        return $seconds . ' s';
    }
    if ($seconds < 3600) {
        return round($seconds / 60) . ' min';
    }
    if ($seconds < 86400) {
        $minutes = (int) round(($seconds % 3600) / 60);
        return intdiv($seconds, 3600) . ' h' . ($minutes ? " $minutes min" : '');
    }
    $hours = (int) round(($seconds % 86400) / 3600);
    return intdiv($seconds, 86400) . ' d' . ($hours ? " $hours h" : '');
}

function edl_iso($time) {
    return $time === null ? null : date('c', $time);
}

/**
 * Compute the metrics for the $days days before $now.
 *
 * $in holds 'pending', 'approved', and 'denied' records as stored,
 * 'fetch_stats' as written by fetch_stats_apply(), and 'lists' mapping each
 * list type to ['published_at', 'entries'] (or null if the file is missing).
 */
function edl_compute_metrics(array $in, $now, $days) {
    $from = $now - $days * 86400;
    $in_window = fn($time) => $time !== null && $time >= $from && $time <= $now;
    $stats = $in['fetch_stats'] + ['tracking_since' => [], 'pruned_before' => [], 'clients' => [], 'versions' => []];

    // Indicators and request volume
    $active = ['ip' => 0, 'domain' => 0, 'url' => 0];
    $removed = $approved = $submitted = 0;
    $time_to_block = [];
    $by_priority = array_fill_keys(METRICS_PRIORITIES, []);
    $time_to_enforce = [];
    $end_to_end = [];

    foreach ($in['approved'] as $entry) {
        $type = $entry['type'] ?? '';
        if (($entry['status'] ?? '') === 'active' && isset($active[$type])) {
            $active[$type]++;
        }
        $submitted_at = edl_timestamp($entry['submitted_at'] ?? null);
        $approved_at = edl_timestamp($entry['approved_at'] ?? null);
        $deleted_at = edl_timestamp($entry['deleted_at'] ?? null);
        if ($in_window($submitted_at)) {
            $submitted++;
        }
        if ($in_window($deleted_at)) {
            $removed++;
        }
        if (!$in_window($approved_at)) {
            continue;
        }
        $approved++;

        if ($submitted_at !== null && $approved_at >= $submitted_at) {
            $time_to_block[] = $approved_at - $submitted_at;
            $priority = $entry['priority'] ?? '';
            if (isset($by_priority[$priority])) {
                $by_priority[$priority][] = $approved_at - $submitted_at;
            }
        }

        // Enforcement: the first fetch of any version of the entry's list
        // published at or after the approval. Only counted when tracking
        // covered the whole time since the approval.
        $since = $stats['tracking_since'][$type] ?? null;
        $pruned = $stats['pruned_before'][$type] ?? null;
        if ($since === null || $approved_at < $since || ($pruned !== null && $approved_at <= $pruned)) {
            continue;
        }
        $first_fetch = null;
        foreach ($stats['versions'][$type] ?? [] as $version) {
            if ($version['published_at'] >= $approved_at
                && ($first_fetch === null || $version['first_fetch_at'] < $first_fetch)) {
                $first_fetch = $version['first_fetch_at'];
            }
        }
        if ($first_fetch === null || ($deleted_at !== null && $deleted_at < $first_fetch)) {
            continue;
        }
        $time_to_enforce[] = $first_fetch - $approved_at;
        if ($submitted_at !== null && $first_fetch >= $submitted_at) {
            $end_to_end[] = $first_fetch - $submitted_at;
        }
    }

    $denied = 0;
    foreach ($in['denied'] as $record) {
        if ($in_window(edl_timestamp($record['submitted_at'] ?? null))) {
            $submitted++;
        }
        if ($in_window(edl_timestamp($record['denied_at'] ?? null))) {
            $denied++;
        }
    }

    $pending = 0;
    $oldest_pending = null;
    foreach ($in['pending'] as $request) {
        if (($request['status'] ?? 'pending') !== 'pending') {
            continue;
        }
        $pending++;
        $submitted_at = edl_timestamp($request['submitted_at'] ?? null);
        if ($in_window($submitted_at)) {
            $submitted++;
        }
        if ($submitted_at !== null && ($oldest_pending === null || $submitted_at < $oldest_pending)) {
            $oldest_pending = $submitted_at;
        }
    }

    // Firewall clients
    $clients = [];
    $polling = $stale = 0;
    foreach ($stats['clients'] as $client) {
        $intervals = array_filter(array_column($client['lists'], 'interval'));
        $interval = $intervals ? min($intervals) : null;
        $expected = $interval ? max(METRICS_STALE_INTERVALS * $interval, 3600) : 86400;
        $is_stale = $now - $client['last_seen'] > $expected;
        if ($is_stale) {
            $stale++;
        } else {
            $polling++;
        }
        $clients[] = [
            'ip' => $client['ip'],
            'user_agent' => $client['user_agent'],
            'lists' => array_keys($client['lists']),
            'first_seen' => edl_iso($client['first_seen']),
            'last_seen' => edl_iso($client['last_seen']),
            'typical_interval_seconds' => $interval,
            'stale' => $is_stale,
        ];
    }
    usort($clients, fn($a, $b) => strcmp($b['last_seen'], $a['last_seen']));

    // Lists
    $lists = [];
    foreach ($in['lists'] as $type => $file) {
        $last_fetch = null;
        $clients_24h = 0;
        foreach ($stats['clients'] as $client) {
            $seen = $client['lists'][$type]['last_seen'] ?? null;
            if ($seen !== null) {
                $last_fetch = max($last_fetch ?? 0, $seen);
                $clients_24h += $now - $seen <= 86400 ? 1 : 0;
            }
        }
        $current_fetched = false;
        foreach ($stats['versions'][$type] ?? [] as $version) {
            if ($file && $version['published_at'] === $file['published_at']) {
                $current_fetched = true;
            }
        }
        $lists[$type] = [
            'entries' => $file['entries'] ?? null,
            'published_at' => edl_iso($file['published_at'] ?? null),
            'last_fetch_at' => edl_iso($last_fetch),
            'clients_last_24h' => $clients_24h,
            'current_version_fetched' => $current_fetched,
        ];
    }

    $metrics = [
        'generated_at' => edl_iso($now),
        'window' => ['days' => $days, 'from' => edl_iso($from), 'to' => edl_iso($now)],
        'indicators' => [
            'active' => ['total' => array_sum($active)] + $active,
            'added' => $approved,
            'removed' => $removed,
        ],
        'requests' => [
            'submitted' => $submitted,
            'approved' => $approved,
            'denied' => $denied,
            'approval_rate' => $approved + $denied ? round($approved / ($approved + $denied), 3) : null,
            'pending' => $pending,
            'oldest_pending_age_seconds' => $oldest_pending === null ? null : $now - $oldest_pending,
        ],
        'time_to_block' => edl_duration_stats($time_to_block) + [
            'by_priority' => array_map('edl_duration_stats', $by_priority),
        ],
        'time_to_enforcement' => edl_duration_stats($time_to_enforce) + [
            'coverage' => $approved ? round(count($time_to_enforce) / $approved, 3) : null,
        ],
        'request_to_enforcement' => edl_duration_stats($end_to_end),
        'firewalls' => [
            'tracking' => (bool) $stats['tracking_since'],
            'total' => count($clients),
            'polling' => $polling,
            'stale' => $stale,
            'clients' => $clients,
        ],
        'lists' => $lists,
    ];
    $metrics['summary'] = edl_metrics_summary($metrics);
    return $metrics;
}

function edl_plural($count, $singular, $plural = null) {
    return $count . ' ' . ($count === 1 ? $singular : ($plural ?? $singular . 's'));
}

/**
 * Plain-language lines for the report. Only states what the data shows.
 */
function edl_metrics_summary(array $m) {
    $active = $m['indicators']['active'];
    $lines = [
        'Blocked right now: ' . edl_plural($active['total'], 'indicator') . ' ('
            . edl_plural($active['ip'], 'IP address', 'IP addresses') . ', '
            . edl_plural($active['domain'], 'domain') . ', '
            . edl_plural($active['url'], 'URL') . ').',
    ];

    $requests = $m['requests'];
    $lines[] = "Last {$m['window']['days']} days: " . edl_plural($requests['approved'], 'request')
        . ' approved, ' . $requests['denied'] . ' denied.';

    $block = $m['time_to_block'];
    if ($block['count']) {
        $lines[] = 'Request to approval: median ' . edl_format_duration($block['median_seconds'])
            . ', 90% within ' . edl_format_duration($block['p90_seconds']) . '.';
    }

    $enforce = $m['time_to_enforcement'];
    if ($enforce['count']) {
        $lines[] = 'Approval to the first firewall pulling the updated list: median '
            . edl_format_duration($enforce['median_seconds']) . ', 90% within '
            . edl_format_duration($enforce['p90_seconds']) . '.';
        $end_to_end = $m['request_to_enforcement'];
        if ($end_to_end['count']) {
            $lines[] = 'Request to enforcement on a firewall: median ' . edl_format_duration($end_to_end['median_seconds']) . '.';
        }
    }

    $firewalls = $m['firewalls'];
    if ($firewalls['total']) {
        $lines[] = 'Firewall clients polling the lists: ' . $firewalls['polling']
            . ($firewalls['stale'] ? ' (' . $firewalls['stale'] . ' more stopped polling).' : '.');
    } else {
        $lines[] = 'No firewall fetches recorded yet.';
    }

    return $lines;
}
