<?php
// includes/fetch_stats.php - Record which clients fetch the blocklists.
//
// feed.php calls fetch_stats_record() for each list download. The stats file
// keeps one row per client (address + user agent) and the first fetch of each
// published version of each list. The metrics page uses those to show which
// firewalls are polling and how fast approvals reach them.

const FETCH_STATS_MAX_CLIENTS = 500;
const FETCH_STATS_MAX_VERSIONS = 500;       // per list
const FETCH_STATS_MIN_WRITE_INTERVAL = 60;  // seconds, per client and list

function fetch_stats_file() {
    return DATA_DIR . '/fetch_stats.json';
}

function fetch_stats_client_id($ip, $user_agent) {
    // Prefixed so PHP never turns an all-digit hash into an integer key.
    return 'c' . substr(sha1($ip . "\n" . $user_agent), 0, 16);
}

/**
 * Whether a fetch adds anything to $stats: a new client, list, or list
 * version, or the client's first fetch of this list in a minute. Skipping the
 * rest keeps busy pollers from rewriting the file on every request.
 */
function fetch_stats_needs_write(array $stats, $list, $published_at, $ip, $user_agent, $now) {
    $seen = $stats['clients'][fetch_stats_client_id($ip, $user_agent)]['lists'][$list] ?? null;
    if (!$seen || $now - $seen['last_seen'] >= FETCH_STATS_MIN_WRITE_INTERVAL) {
        return true;
    }
    foreach ($stats['versions'][$list] ?? [] as $version) {
        if ($version['published_at'] === $published_at) {
            return false;
        }
    }
    return true;
}

/**
 * Return $stats with one fetch of $list added.
 *
 * $published_at is the list file's modification time, which identifies the
 * version served; $entries is its line count.
 */
function fetch_stats_apply(array $stats, $list, $published_at, $entries, $ip, $user_agent, $now) {
    $stats += ['tracking_since' => [], 'pruned_before' => [], 'clients' => [], 'versions' => []];
    $stats['tracking_since'][$list] = $stats['tracking_since'][$list] ?? $now;

    $id = fetch_stats_client_id($ip, $user_agent);
    $client = $stats['clients'][$id] ?? [
        'ip' => $ip,
        'user_agent' => $user_agent,
        'first_seen' => $now,
        'last_seen' => $now,
        'lists' => [],
    ];
    $seen = $client['lists'][$list] ?? null;
    $interval = $seen['interval'] ?? null;
    if ($seen && $now - $seen['last_seen'] >= FETCH_STATS_MIN_WRITE_INTERVAL) {
        $interval = $now - $seen['last_seen'];
    }
    $client['lists'][$list] = [
        'first_seen' => $seen['first_seen'] ?? $now,
        'last_seen' => $now,
        'interval' => $interval,
    ];
    $client['last_seen'] = $now;
    $stats['clients'][$id] = $client;

    if (count($stats['clients']) > FETCH_STATS_MAX_CLIENTS) {
        uasort($stats['clients'], fn($a, $b) => $b['last_seen'] <=> $a['last_seen']);
        $stats['clients'] = array_slice($stats['clients'], 0, FETCH_STATS_MAX_CLIENTS, true);
    }

    $versions = $stats['versions'][$list] ?? [];
    $known = false;
    foreach ($versions as $version) {
        if ($version['published_at'] === $published_at) {
            $known = true;
            break;
        }
    }
    if (!$known) {
        $versions[] = [
            'published_at' => $published_at,
            'entries' => $entries,
            'first_fetch_at' => $now,
            'first_fetch_by' => $id,
        ];
        usort($versions, fn($a, $b) => $a['published_at'] <=> $b['published_at']);
        if (count($versions) > FETCH_STATS_MAX_VERSIONS) {
            $dropped = array_splice($versions, 0, count($versions) - FETCH_STATS_MAX_VERSIONS);
            $stats['pruned_before'][$list] = end($dropped)['published_at'];
        }
    }
    $stats['versions'][$list] = $versions;

    return $stats;
}

/**
 * Record a fetch of $list. Never throws: a stats problem must not stop a
 * firewall from getting its list.
 */
function fetch_stats_record($list, $published_at, $entries, $ip, $user_agent) {
    try {
        $ip = substr((string) $ip, 0, 45);
        $user_agent = substr(preg_replace('/[\x00-\x1f\x7f]/', '', (string) $user_agent), 0, 200);
        $now = time();
        if (!fetch_stats_needs_write(read_json_file(fetch_stats_file()) ?: [], $list, $published_at, $ip, $user_agent, $now)) {
            return;
        }

        // A lock of its own rather than the data lock, so firewall polling
        // never queues behind approvals.
        $lock = fopen(DATA_DIR . '/.fetch_stats.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            return;
        }
        try {
            $stats = fetch_stats_apply(read_json_file(fetch_stats_file()) ?: [], $list, $published_at, $entries, $ip, $user_agent, $now);
            write_file_atomic(fetch_stats_file(), json_encode($stats, JSON_UNESCAPED_SLASHES));
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    } catch (Throwable $e) {
        error_log('fetch_stats_record: ' . $e->getMessage());
    }
}
