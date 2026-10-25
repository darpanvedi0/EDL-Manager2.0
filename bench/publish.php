<?php
// bench/publish.php - How long publishing, approving, and submitting take as
// the blocklist grows. Runs the application code directly against a
// temporary data directory; prints JSON.
// Usage: php bench/publish.php [entry counts...]   (default 1000 10000 50000 100000)

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$tmp = sys_get_temp_dir() . '/edl-bench-' . bin2hex(random_bytes(4));
mkdir("$tmp/data", 0700, true);
mkdir("$tmp/lists", 0700, true);
define('DATA_DIR', "$tmp/data");
define('EDL_FILES_DIR', "$tmp/lists");

require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/requests.php';
require_once __DIR__ . '/entries.php';

const RUNS = 7;

function median_ms(array $seconds) {
    sort($seconds);
    return round($seconds[intdiv(count($seconds), 2)] * 1000, 2);
}

function timed(callable $work) {
    $start = hrtime(true);
    $work();
    return (hrtime(true) - $start) / 1e9;
}

$sizes = array_map('intval', array_slice($argv, 1)) ?: [1000, 10000, 50000, 100000];
$results = [];

foreach ($sizes as $size) {
    write_json_file(DATA_DIR . '/approved_entries.json', bench_entries($size));
    write_json_file(DATA_DIR . '/pending_requests.json', []);
    write_json_file(DATA_DIR . '/denied_entries.json', []);
    write_json_file(DATA_DIR . '/audit_logs.json', []);

    $publish = $approve = $submit = [];
    for ($run = 0; $run < RUNS; $run++) {
        $publish[] = timed(fn() => write_edl_lists());

        // A new indicator each run, so the duplicate checks scan every entry.
        $indicator = sprintf('192.0.2.%d', $run + 1);
        $created = null;
        $submit[] = timed(function () use ($indicator, &$created) {
            $created = edl_submit_requests(
                [['entry' => $indicator]],
                ['justification' => 'Benchmark', 'servicenow_ticket' => 'INC0000001'],
                'bench'
            )['created'][0];
        });
        $approve[] = timed(fn() => edl_decide_request($created['id'], true, 'bench', ''));
    }

    $results[] = [
        'entries' => $size,
        'publish_ms' => median_ms($publish),
        'submit_ms' => median_ms($submit),
        'approve_ms' => median_ms($approve),
        'store_bytes' => filesize(DATA_DIR . '/approved_entries.json'),
        'ip_list_bytes' => filesize(EDL_FILES_DIR . '/ip_blocklist.txt'),
    ];
    fwrite(STDERR, "entries=$size publish=" . end($results)['publish_ms'] . "ms approve=" . end($results)['approve_ms'] . "ms\n");
}

foreach (array_merge(glob(DATA_DIR . '/{,.}*', GLOB_BRACE), glob(EDL_FILES_DIR . '/*')) as $file) {
    if (is_file($file)) {
        unlink($file);
    }
}
rmdir(DATA_DIR);
rmdir(EDL_FILES_DIR);
rmdir($tmp);

echo json_encode([
    'benchmark' => 'publish',
    'runs_per_size' => RUNS,
    'statistic' => 'median',
    'php' => PHP_VERSION,
    'results' => $results,
], JSON_PRETTY_PRINT) . "\n";
