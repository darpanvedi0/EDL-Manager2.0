<?php
// bench/entries.php - Synthetic blocklist entries for the benchmarks.
//
// Entries have the shape the approval page writes. The mix is 60% IP
// addresses, 30% domains, and 10% URLs; every entry is unique.

function bench_entries($count) {
    $entries = [];
    for ($i = 0; $i < $count; $i++) {
        $kind = $i % 10;
        if ($kind < 6) {
            $type = 'ip';
            $entry = sprintf('10.%d.%d.%d', ($i >> 16) & 255, ($i >> 8) & 255, $i & 255);
        } elseif ($kind < 9) {
            $type = 'domain';
            $entry = "host$i.example" . ($i % 97) . '.com';
        } else {
            $type = 'url';
            $entry = "https://bad$i.example.net/login/$i";
        }
        $entries[] = [
            'id' => "app_bench_$i",
            'entry' => $entry,
            'type' => $type,
            'comment' => '',
            'justification' => 'Benchmark entry',
            'priority' => 'medium',
            'submitted_by' => 'bench',
            'submitted_at' => '2026-01-01 00:00:00',
            'approved_by' => 'bench',
            'approved_at' => '2026-01-01T00:05:00+00:00',
            'status' => 'active',
            'admin_comment' => '',
            'request_id' => "req_bench_$i",
            'servicenow_ticket' => 'INC0000001',
            'source' => 'request',
        ];
    }
    return $entries;
}
