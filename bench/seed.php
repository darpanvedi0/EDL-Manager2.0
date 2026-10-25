<?php
// bench/seed.php - Runs inside the EDL Manager container (run.sh copies it
// in): loads N synthetic entries, publishes the lists, copies the IP list to
// a static file for the static-serving baseline, and prints an API key.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require '/var/www/html/config/config.php';
require '/var/www/html/includes/functions.php';
require '/var/www/html/includes/edl_lists.php';
require '/var/www/html/includes/api_keys.php';
require __DIR__ . '/entries.php';

write_json_file(DATA_DIR . '/approved_entries.json', bench_entries((int) (getenv('N') ?: 0)));
write_edl_lists();
copy(EDL_FILES_DIR . '/ip_blocklist.txt', EDL_FILES_DIR . '/static_ip.txt');
echo api_key_create('bench', ['view', 'submit', 'approve', 'remove'], 'bench')['token'], "\n";
