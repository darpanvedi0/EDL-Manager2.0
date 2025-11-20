<?php
// Minimal EDL Manager Configuration for Testing
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Basic constants
define('APP_NAME', 'EDL Manager');
define('APP_VERSION', '2.0.0');
define('APP_ROOT', dirname(__DIR__));

// Paths
define('DATA_DIR', APP_ROOT . '/data');
define('EDL_FILES_DIR', APP_ROOT . '/edl-files');
define('VIRUSTOTAL_CACHE_FILE', DATA_DIR . '/virustotal_cache.json');
define('VIRUSTOTAL_CONFIG_FILE', DATA_DIR . '/virustotal_config.json');

// Create directories if they don't exist
$dirs = [DATA_DIR, EDL_FILES_DIR];
foreach ($dirs as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Create default data files
$files = [
    DATA_DIR . '/users.json' => '{}',
    DATA_DIR . '/pending_requests.json' => '[]',
    DATA_DIR . '/approved_entries.json' => '[]',
    DATA_DIR . '/denied_entries.json' => '[]',
    DATA_DIR . '/audit_logs.json' => '[]',
    VIRUSTOTAL_CACHE_FILE => '[]',
    VIRUSTOTAL_CONFIG_FILE => json_encode([
        'api_key' => getenv('VIRUSTOTAL_API_KEY') ?: '',
        'cache_ttl' => 3600
    ])
];

foreach ($files as $file => $content) {
    if (!file_exists($file)) {
        file_put_contents($file, $content);
    }
}

// Session settings
define('SESSION_TIMEOUT', 3600);
define('CSRF_TOKEN_NAME', 'csrf_token');

// Load VirusTotal configuration (admin managed)
$vt_config = [];
if (file_exists(VIRUSTOTAL_CONFIG_FILE)) {
    $vt_config = json_decode(file_get_contents(VIRUSTOTAL_CONFIG_FILE), true) ?: [];
}

$vt_api_key = trim($vt_config['api_key'] ?? getenv('VIRUSTOTAL_API_KEY') ?: '');
$vt_cache_ttl = (int)($vt_config['cache_ttl'] ?? 3600);

if ($vt_cache_ttl < 60) {
    $vt_cache_ttl = 3600;
}

define('VIRUSTOTAL_API_KEY', $vt_api_key);
define('VIRUSTOTAL_CACHE_TTL', $vt_cache_ttl);

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

echo "<!-- Config loaded successfully -->\n";
?>