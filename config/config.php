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
    DATA_DIR . '/audit_logs.json' => '[]'
];

foreach ($files as $file => $content) {
    if (!file_exists($file)) {
        file_put_contents($file, $content);
    }
}

// Session settings
define('SESSION_TIMEOUT', 3600);
define('CSRF_TOKEN_NAME', 'csrf_token');

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

echo "<!-- Config loaded successfully -->\n";
?>