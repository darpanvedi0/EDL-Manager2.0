<?php
// EDL Manager Configuration

// Basic constants
define('APP_NAME', 'EDL Manager');
define('APP_VERSION', '2.0.0');
define('APP_ROOT', dirname(__DIR__));

// Site-specific settings. Copy config.local.php.example to config.local.php
// (not committed) and define them there, or set them as environment variables
// in the web server / PHP-FPM pool. A constant in config.local.php wins.
if (file_exists(__DIR__ . '/config.local.php')) {
    require __DIR__ . '/config.local.php';
}

// EDL_DATA_DIR: where users, requests, audit logs and SSL keys are stored.
// Put it outside the web root in production.
if (!defined('EDL_DATA_DIR')) {
    define('EDL_DATA_DIR', getenv('EDL_DATA_DIR') ?: APP_ROOT . '/data');
}

// EDL_DEBUG: show PHP errors in the browser. Never enable it in production.
if (!defined('EDL_DEBUG')) {
    define('EDL_DEBUG', filter_var(getenv('EDL_DEBUG'), FILTER_VALIDATE_BOOLEAN));
}

if (EDL_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

// Paths
define('DATA_DIR', rtrim(EDL_DATA_DIR, '/\\'));
define('EDL_FILES_DIR', APP_ROOT . '/edl-files');

// Create directories if they don't exist
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0750, true);
}
if (!is_dir(EDL_FILES_DIR)) {
    mkdir(EDL_FILES_DIR, 0755, true);
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
    // 'x' only creates the file if it is still missing, so two first requests
    // can't race and truncate data the other one has already written.
    if (!file_exists($file) && ($handle = @fopen($file, 'x'))) {
        fwrite($handle, $content);
        fclose($handle);
    }
}

// Session settings
define('SESSION_TIMEOUT', 3600);
define('CSRF_TOKEN_NAME', 'csrf_token');

// Start session (not needed for command-line scripts such as user_setup.php).
// The REST API and the firewall feed define EDL_NO_SESSION: they authenticate
// per request, and a session per firewall poll would only pile up files.
if (PHP_SAPI !== 'cli' && !defined('EDL_NO_SESSION') && session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>