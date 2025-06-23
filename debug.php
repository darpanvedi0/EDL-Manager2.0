<?php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

echo "<h2>EDL Manager Debug Information</h2>";

// Check PHP version
echo "<h3>1. PHP Version Check</h3>";
echo "PHP Version: " . PHP_VERSION . "<br>";
if (version_compare(PHP_VERSION, '7.4.0', '<')) {
    echo "<span style='color: red;'>⚠️ PHP 7.4+ required</span><br>";
} else {
    echo "<span style='color: green;'>✅ PHP version OK</span><br>";
}

// Check required extensions
echo "<h3>2. Required Extensions</h3>";
$required_extensions = ['json', 'session', 'filter'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        echo "<span style='color: green;'>✅ $ext extension loaded</span><br>";
    } else {
        echo "<span style='color: red;'>❌ $ext extension missing</span><br>";
    }
}

// Check directories
echo "<h3>3. Directory Structure</h3>";
$required_dirs = [
    'config',
    'includes', 
    'assets',
    'assets/css',
    'assets/js',
    'data',
    'edl-files',
    'pages',
    'api'
];

foreach ($required_dirs as $dir) {
    if (is_dir($dir)) {
        $writable = is_writable($dir) ? 'writable' : 'not writable';
        echo "<span style='color: green;'>✅ $dir exists ($writable)</span><br>";
    } else {
        echo "<span style='color: red;'>❌ $dir missing</span><br>";
        // Try to create it
        if (mkdir($dir, 0755, true)) {
            echo "<span style='color: blue;'>➡️ Created $dir</span><br>";
        } else {
            echo "<span style='color: red;'>❌ Failed to create $dir</span><br>";
        }
    }
}

// Check required files
echo "<h3>4. Required Files</h3>";
$required_files = [
    'config/config.php',
    'includes/functions.php',
    'includes/auth.php',
    'includes/validation.php',
    'assets/css/style.css',
    'assets/js/main.js'
];

foreach ($required_files as $file) {
    if (file_exists($file)) {
        echo "<span style='color: green;'>✅ $file exists</span><br>";
    } else {
        echo "<span style='color: red;'>❌ $file missing</span><br>";
    }
}

// Test config loading
echo "<h3>5. Configuration Test</h3>";
try {
    if (file_exists('config/config.php')) {
        include 'config/config.php';
        echo "<span style='color: green;'>✅ Config loaded successfully</span><br>";
        echo "APP_NAME: " . (defined('APP_NAME') ? APP_NAME : 'NOT DEFINED') . "<br>";
        echo "DATA_DIR: " . (defined('DATA_DIR') ? DATA_DIR : 'NOT DEFINED') . "<br>";
    } else {
        echo "<span style='color: red;'>❌ config/config.php not found</span><br>";
    }
} catch (Exception $e) {
    echo "<span style='color: red;'>❌ Config error: " . $e->getMessage() . "</span><br>";
}

// Test functions loading
echo "<h3>6. Functions Test</h3>";
try {
    if (file_exists('includes/functions.php')) {
        include 'includes/functions.php';
        echo "<span style='color: green;'>✅ Functions loaded successfully</span><br>";
        
        // Test a function
        if (function_exists('sanitize_input')) {
            echo "<span style='color: green;'>✅ sanitize_input function available</span><br>";
        } else {
            echo "<span style='color: red;'>❌ sanitize_input function missing</span><br>";
        }
    } else {
        echo "<span style='color: red;'>❌ includes/functions.php not found</span><br>";
    }
} catch (Exception $e) {
    echo "<span style='color: red;'>❌ Functions error: " . $e->getMessage() . "</span><br>";
}

// Check data files
echo "<h3>7. Data Files</h3>";
$data_files = [
    'data/users.json',
    'data/pending_requests.json',
    'data/approved_entries.json',
    'data/denied_entries.json',
    'data/audit_logs.json'
];

foreach ($data_files as $file) {
    if (file_exists($file)) {
        echo "<span style='color: green;'>✅ $file exists</span><br>";
    } else {
        echo "<span style='color: orange;'>⚠️ $file missing (will be created)</span><br>";
        // Try to create with default content
        $default_content = in_array($file, ['data/users.json']) ? '{}' : '[]';
        if (file_put_contents($file, $default_content)) {
            echo "<span style='color: blue;'>➡️ Created $file</span><br>";
        }
    }
}

// Check permissions
echo "<h3>8. Permissions Check</h3>";
$paths_to_check = ['data', 'edl-files', 'data/users.json'];
foreach ($paths_to_check as $path) {
    if (file_exists($path)) {
        $perms = substr(sprintf('%o', fileperms($path)), -4);
        $writable = is_writable($path) ? 'writable' : 'not writable';
        echo "$path: $perms ($writable)<br>";
    }
}

// Test session
echo "<h3>9. Session Test</h3>";
try {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    echo "<span style='color: green;'>✅ Session started successfully</span><br>";
    echo "Session ID: " . session_id() . "<br>";
} catch (Exception $e) {
    echo "<span style='color: red;'>❌ Session error: " . $e->getMessage() . "</span><br>";
}

echo "<h3>10. Simple Index Test</h3>";
echo "<a href='test_index.php' style='color: blue;'>➡️ Test Simple Index</a><br>";

echo "<h3>11. Current Directory Contents</h3>";
echo "<pre>";
print_r(scandir('.'));
echo "</pre>";

?>