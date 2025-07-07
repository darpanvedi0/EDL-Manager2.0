<?php
// debug_auth.php - Place this in your EDL Manager root directory
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config/config.php';
require_once 'includes/functions.php';
require_once 'includes/auth.php';

// Optional: Clear all sessions if requested
if (isset($_GET['clear_session'])) {
    session_destroy();
    session_start();
    echo "<h2>✅ Session Cleared</h2>";
    echo '<a href="debug_auth.php">Refresh</a><br><br>';
}

echo "<h1>🔍 EDL Manager Authentication Debug</h1>";

echo "<h2>1. Session Information</h2>";
echo "<pre>";
echo "Session ID: " . session_id() . "\n";
echo "Session Status: " . session_status() . " (1=disabled, 2=active)\n";
echo "Session Data:\n";
print_r($_SESSION);
echo "</pre>";

echo "<h2>2. Authentication Status</h2>";
try {
    $auth = new EDLAuth();
    $is_authenticated = $auth->check_session();
    echo "EDLAuth check_session(): " . ($is_authenticated ? "✅ TRUE" : "❌ FALSE") . "<br>";
    
    // Check specific session flags
    echo "Session authenticated flag: " . (isset($_SESSION['authenticated']) ? ($_SESSION['authenticated'] ? "✅ TRUE" : "❌ FALSE") : "❌ NOT SET") . "<br>";
    echo "Session username: " . ($_SESSION['username'] ?? "❌ NOT SET") . "<br>";
    echo "Session role: " . ($_SESSION['role'] ?? "❌ NOT SET") . "<br>";
    echo "Login method: " . ($_SESSION['login_method'] ?? "❌ NOT SET") . "<br>";
    
} catch (Exception $e) {
    echo "❌ EDLAuth Error: " . $e->getMessage() . "<br>";
}

echo "<h2>3. Okta Session Data</h2>";
$okta_session_vars = [];
foreach ($_SESSION as $key => $value) {
    if (strpos($key, 'okta') !== false || strpos($key, 'oauth') !== false) {
        $okta_session_vars[$key] = $value;
    }
}

if (empty($okta_session_vars)) {
    echo "✅ No Okta session variables found<br>";
} else {
    echo "⚠️ Found Okta session variables:<br>";
    echo "<pre>";
    print_r($okta_session_vars);
    echo "</pre>";
}

echo "<h2>4. Okta Configuration</h2>";
if (file_exists('includes/okta_auth.php')) {
    try {
        require_once 'includes/okta_auth.php';
        if (class_exists('OktaAuth')) {
            $okta_auth = new OktaAuth();
            echo "Okta SSO Enabled: " . ($okta_auth->is_enabled() ? "✅ YES" : "❌ NO") . "<br>";
            echo "Allow Local Fallback: " . ($okta_auth->allow_local_fallback() ? "✅ YES" : "❌ NO") . "<br>";
        } else {
            echo "❌ OktaAuth class not found<br>";
        }
    } catch (Exception $e) {
        echo "❌ Okta Error: " . $e->getMessage() . "<br>";
    }
} else {
    echo "❌ okta_auth.php file not found<br>";
}

echo "<h2>5. URL and Request Information</h2>";
echo "Current URL: " . ($_SERVER['REQUEST_URI'] ?? 'Unknown') . "<br>";
echo "HTTP Host: " . ($_SERVER['HTTP_HOST'] ?? 'Unknown') . "<br>";
echo "Script Name: " . ($_SERVER['SCRIPT_NAME'] ?? 'Unknown') . "<br>";
echo "Request Method: " . ($_SERVER['REQUEST_METHOD'] ?? 'Unknown') . "<br>";

// Check for callback parameters
if (isset($_GET['code']) || isset($_GET['state']) || isset($_GET['error'])) {
    echo "<br>⚠️ <strong>OKTA CALLBACK PARAMETERS DETECTED:</strong><br>";
    echo "Code: " . ($_GET['code'] ?? 'Not set') . "<br>";
    echo "State: " . ($_GET['state'] ?? 'Not set') . "<br>";
    echo "Error: " . ($_GET['error'] ?? 'Not set') . "<br>";
    echo "<em>This might be why you're seeing Okta errors!</em><br>";
}

echo "<h2>6. Flash Messages</h2>";
$flash = get_flash();
if ($flash) {
    echo "Flash Message: " . $flash['message'] . " (Type: " . $flash['type'] . ")<br>";
} else {
    echo "No flash messages<br>";
}

echo "<h2>7. Quick Actions</h2>";
echo '<a href="debug_auth.php?clear_session=1" style="background: red; color: white; padding: 10px; text-decoration: none;">🗑️ Clear All Session Data</a><br><br>';
echo '<a href="login.php">🔑 Go to Login Page</a><br>';
echo '<a href="index.php">🏠 Go to Dashboard</a><br>';

echo "<h2>8. Test Local Authentication</h2>";
echo '<form method="POST" style="border: 1px solid #ccc; padding: 15px; margin: 10px 0;">
    <h4>Test Login (this should work without Okta errors):</h4>
    <input type="text" name="test_username" placeholder="Username" value="admin" required><br><br>
    <input type="password" name="test_password" placeholder="Password" value="admin123" required><br><br>
    <button type="submit" name="test_login">Test Login</button>
</form>';

if (isset($_POST['test_login'])) {
    echo "<h3>🧪 Local Authentication Test Results:</h3>";
    try {
        // Clear any Okta session data before testing
        foreach ($_SESSION as $key => $value) {
            if (strpos($key, 'okta') !== false || strpos($key, 'oauth') !== false) {
                unset($_SESSION[$key]);
                echo "Cleared Okta session variable: {$key}<br>";
            }
        }
        
        $test_auth = new EDLAuth();
        $result = $test_auth->authenticate($_POST['test_username'], $_POST['test_password']);
        
        if ($result) {
            echo "✅ <strong>Local authentication SUCCESS!</strong><br>";
            echo "You should now be able to access the dashboard without Okta errors.<br>";
            echo '<a href="index.php">Go to Dashboard</a><br>';
        } else {
            echo "❌ <strong>Local authentication FAILED!</strong><br>";
            echo "Check your username/password.<br>";
        }
        
    } catch (Exception $e) {
        echo "❌ Authentication test error: " . $e->getMessage() . "<br>";
    }
}

echo "<hr>";
echo "<small>Debug completed at " . date('Y-m-d H:i:s') . "</small>";
?>
