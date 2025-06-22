<?php
// User Setup and Debug Script
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>EDL Manager User Setup & Debug</h2>";

// Load config first
require_once 'config/config.php';
require_once 'includes/functions.php';

$users_file = DATA_DIR . '/users.json';

echo "<h3>1. Check Users File</h3>";
echo "Users file path: " . $users_file . "<br>";

if (file_exists($users_file)) {
    echo "✅ Users file exists<br>";
    $content = file_get_contents($users_file);
    echo "File size: " . strlen($content) . " bytes<br>";
    echo "Raw content: <pre>" . htmlspecialchars($content) . "</pre>";
    
    $users = json_decode($content, true);
    if ($users === null) {
        echo "❌ JSON decode failed: " . json_last_error_msg() . "<br>";
    } else {
        echo "✅ JSON decode successful<br>";
        echo "Users count: " . count($users) . "<br>";
        echo "User list: " . implode(', ', array_keys($users)) . "<br>";
    }
} else {
    echo "❌ Users file doesn't exist<br>";
}

echo "<h3>2. Create/Reset Default Users</h3>";

$default_users = [
    'admin' => [
        'password' => password_hash('admin123', PASSWORD_DEFAULT),
        'name' => 'System Administrator',
        'email' => 'admin@company.com',
        'role' => 'admin',
        'permissions' => ['submit', 'approve', 'view', 'manage', 'audit']
    ],
    'approver' => [
        'password' => password_hash('approver123', PASSWORD_DEFAULT),
        'name' => 'Security Approver',
        'email' => 'approver@company.com',
        'role' => 'approver',
        'permissions' => ['approve', 'view']
    ],
    'operator' => [
        'password' => password_hash('operator123', PASSWORD_DEFAULT),
        'name' => 'Security Operator',
        'email' => 'operator@company.com',
        'role' => 'operator',
        'permissions' => ['submit', 'view']
    ]
];

// Create users file
if (write_json_file($users_file, $default_users)) {
    echo "✅ Default users created successfully<br>";
} else {
    echo "❌ Failed to create users file<br>";
}

// Verify the file was written correctly
if (file_exists($users_file)) {
    $verification = read_json_file($users_file);
    echo "Verification - Users in file: " . count($verification) . "<br>";
    
    foreach ($verification as $username => $user) {
        echo "User: $username - Role: {$user['role']} - Permissions: " . implode(', ', $user['permissions']) . "<br>";
    }
}

echo "<h3>3. Test Password Verification</h3>";

// Test password verification
$users = read_json_file($users_file);
if (isset($users['admin'])) {
    $stored_hash = $users['admin']['password'];
    echo "Stored hash for admin: " . substr($stored_hash, 0, 20) . "...<br>";
    
    $verify_result = password_verify('admin123', $stored_hash);
    echo "Password verification test: " . ($verify_result ? "✅ SUCCESS" : "❌ FAILED") . "<br>";
    
    // Test wrong password
    $wrong_verify = password_verify('wrongpassword', $stored_hash);
    echo "Wrong password test: " . ($wrong_verify ? "❌ SHOULD FAIL" : "✅ Correctly rejected") . "<br>";
} else {
    echo "❌ Admin user not found in users array<br>";
}

echo "<h3>4. Test Authentication Class</h3>";

try {
    require_once 'includes/auth.php';
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    $auth = new EDLAuth();
    echo "✅ EDLAuth class instantiated<br>";
    
    // Test authentication
    $auth_result = $auth->authenticate('admin', 'admin123');
    echo "Authentication test: " . ($auth_result ? "✅ SUCCESS" : "❌ FAILED") . "<br>";
    
    if ($auth_result) {
        echo "Session data:<br>";
        echo "- Username: " . ($_SESSION['username'] ?? 'NOT SET') . "<br>";
        echo "- Role: " . ($_SESSION['role'] ?? 'NOT SET') . "<br>";
        echo "- Permissions: " . implode(', ', $_SESSION['permissions'] ?? []) . "<br>";
    }
    
} catch (Exception $e) {
    echo "❌ Authentication error: " . $e->getMessage() . "<br>";
}

echo "<h3>5. Manual Login Test</h3>";
echo '<form method="POST">
    <p>Test login form:</p>
    <input type="text" name="test_username" placeholder="Username" value="admin"><br>
    <input type="password" name="test_password" placeholder="Password" value="admin123"><br>
    <button type="submit" name="test_login">Test Login</button>
</form>';

if (isset($_POST['test_login'])) {
    $test_username = $_POST['test_username'];
    $test_password = $_POST['test_password'];
    
    echo "<h4>Manual Login Test Results:</h4>";
    echo "Username: " . htmlspecialchars($test_username) . "<br>";
    echo "Password: " . str_repeat('*', strlen($test_password)) . "<br>";
    
    try {
        if (!isset($auth)) {
            require_once 'includes/auth.php';
            $auth = new EDLAuth();
        }
        
        $result = $auth->authenticate($test_username, $test_password);
        echo "Result: " . ($result ? "✅ LOGIN SUCCESS" : "❌ LOGIN FAILED") . "<br>";
        
        if ($result) {
            echo '<p style="color: green; font-weight: bold;">Login successful! You can now go to <a href="login.php">login.php</a></p>';
        }
        
    } catch (Exception $e) {
        echo "❌ Error during manual test: " . $e->getMessage() . "<br>";
    }
}

echo "<h3>6. File Permissions</h3>";
echo "Data directory writable: " . (is_writable(DATA_DIR) ? "✅ YES" : "❌ NO") . "<br>";
echo "Users file writable: " . (is_writable($users_file) ? "✅ YES" : "❌ NO") . "<br>";

echo "<br><p><a href='login.php'>→ Go to Login Page</a></p>";
echo "<p><a href='debug.php'>→ Back to Debug</a></p>";
?>