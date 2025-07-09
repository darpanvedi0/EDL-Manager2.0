<?php
// User Setup Script with Interactive Password Input
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>EDL Manager User Setup</h2>";

// Load config first
require_once 'config/config.php';
require_once 'includes/functions.php';

$users_file = DATA_DIR . '/users.json';

echo "<h3>1. Check Users File</h3>";
echo "Users file path: " . $users_file . "<br>";

if (file_exists($users_file)) {
    echo "⚠️ Users file already exists<br>";
    $content = file_get_contents($users_file);
    echo "File size: " . strlen($content) . " bytes<br>";
    
    $users = json_decode($content, true);
    if ($users !== null) {
        echo "Current users count: " . count($users) . "<br>";
        echo "Current user list: " . implode(', ', array_keys($users)) . "<br>";
    }
} else {
    echo "✅ No existing users file found<br>";
}

echo "<h3>2. Create/Reset Users with Custom Passwords</h3>";

// Handle password setup form
if (isset($_POST['setup_users'])) {
    // Validate all passwords are provided
    $required_users = ['admin', 'approver', 'operator', 'viewer'];
    $passwords = [];
    $all_passwords_provided = true;
    
    foreach ($required_users as $user_type) {
        $password = trim($_POST[$user_type . '_password'] ?? '');
        if (empty($password)) {
            echo "❌ Password for $user_type is required<br>";
            $all_passwords_provided = false;
        } else if (strlen($password) < 6) {
            echo "❌ Password for $user_type must be at least 6 characters<br>";
            $all_passwords_provided = false;
        } else {
            $passwords[$user_type] = $password;
        }
    }
    
    if ($all_passwords_provided) {
        // Create users with custom passwords
        $default_users = [
            'admin' => [
                'password' => password_hash($passwords['admin'], PASSWORD_DEFAULT),
                'name' => 'System Administrator',
                'email' => 'admin@company.com',
                'role' => 'admin',
                'permissions' => ['submit', 'approve', 'view', 'manage', 'audit']
            ],
            'approver' => [
                'password' => password_hash($passwords['approver'], PASSWORD_DEFAULT),
                'name' => 'Security Approver',
                'email' => 'approver@company.com',
                'role' => 'approver',
                'permissions' => ['approve', 'view']
            ],
            'operator' => [
                'password' => password_hash($passwords['operator'], PASSWORD_DEFAULT),
                'name' => 'Security Operator',
                'email' => 'operator@company.com',
                'role' => 'operator',
                'permissions' => ['submit', 'view']
            ],
            'viewer' => [
                'password' => password_hash($passwords['viewer'], PASSWORD_DEFAULT),
                'name' => 'Security Viewer',
                'email' => 'viewer@company.com',
                'role' => 'viewer',
                'permissions' => ['view']
            ]
        ];

        // Create users file
        if (write_json_file($users_file, $default_users)) {
            echo "✅ Users created successfully with custom passwords<br>";
            
            // Verify the file was written correctly
            if (file_exists($users_file)) {
                $verification = read_json_file($users_file);
                echo "<h4>✅ Verification - Users created:</h4>";
                
                foreach ($verification as $username => $user) {
                    echo "User: <strong>$username</strong> - Role: <strong>{$user['role']}</strong> - Permissions: " . implode(', ', $user['permissions']) . "<br>";
                }
                
                echo "<h4>🔒 Password Testing</h4>";
                
                // Test password verification for each user
                foreach ($passwords as $username => $plain_password) {
                    if (isset($verification[$username])) {
                        $stored_hash = $verification[$username]['password'];
                        $verify_result = password_verify($plain_password, $stored_hash);
                        echo "Password verification for <strong>$username</strong>: " . ($verify_result ? "✅ SUCCESS" : "❌ FAILED") . "<br>";
                    }
                }
                
                echo "<h4>🚀 Setup Complete!</h4>";
                echo '<p style="color: green; font-weight: bold;">All users have been created successfully with your custom passwords!</p>';
                echo '<p><strong>Next steps:</strong></p>';
                echo '<ul>';
                echo '<li><a href="login.php">→ Go to Login Page</a></li>';
                echo '<li><a href="debug.php">→ Test System (Debug Page)</a></li>';
                echo '<li><a href="index.php">→ Go to Main Application</a></li>';
                echo '</ul>';
                
                // Clear passwords from memory for security
                foreach ($passwords as $key => $value) {
                    unset($passwords[$key]);
                }
                
            } else {
                echo "❌ Failed to verify users file after creation<br>";
            }
        } else {
            echo "❌ Failed to create users file<br>";
        }
    }
} else {
    // Display password setup form
    echo '<div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">';
    echo '<h4>🔐 Set Passwords for User Types</h4>';
    echo '<p>Please enter secure passwords for each user type. Passwords must be at least 6 characters long.</p>';
    
    echo '<form method="POST" style="max-width: 600px;">';
    
    $user_descriptions = [
        'admin' => [
            'title' => 'System Administrator',
            'description' => 'Full access to all features including system management and configuration',
            'permissions' => 'Submit, Approve, View, Manage, Audit'
        ],
        'approver' => [
            'title' => 'Security Approver', 
            'description' => 'Can approve/deny requests and view EDL entries',
            'permissions' => 'Approve, View'
        ],
        'operator' => [
            'title' => 'Security Operator',
            'description' => 'Can submit new requests and view EDL entries',
            'permissions' => 'Submit, View'
        ],
        'viewer' => [
            'title' => 'Security Viewer',
            'description' => 'Read-only access to view EDL entries',
            'permissions' => 'View'
        ]
    ];
    
    foreach ($user_descriptions as $user_type => $info) {
        echo '<div style="margin-bottom: 25px; padding: 15px; border: 1px solid #dee2e6; border-radius: 4px;">';
        echo '<h5 style="color: #0066cc; margin-bottom: 5px;">' . ucfirst($user_type) . ' - ' . $info['title'] . '</h5>';
        echo '<p style="margin-bottom: 8px; color: #666; font-size: 14px;">' . $info['description'] . '</p>';
        echo '<p style="margin-bottom: 10px; color: #28a745; font-size: 13px;"><strong>Permissions:</strong> ' . $info['permissions'] . '</p>';
        echo '<label for="' . $user_type . '_password" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>';
        echo '<input type="password" id="' . $user_type . '_password" name="' . $user_type . '_password" ';
        echo 'style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;" ';
        echo 'placeholder="Enter password for ' . $user_type . ' (min 6 characters)" required minlength="6">';
        echo '</div>';
    }
    
    echo '<div style="margin-top: 30px;">';
    echo '<button type="submit" name="setup_users" style="background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer;">Create Users with Custom Passwords</button>';
    echo '</div>';
    echo '</form>';
    echo '</div>';
    
    if (file_exists($users_file)) {
        echo '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px; border-left: 4px solid #ffc107;">';
        echo '<h5 style="color: #856404;">⚠️ Warning</h5>';
        echo '<p style="color: #856404; margin: 0;">A users file already exists. Creating new users will overwrite the existing users and their passwords.</p>';
        echo '</div>';
    }
}

echo "<h3>3. File Permissions Check</h3>";
echo "Data directory writable: " . (is_writable(DATA_DIR) ? "✅ YES" : "❌ NO") . "<br>";
if (file_exists($users_file)) {
    echo "Users file writable: " . (is_writable($users_file) ? "✅ YES" : "❌ NO") . "<br>";
}

// Display current file status
echo "<h3>4. Current File Status</h3>";
if (file_exists($users_file)) {
    echo "Users file exists: ✅ YES<br>";
    echo "File size: " . filesize($users_file) . " bytes<br>";
    echo "Last modified: " . date('Y-m-d H:i:s', filemtime($users_file)) . "<br>";
} else {
    echo "Users file exists: ❌ NO<br>";
}

echo '<br><div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6;">';
echo '<h4>🔗 Quick Links</h4>';
echo '<p><a href="debug.php">→ System Debug & Testing</a></p>';
echo '<p><a href="login.php">→ Login Page</a></p>';
echo '<p><a href="index.php">→ Main Application</a></p>';
echo '</div>';
?>
