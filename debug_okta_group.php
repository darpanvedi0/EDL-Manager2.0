<?php
// debug_okta_groups.php - Debug Okta groups and role mapping
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config/config.php';
require_once 'includes/functions.php';

session_start();

echo "<h1>🔍 Okta Groups & Role Mapping Debug</h1>";

echo "<h2>1. Current Session Information</h2>";
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated']) {
    echo "✅ <strong>Authenticated via:</strong> " . ($_SESSION['login_method'] ?? 'unknown') . "<br>";
    echo "✅ <strong>Username/Email:</strong> " . ($_SESSION['username'] ?? 'unknown') . "<br>";
    echo "✅ <strong>Current Role:</strong> " . ($_SESSION['role'] ?? 'unknown') . "<br>";
    echo "✅ <strong>Permissions:</strong> " . implode(', ', $_SESSION['permissions'] ?? []) . "<br>";
    
    if (isset($_SESSION['groups'])) {
        echo "<h3>📋 Okta Groups (from session):</h3>";
        echo "<ul>";
        foreach ($_SESSION['groups'] as $group) {
            echo "<li><code>" . htmlspecialchars($group) . "</code></li>";
        }
        echo "</ul>";
    } else {
        echo "❌ <strong>No groups found in session</strong><br>";
    }
} else {
    echo "❌ <strong>Not authenticated</strong><br>";
    echo '<p><a href="login.php">Please login first</a></p>';
    exit;
}

echo "<h2>2. Current Okta Configuration</h2>";
$okta_config = read_json_file(DATA_DIR . '/okta_config.json');

if (empty($okta_config)) {
    echo "❌ <strong>No Okta configuration found</strong><br>";
} else {
    echo "✅ <strong>Okta Enabled:</strong> " . ($okta_config['enabled'] ? 'YES' : 'NO') . "<br>";
    echo "✅ <strong>Default Role:</strong> " . ($okta_config['default_role'] ?? 'viewer') . "<br>";
    
    echo "<h3>🔗 Group Mappings:</h3>";
    $group_mappings = $okta_config['group_mappings'] ?? [];
    
    if (empty($group_mappings)) {
        echo "❌ <strong>No group mappings configured!</strong><br>";
        echo "<p class='alert alert-warning'>This is why you're getting the 'viewer' role. You need to configure group mappings.</p>";
    } else {
        echo "<table class='table table-sm table-bordered'>";
        echo "<thead><tr><th>EDL Role</th><th>Mapped Okta Group</th><th>Your Access</th></tr></thead>";
        echo "<tbody>";
        
        $user_groups = $_SESSION['groups'] ?? [];
        
        foreach (['admin', 'approver', 'operator', 'viewer'] as $role) {
            $mapped_group = $group_mappings[$role . '_group'] ?? '';
            $has_access = !empty($mapped_group) && in_array($mapped_group, $user_groups);
            
            echo "<tr>";
            echo "<td><strong>" . ucfirst($role) . "</strong></td>";
            echo "<td><code>" . htmlspecialchars($mapped_group ?: 'Not configured') . "</code></td>";
            echo "<td>" . ($has_access ? "✅ YES" : "❌ NO") . "</td>";
            echo "</tr>";
        }
        
        echo "</tbody></table>";
    }
}

echo "<h2>3. Recommended Fix</h2>";
echo "<div class='alert alert-info'>";
echo "<h4>🔧 To fix your role assignment:</h4>";
echo "<ol>";
echo "<li>Go to <a href='pages/okta_config.php'><strong>Okta Configuration</strong></a></li>";
echo "<li>In the <strong>Group Mappings</strong> section, set:</li>";
echo "<ul>";
echo "<li><strong>Admin Group:</strong> <code>sp_EDLManager_Admins</code></li>";
echo "<li>Configure other groups as needed</li>";
echo "</ul>";
echo "<li>Save the configuration</li>";
echo "<li>Log out and log back in to test</li>";
echo "</ol>";
echo "</div>";

echo "<h2>4. Role Assignment Logic</h2>";
echo "<p>The system checks groups in this order (highest privilege first):</p>";
echo "<ol>";
echo "<li><strong>Admin</strong> - Full access to everything</li>";
echo "<li><strong>Approver</strong> - Can approve/deny requests and view</li>";
echo "<li><strong>Operator</strong> - Can submit requests and view</li>";
echo "<li><strong>Viewer</strong> - Can only view (default fallback)</li>";
echo "</ol>";

echo "<p><strong>Current Issue:</strong> Your group <code>sp_EDLManager_Admins</code> is not mapped to any role, so you're getting the default 'viewer' role.</p>";

echo '<hr>';
echo '<p><a href="pages/okta_config.php" class="btn btn-primary">Go to Okta Configuration</a> ';
echo '<a href="debug_auth.php" class="btn btn-secondary">Back to Auth Debug</a></p>';
?>

<style>
.alert {
    padding: 15px;
    margin: 15px 0;
    border: 1px solid transparent;
    border-radius: 4px;
}
.alert-warning {
    color: #856404;
    background-color: #fff3cd;
    border-color: #ffeaa7;
}
.alert-info {
    color: #0c5460;
    background-color: #d1ecf1;
    border-color: #bee5eb;
}
.table {
    width: 100%;
    margin-bottom: 1rem;
    color: #212529;
    border-collapse: collapse;
}
.table th,
.table td {
    padding: 0.75rem;
    vertical-align: top;
    border-top: 1px solid #dee2e6;
}
.table-bordered {
    border: 1px solid #dee2e6;
}
.table-bordered th,
.table-bordered td {
    border: 1px solid #dee2e6;
}
.btn {
    display: inline-block;
    padding: 0.375rem 0.75rem;
    margin-bottom: 0;
    font-size: 1rem;
    font-weight: 400;
    line-height: 1.5;
    text-align: center;
    text-decoration: none;
    vertical-align: middle;
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 0.25rem;
}
.btn-primary {
    color: #fff;
    background-color: #007bff;
    border-color: #007bff;
}
.btn-secondary {
    color: #fff;
    background-color: #6c757d;
    border-color: #6c757d;
}
</style>
