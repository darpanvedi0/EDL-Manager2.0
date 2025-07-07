<?php
// debug_okta_flow.php - Debug the actual Okta authentication flow
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config/config.php';
require_once 'includes/functions.php';

echo "<h1>🔍 Okta Authentication Flow Debug</h1>";

echo "<h2>1. Available Okta Classes</h2>";

// Check for OktaAuthOrg
if (file_exists('includes/okta_auth_org.php')) {
    require_once 'includes/okta_auth_org.php';
    if (class_exists('OktaAuthOrg')) {
        echo "✅ <strong>OktaAuthOrg class found</strong><br>";
        
        try {
            $okta_auth_org = new OktaAuthOrg();
            echo "✅ OktaAuthOrg instantiated successfully<br>";
            echo "• Enabled: " . ($okta_auth_org->is_enabled() ? "✅ YES" : "❌ NO") . "<br>";
            echo "• Allow fallback: " . ($okta_auth_org->allow_local_fallback() ? "✅ YES" : "❌ NO") . "<br>";
            
            if ($okta_auth_org->is_enabled()) {
                echo "<h3>🧪 Testing OktaAuthOrg Connection</h3>";
                $test_result = $okta_auth_org->test_connection();
                if ($test_result['success']) {
                    echo "✅ <strong>OktaAuthOrg connection test: SUCCESS</strong><br>";
                    echo "• Message: " . htmlspecialchars($test_result['message']) . "<br>";
                    if (isset($test_result['endpoints'])) {
                        echo "• Authorization: <code>" . htmlspecialchars($test_result['endpoints']['authorization']) . "</code><br>";
                        echo "• Token: <code>" . htmlspecialchars($test_result['endpoints']['token']) . "</code><br>";
                        echo "• UserInfo: <code>" . htmlspecialchars($test_result['endpoints']['userinfo']) . "</code><br>";
                        echo "• Issuer: <code>" . htmlspecialchars($test_result['endpoints']['issuer']) . "</code><br>";
                    }
                } else {
                    echo "❌ <strong>OktaAuthOrg connection test: FAILED</strong><br>";
                    echo "• Error: " . htmlspecialchars($test_result['message']) . "<br>";
                }
                
                echo "<h3>🔗 Testing Authorization URL Generation</h3>";
                try {
                    session_start();
                    $auth_url = $okta_auth_org->get_authorization_url();
                    echo "✅ <strong>Authorization URL generated successfully:</strong><br>";
                    echo "<div style='background: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin: 10px 0;'>";
                    echo "<code>" . htmlspecialchars($auth_url) . "</code><br>";
                    echo "</div>";
                    
                    // Parse the URL to show components
                    $parsed = parse_url($auth_url);
                    parse_str($parsed['query'] ?? '', $query_params);
                    
                    echo "<strong>URL Components:</strong><br>";
                    echo "• Base URL: <code>" . htmlspecialchars($parsed['scheme'] . '://' . $parsed['host'] . $parsed['path']) . "</code><br>";
                    echo "• Client ID: <code>" . htmlspecialchars($query_params['client_id'] ?? 'not set') . "</code><br>";
                    echo "• Redirect URI: <code>" . htmlspecialchars($query_params['redirect_uri'] ?? 'not set') . "</code><br>";
                    echo "• Scope: <code>" . htmlspecialchars($query_params['scope'] ?? 'not set') . "</code><br>";
                    echo "• State: <code>" . htmlspecialchars($query_params['state'] ?? 'not set') . "</code><br>";
                    
                } catch (Exception $e) {
                    echo "❌ <strong>Authorization URL generation failed:</strong><br>";
                    echo "• Error: " . htmlspecialchars($e->getMessage()) . "<br>";
                }
            }
            
        } catch (Exception $e) {
            echo "❌ Error with OktaAuthOrg: " . htmlspecialchars($e->getMessage()) . "<br>";
        }
    } else {
        echo "❌ OktaAuthOrg class not found in file<br>";
    }
} else {
    echo "❌ <strong>includes/okta_auth_org.php file not found</strong><br>";
}

echo "<hr>";

// Check for regular OktaAuth
if (file_exists('includes/okta_auth.php')) {
    require_once 'includes/okta_auth.php';
    if (class_exists('OktaAuth')) {
        echo "✅ <strong>OktaAuth class found (fallback)</strong><br>";
        
        try {
            $okta_auth = new OktaAuth();
            echo "✅ OktaAuth instantiated successfully<br>";
            echo "• Enabled: " . ($okta_auth->is_enabled() ? "✅ YES" : "❌ NO") . "<br>";
            echo "• Allow fallback: " . ($okta_auth->allow_local_fallback() ? "✅ YES" : "❌ NO") . "<br>";
        } catch (Exception $e) {
            echo "❌ Error with OktaAuth: " . htmlspecialchars($e->getMessage()) . "<br>";
        }
    } else {
        echo "❌ OktaAuth class not found in file<br>";
    }
} else {
    echo "❌ includes/okta_auth.php file not found<br>";
}

echo "<h2>2. Okta Configuration</h2>";
$okta_config = read_json_file(DATA_DIR . '/okta_config.json');
if ($okta_config) {
    echo "<pre>";
    echo "Domain: " . htmlspecialchars($okta_config['okta_domain'] ?? 'not set') . "\n";
    echo "Client ID: " . htmlspecialchars(substr($okta_config['client_id'] ?? '', 0, 10) . '...') . "\n";
    echo "Client Secret: " . (empty($okta_config['client_secret']) ? 'not set' : 'set (' . strlen($okta_config['client_secret']) . ' chars)') . "\n";
    echo "Redirect URI: " . htmlspecialchars($okta_config['redirect_uri'] ?? 'not set') . "\n";
    echo "Enabled: " . ($okta_config['enabled'] ? 'YES' : 'NO') . "\n";
    echo "Allow Local Fallback: " . ($okta_config['allow_local_fallback'] ? 'YES' : 'NO') . "\n";
    echo "</pre>";
} else {
    echo "❌ No Okta configuration found<br>";
}

echo "<h2>3. Test Login Flow</h2>";
echo "<p>Click the button below to test the actual Okta login flow:</p>";
echo '<a href="okta/login.php" class="btn btn-primary" style="display: inline-block; background: #007acc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">🧪 Test Okta Login Flow</a>';

echo "<h2>4. Manual Issuer Test</h2>";
echo "<p>Let's manually test what issuer your Okta domain should return:</p>";

$domain = $okta_config['okta_domain'] ?? '';
if ($domain) {
    // Test what the actual token endpoint would return for issuer
    echo "<h4>Expected issuer for org-level: <code>https://{$domain}</code></h4>";
    
    echo "<p>If you're still getting issuer mismatch, the actual issuer in your ID token might be different. Check your PHP error log for debug messages that show:</p>";
    echo "<ul>";
    echo "<li><code>DEBUG: Expected issuer (org-level): ...</code></li>";
    echo "<li><code>DEBUG: Actual ID token issuer: ...</code></li>";
    echo "</ul>";
    
    echo "<h4>🔧 Quick Fix Test</h4>";
    echo "<p>If the issue persists, we can create a version that accepts any issuer from your domain:</p>";
    echo '<form method="POST" style="margin: 10px 0;">
        <button type="submit" name="create_flexible_auth" style="background: #28a745; color: white; padding: 8px 16px; border: none; border-radius: 4px;">
            Create Flexible Issuer Version
        </button>
    </form>';
    
    if (isset($_POST['create_flexible_auth'])) {
        echo "<div style='background: #d4edda; padding: 15px; border: 1px solid #c3e6cb; border-radius: 4px; margin: 10px 0;'>";
        echo "<h5>✅ Creating flexible issuer version...</h5>";
        echo "<p>I'll create a version that accepts multiple issuer formats from your domain.</p>";
        echo "<p>This will help us identify exactly what issuer your Okta org is sending.</p>";
        echo "</div>";
    }
} else {
    echo "❌ No Okta domain configured. Please configure Okta first.";
}

echo "<hr>";
echo "<p><strong>Next Steps:</strong></p>";
echo "<ol>";
echo "<li>Make sure you have the <code>includes/okta_auth_org.php</code> file</li>";
echo "<li>Test the authorization URL generation above</li>";
echo "<li>Try the Okta login flow and check your PHP error log for debug messages</li>";
echo "<li>Look for debug messages that show the expected vs actual issuer</li>";
echo "</ol>";

echo '<p><a href="debug_auth.php">← Back to Authentication Debug</a> | <a href="pages/okta_config.php">Go to Okta Config</a></p>';
?>
