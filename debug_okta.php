<?php
// debug_okta.php - Comprehensive Okta debugging tool
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config/config.php';
require_once 'includes/functions.php';

echo "<h1>🔍 Okta Connection Debugging Tool</h1>";

// Get domain from config or form
$okta_config = read_json_file(DATA_DIR . '/okta_config.json');
$test_domain = $_POST['test_domain'] ?? $okta_config['okta_domain'] ?? '';

echo '<form method="POST" style="margin-bottom: 20px; padding: 15px; border: 1px solid #ccc;">
    <h3>Test Okta Domain</h3>
    <label>Okta Domain (without https://): </label>
    <input type="text" name="test_domain" value="' . htmlspecialchars($test_domain) . '" placeholder="your-domain.okta.com" style="width: 300px;">
    <button type="submit">Test Domain</button>
    <br><small>Examples: dev-12345.okta.com, company.okta.com, company.oktapreview.com</small>
</form>';

if (!empty($test_domain)) {
    echo "<h2>🌐 Testing Domain: <code>{$test_domain}</code></h2>";
    
    // Test 1: Basic DNS resolution
    echo "<h3>1. DNS Resolution Test</h3>";
    $ip = gethostbyname($test_domain);
    if ($ip === $test_domain) {
        echo "❌ <strong>DNS FAILED:</strong> Cannot resolve domain '{$test_domain}'<br>";
        echo "   • Check if domain is spelled correctly<br>";
        echo "   • Make sure it's the correct Okta domain<br>";
        echo "   • Try: dev-12345.okta.com or company.okta.com format<br>";
    } else {
        echo "✅ DNS resolved to: <code>{$ip}</code><br>";
    }
    
    // Test 2: Basic HTTPS connectivity
    echo "<h3>2. HTTPS Connectivity Test</h3>";
    $test_url = "https://{$test_domain}";
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'user_agent' => 'EDL-Manager/2.0'
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);
    
    $result = @file_get_contents($test_url, false, $context);
    if ($result === false) {
        echo "❌ <strong>HTTPS CONNECTION FAILED</strong><br>";
        echo "   • Cannot connect to https://{$test_domain}<br>";
        $error = error_get_last();
        if ($error) {
            echo "   • Error: " . $error['message'] . "<br>";
        }
    } else {
        echo "✅ HTTPS connection successful<br>";
        echo "   • Response length: " . strlen($result) . " bytes<br>";
    }
    
    // Test 3: Well-known endpoints with detailed method testing
    echo "<h3>3. Well-Known Endpoint Discovery</h3>";
    
    $endpoints_to_test = [
        'Default Authorization Server' => "https://{$test_domain}/oauth2/default/.well-known/openid_configuration",
        'Org Authorization Server' => "https://{$test_domain}/.well-known/openid_configuration",
        'Custom Authorization Server (common pattern)' => "https://{$test_domain}/oauth2/aus1/.well-known/openid_configuration"
    ];
    
    $has_working_endpoint = false;
    
    foreach ($endpoints_to_test as $name => $url) {
        echo "<h4>Testing: {$name}</h4>";
        echo "URL: <code>{$url}</code><br>";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_USERAGENT, 'EDL-Manager/2.0');
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET'); // Explicitly set GET method
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        $connect_time = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
        $total_time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        curl_close($ch);
        
        echo "HTTP Status: <code>{$http_code}</code><br>";
        echo "Connect Time: <code>{$connect_time}s</code><br>";
        echo "Total Time: <code>{$total_time}s</code><br>";
        
        if ($response === false) {
            echo "❌ <strong>CURL ERROR:</strong> {$curl_error}<br>";
        } elseif ($http_code === 200) {
            echo "✅ <strong>SUCCESS!</strong><br>";
            $has_working_endpoint = true;
            
            $config = json_decode($response, true);
            if ($config) {
                echo "<strong>🎯 OIDC Configuration Found:</strong><br>";
                echo "• Issuer: <code>" . ($config['issuer'] ?? 'Not provided') . "</code><br>";
                echo "• Authorization Endpoint: <code>" . ($config['authorization_endpoint'] ?? 'Not provided') . "</code><br>";
                echo "• Token Endpoint: <code>" . ($config['token_endpoint'] ?? 'Not provided') . "</code><br>";
                echo "• UserInfo Endpoint: <code>" . ($config['userinfo_endpoint'] ?? 'Not provided') . "</code><br>";
                
                // This is the working authorization server!
                echo "<div style='background: #d4edda; padding: 10px; margin: 10px 0; border: 1px solid #c3e6cb; border-radius: 4px;'>";
                echo "<strong>🚀 This authorization server works! Use these settings in your Okta app:</strong><br>";
                echo "• Authorization Server: <strong>{$name}</strong><br>";
                echo "• Issuer: <strong>" . ($config['issuer'] ?? 'Unknown') . "</strong><br>";
                echo "</div>";
            } else {
                echo "⚠️ Response received but not valid JSON<br>";
                echo "Response preview: <code>" . htmlspecialchars(substr($response, 0, 200)) . "...</code><br>";
            }
        } elseif ($http_code === 404) {
            echo "❌ <strong>404 NOT FOUND:</strong> This authorization server doesn't exist<br>";
        } elseif ($http_code === 403) {
            echo "❌ <strong>403 FORBIDDEN:</strong> Access denied - check domain permissions<br>";
        } elseif ($http_code === 405) {
            echo "❌ <strong>405 METHOD NOT ALLOWED:</strong> Authorization server disabled or not configured<br>";
            if ($response) {
                $error_data = json_decode($response, true);
                if ($error_data && isset($error_data['errorSummary'])) {
                    echo "   • Okta Error: <code>" . htmlspecialchars($error_data['errorSummary']) . "</code><br>";
                }
            }
            echo "   • This usually means the authorization server is not enabled in your Okta org<br>";
        } elseif ($http_code >= 500) {
            echo "❌ <strong>SERVER ERROR ({$http_code}):</strong> Okta server issue<br>";
        } else {
            echo "❌ <strong>HTTP ERROR ({$http_code}):</strong> Unexpected response<br>";
            if ($response) {
                echo "Response preview: <code>" . htmlspecialchars(substr($response, 0, 200)) . "...</code><br>";
            }
        }
        
        echo "<hr>";
    }
    
    // Special test for 405 errors - check if ANY authorization servers exist
    if (!$has_working_endpoint) {
        echo "<div style='background: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 4px; margin: 20px 0;'>";
        echo "<h4>🚨 No Working Authorization Servers Found</h4>";
        echo "<p>All endpoints returned 405 errors, which means:</p>";
        echo "<ul>";
        echo "<li><strong>Your Okta org doesn't have authorization servers enabled</strong></li>";
        echo "<li>OR the authorization servers are disabled/misconfigured</li>";
        echo "<li>OR you need to enable API Access Management</li>";
        echo "</ul>";
        
        echo "<h5>📋 How to fix this in Okta:</h5>";
        echo "<ol>";
        echo "<li><strong>Log into your Okta Admin Console:</strong> <a href='https://lucid.okta.com/admin' target='_blank'>https://lucid.okta.com/admin</a></li>";
        echo "<li><strong>Go to Security → API:</strong> Check if you have API Access Management enabled</li>";
        echo "<li><strong>Check Authorization Servers:</strong>";
        echo "<ul>";
        echo "<li>Go to <strong>Security → API → Authorization Servers</strong></li>";
        echo "<li>Look for a 'default' authorization server</li>";
        echo "<li>Make sure it's <strong>Active</strong></li>";
        echo "<li>If none exist, you may need to upgrade your Okta plan</li>";
        echo "</ul></li>";
        echo "<li><strong>Alternative:</strong> Use the Org Authorization Server (simpler setup)</li>";
        echo "</ol>";
        echo "</div>";
        
        // Test for org-level OIDC (simpler alternative)
        echo "<h4>🔄 Testing Alternative: Org-Level OIDC</h4>";
        echo "<p>Let's try the simpler org-level OIDC configuration...</p>";
        
        $org_auth_url = "https://{$test_domain}/oauth2/v1/authorize";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $org_auth_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'EDL-Manager/2.0');
        curl_setopt($ch, CURLOPT_NOBODY, true); // HEAD request
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        echo "Testing org authorize endpoint: <code>{$org_auth_url}</code><br>";
        echo "HTTP Status: <code>{$http_code}</code><br>";
        
        if ($http_code === 400 || $http_code === 401) {
            echo "✅ <strong>Org Authorization Server is available!</strong><br>";
            echo "<div style='background: #d1ecf1; padding: 10px; margin: 10px 0; border: 1px solid #bee5eb; border-radius: 4px;'>";
            echo "<strong>💡 Solution: Use Org Authorization Server</strong><br>";
            echo "Your Okta org supports the simpler org-level OIDC. This uses:<br>";
            echo "• Authorization URL: <code>https://lucid.okta.com/oauth2/v1/authorize</code><br>";
            echo "• Token URL: <code>https://lucid.okta.com/oauth2/v1/token</code><br>";
            echo "• UserInfo URL: <code>https://lucid.okta.com/oauth2/v1/userinfo</code><br>";
            echo "• Issuer: <code>https://lucid.okta.com</code><br>";
            echo "</div>";
        } else {
            echo "❌ Org authorization server also not available (HTTP {$http_code})<br>";
        }
    }
    
    // Test 4: Network diagnostics
    echo "<h3>4. Network Diagnostics</h3>";
    
    echo "<h4>Server Information:</h4>";
    echo "• Server IP: <code>" . ($_SERVER['SERVER_ADDR'] ?? 'Unknown') . "</code><br>";
    echo "• Server Name: <code>" . ($_SERVER['SERVER_NAME'] ?? 'Unknown') . "</code><br>";
    echo "• User Agent: <code>" . ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown') . "</code><br>";
    
    echo "<h4>PHP Configuration:</h4>";
    echo "• allow_url_fopen: <code>" . (ini_get('allow_url_fopen') ? 'Enabled' : 'Disabled') . "</code><br>";
    echo "• cURL version: <code>" . (function_exists('curl_version') ? curl_version()['version'] : 'Not available') . "</code><br>";
    echo "• OpenSSL version: <code>" . (defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'Not available') . "</code><br>";
    
    // Test 5: Try curl command for troubleshooting
    echo "<h3>5. Manual Testing Commands</h3>";
    echo "<p>If you have shell access, try these commands to test connectivity:</p>";
    echo "<pre style='background: #f8f9fa; padding: 10px; border: 1px solid #dee2e6;'>";
    echo "# Test DNS resolution\n";
    echo "nslookup {$test_domain}\n\n";
    echo "# Test HTTPS connectivity\n";
    echo "curl -v https://{$test_domain}/\n\n";
    echo "# Test well-known endpoint\n";
    echo "curl -v https://{$test_domain}/oauth2/default/.well-known/openid_configuration\n";
    echo "curl -v https://{$test_domain}/.well-known/openid_configuration\n";
    echo "</pre>";
    
    // Test 6: Common issues and solutions
    echo "<h3>6. Common Issues & Solutions</h3>";
    echo "<div style='background: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 4px;'>";
    echo "<h4>🔧 If all tests are failing:</h4>";
    echo "<ul>";
    echo "<li><strong>Domain Issues:</strong>";
    echo "<ul>";
    echo "<li>Make sure you're using the correct Okta domain format</li>";
    echo "<li>Common formats: <code>dev-12345.okta.com</code>, <code>company.okta.com</code>, <code>company.oktapreview.com</code></li>";
    echo "<li>Do NOT include <code>https://</code> in the domain field</li>";
    echo "</ul></li>";
    echo "<li><strong>Network Issues:</strong>";
    echo "<ul>";
    echo "<li>Check if your server can access external HTTPS sites</li>";
    echo "<li>Verify firewall allows outbound HTTPS (port 443)</li>";
    echo "<li>Check for corporate proxy settings</li>";
    echo "</ul></li>";
    echo "<li><strong>Okta Configuration:</strong>";
    echo "<ul>";
    echo "<li>Verify your Okta org is active and accessible</li>";
    echo "<li>Make sure you have admin access to the Okta org</li>";
    echo "<li>Check if the authorization server is enabled</li>";
    echo "</ul></li>";
    echo "</ul>";
    echo "</div>";
    
} else {
    echo "<p>Enter your Okta domain above to start testing.</p>";
}

echo "<hr>";
echo "<h3>📋 Current Configuration</h3>";
if (!empty($okta_config)) {
    echo "<pre>";
    echo "Configured Domain: " . ($okta_config['okta_domain'] ?? 'Not set') . "\n";
    echo "Client ID: " . (empty($okta_config['client_id']) ? 'Not set' : substr($okta_config['client_id'], 0, 10) . '...') . "\n";
    echo "SSO Enabled: " . ($okta_config['enabled'] ? 'Yes' : 'No') . "\n";
    echo "Local Fallback: " . ($okta_config['allow_local_fallback'] ? 'Yes' : 'No') . "\n";
    echo "</pre>";
} else {
    echo "❌ No Okta configuration found. Please configure Okta first.";
}

echo '<p><a href="pages/okta_config.php">← Back to Okta Configuration</a></p>';
?>
