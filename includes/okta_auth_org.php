<?php
// includes/okta_auth_org.php - Simplified Okta integration using org-level authorization server
class OktaAuthOrg {
    private $config_file;
    private $config;
    
    public function __construct() {
        $this->config_file = DATA_DIR . '/okta_config.json';
        $this->load_config();
    }
    
    private function load_config() {
        $this->config = read_json_file($this->config_file);
        if (empty($this->config)) {
            $this->config = ['enabled' => false];
        }
    }
    
    public function is_enabled() {
        return $this->config['enabled'] ?? false;
    }
    
    public function allow_local_fallback() {
        return $this->config['allow_local_fallback'] ?? true;
    }
    
    public function get_authorization_url() {
        if (!$this->is_enabled()) {
            throw new Exception('Okta SSO is not enabled');
        }
        
        $domain = $this->config['okta_domain'] ?? '';
        $client_id = $this->config['client_id'] ?? '';
        $redirect_uri = $this->config['redirect_uri'] ?? '';
        
        if (empty($domain) || empty($client_id) || empty($redirect_uri)) {
            throw new Exception('Okta configuration incomplete');
        }
        
        // Generate state for CSRF protection
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;
        
        // Generate PKCE parameters for enhanced security
        $code_verifier = $this->generateCodeVerifier();
        $code_challenge = $this->generateCodeChallenge($code_verifier);
        $_SESSION['oauth_code_verifier'] = $code_verifier;
        
        // Store org-level endpoints for consistency
        $_SESSION['okta_endpoints'] = [
            'authorization' => "https://{$domain}/oauth2/v1/authorize",
            'token' => "https://{$domain}/oauth2/v1/token",
            'userinfo' => "https://{$domain}/oauth2/v1/userinfo",
            'issuer' => "https://{$domain}"
        ];
        
        // Build authorization URL using org-level endpoint
        $params = [
            'client_id' => $client_id,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'redirect_uri' => $redirect_uri,
            'state' => $state,
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256'
        ];
        
        error_log("DEBUG: Using org-level authorization server for domain: {$domain}");
        return "https://{$domain}/oauth2/v1/authorize?" . http_build_query($params);
    }
    
    public function handle_callback($code, $state) {
        if (!$this->is_enabled()) {
            throw new Exception('Okta SSO is not enabled');
        }
        
        // Verify state parameter for CSRF protection
        if (empty($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid state parameter - possible CSRF attack');
        }
        unset($_SESSION['oauth_state']);
        
        // Get code verifier for PKCE
        $code_verifier = $_SESSION['oauth_code_verifier'] ?? '';
        unset($_SESSION['oauth_code_verifier']);
        
        if (empty($code_verifier)) {
            throw new Exception('Missing code verifier - PKCE flow incomplete');
        }
        
        // Exchange authorization code for tokens
        $token_data = $this->exchange_code_for_tokens($code, $code_verifier);
        
        // Validate and decode ID token
        $id_token_payload = $this->validate_id_token($token_data['id_token'] ?? '');
        
        // Get additional user info if needed
        $user_info = [];
        if (!empty($token_data['access_token'])) {
            try {
                $user_info = $this->get_user_info($token_data['access_token']);
            } catch (Exception $e) {
                // User info endpoint might fail, use ID token claims instead
                error_log('UserInfo endpoint failed: ' . $e->getMessage());
            }
        }
        
        // Merge ID token claims with user info
        $user_data = array_merge($id_token_payload, $user_info);
        
        // Process user and set session
        return $this->process_user($user_data);
    }
    
    private function exchange_code_for_tokens($code, $code_verifier) {
        $domain = $this->config['okta_domain'];
        $client_id = $this->config['client_id'];
        $client_secret = $this->config['client_secret'];
        $redirect_uri = $this->config['redirect_uri'];
        
        // Use org-level token endpoint
        $token_url = "https://{$domain}/oauth2/v1/token";
        
        $post_data = [
            'grant_type' => 'authorization_code',
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'code' => $code,
            'redirect_uri' => $redirect_uri,
            'code_verifier' => $code_verifier
        ];
        
        error_log("DEBUG: Using org-level token endpoint: " . $token_url);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
            'User-Agent: EDL-Manager/2.0'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);
        
        if ($response === false) {
            throw new Exception('Token request failed: ' . $curl_error);
        }
        
        if ($http_code !== 200) {
            $error_data = json_decode($response, true);
            $error_message = $error_data['error_description'] ?? $error_data['error'] ?? 'Unknown error';
            error_log("DEBUG: Token exchange failed. Response: " . $response);
            throw new Exception("Token exchange failed (HTTP {$http_code}): {$error_message}");
        }
        
        $token_data = json_decode($response, true);
        if (!$token_data || !isset($token_data['access_token'])) {
            throw new Exception('Invalid token response - missing access_token');
        }
        
        error_log("DEBUG: Token exchange successful using org-level endpoint");
        return $token_data;
    }
    
    private function validate_id_token($id_token) {
        if (empty($id_token)) {
            throw new Exception('ID token is required but missing');
        }
        
        // Basic JWT structure validation
        $parts = explode('.', $id_token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid ID token format');
        }
        
        // Decode payload (skip signature validation for simplicity)
        $payload = json_decode(base64_decode(str_pad(strtr($parts[1], '-_', '+/'), strlen($parts[1]) % 4, '=', STR_PAD_RIGHT)), true);
        
        if (!$payload) {
            throw new Exception('Invalid ID token payload');
        }
        
        $domain = $this->config['okta_domain'];
        $expected_issuer = "https://{$domain}";
        $actual_issuer = $payload['iss'] ?? 'not set';
        
        error_log("DEBUG: Expected issuer (org-level): " . $expected_issuer);
        error_log("DEBUG: Actual ID token issuer: " . $actual_issuer);
        
        // Basic validation
        $now = time();
        if (isset($payload['exp']) && $payload['exp'] < $now) {
            throw new Exception('ID token has expired');
        }
        
        if (isset($payload['iat']) && $payload['iat'] > ($now + 300)) {
            throw new Exception('ID token issued in the future');
        }
        
        // Validate audience
        $expected_audience = $this->config['client_id'];
        if (isset($payload['aud']) && $payload['aud'] !== $expected_audience) {
            throw new Exception("ID token audience mismatch. Expected: {$expected_audience}, Got: {$payload['aud']}");
        }
        
        // Validate issuer (org-level should be https://domain)
        if (isset($payload['iss']) && $payload['iss'] !== $expected_issuer) {
            throw new Exception("ID token issuer mismatch. Expected: {$expected_issuer}, Got: {$actual_issuer}");
        }
        
        error_log("DEBUG: ID token validation passed for org-level authorization server");
        return $payload;
    }
    
    private function get_user_info($access_token) {
        $domain = $this->config['okta_domain'];
        $userinfo_url = "https://{$domain}/oauth2/v1/userinfo";
        
        error_log("DEBUG: Using org-level userinfo endpoint: " . $userinfo_url);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $userinfo_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer {$access_token}",
            'Accept: application/json',
            'User-Agent: EDL-Manager/2.0'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);
        
        if ($response === false) {
            throw new Exception('UserInfo request failed: ' . $curl_error);
        }
        
        if ($http_code !== 200) {
            error_log("DEBUG: UserInfo request failed. HTTP {$http_code}, Response: " . $response);
            throw new Exception("UserInfo request failed: HTTP {$http_code}");
        }
        
        $user_info = json_decode($response, true);
        if (!$user_info) {
            throw new Exception('Invalid UserInfo response');
        }
        
        error_log("DEBUG: UserInfo retrieved successfully from org-level endpoint");
        return $user_info;
    }
    
    private function process_user($user_data) {
        // Extract user information with fallbacks
        $email = $user_data['email'] ?? $user_data['preferred_username'] ?? '';
        $name = $user_data['name'] ?? $user_data['given_name'] . ' ' . $user_data['family_name'] ?? $email;
        $name = trim($name);
        
        // Handle groups - they might be in different places depending on Okta config
        $groups = [];
        if (isset($user_data['groups']) && is_array($user_data['groups'])) {
            $groups = $user_data['groups'];
        } elseif (isset($user_data['Groups']) && is_array($user_data['Groups'])) {
            $groups = $user_data['Groups'];
        }
        
        if (empty($email)) {
            throw new Exception('Email address is required but not provided by Okta');
        }
        
        // Determine user role based on group membership
        $user_role = $this->determine_role($groups);
        
        // Set session variables - BOTH authenticated and okta_authenticated
        $_SESSION['authenticated'] = true;
        $_SESSION['okta_authenticated'] = true;
        $_SESSION['username'] = $email;
        $_SESSION['email'] = $email;
        $_SESSION['name'] = $name ?: $email;
        $_SESSION['role'] = $user_role['role'];
        $_SESSION['permissions'] = $user_role['permissions'];
        $_SESSION['groups'] = $groups;
        $_SESSION['login_time'] = time();
        $_SESSION['login_method'] = 'okta_sso_org';
        
        // Store additional Okta data for debugging/auditing
        $_SESSION['okta_sub'] = $user_data['sub'] ?? '';
        $_SESSION['okta_iss'] = $user_data['iss'] ?? '';
        
        // Log the successful login
        $this->log_login($email, $groups, $user_role['role'], $user_data);
        
        error_log("DEBUG: User session created successfully for: " . $email);
        return true;
    }
    
    private function determine_role($groups) {
        $group_mappings = $this->config['group_mappings'] ?? [];
        $default_role = $this->config['default_role'] ?? 'viewer';
        
        // Role hierarchy (highest to lowest)
        $role_hierarchy = [
            'admin' => [
                'role' => 'admin',
                'permissions' => ['view', 'submit', 'approve', 'manage']
            ],
            'approver' => [
                'role' => 'approver', 
                'permissions' => ['view', 'submit', 'approve']
            ],
            'operator' => [
                'role' => 'operator',
                'permissions' => ['view', 'submit']
            ],
            'viewer' => [
                'role' => 'viewer',
                'permissions' => ['view']
            ]
        ];
        
        // Check groups against mappings (highest role wins)
        foreach (['admin', 'approver', 'operator', 'viewer'] as $role) {
            $mapped_group = $group_mappings[$role . '_group'] ?? '';
            if (!empty($mapped_group) && in_array($mapped_group, $groups)) {
                return $role_hierarchy[$role];
            }
        }
        
        // Default role if no group matches
        return $role_hierarchy[$default_role] ?? $role_hierarchy['viewer'];
    }
    
    private function log_login($email, $groups, $role, $user_data) {
        // Add to audit log
        $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
        $audit_logs[] = [
            'id' => uniqid('audit_', true),
            'timestamp' => date('c'),
            'action' => 'user_login_okta_org',
            'entry' => 'User Login via Okta SSO (Org-Level)',
            'user' => $email,
            'details' => 'Role: ' . $role . ', Groups: ' . implode(', ', $groups),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'okta_subject' => $user_data['sub'] ?? '',
            'okta_issuer' => $user_data['iss'] ?? ''
        ];
        write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
    }
    
    public function check_session() {
        // Check both authenticated flags
        if (!isset($_SESSION['authenticated']) || !isset($_SESSION['okta_authenticated'])) {
            return false;
        }
        
        // Check session timeout
        if (isset($_SESSION['login_time']) && 
            (time() - $_SESSION['login_time']) > SESSION_TIMEOUT) {
            $this->logout();
            return false;
        }
        
        return true;
    }
    
    public function logout() {
        // Get Okta domain for logout URL
        $okta_domain = $this->config['okta_domain'] ?? '';
        
        // Clear local session
        session_destroy();
        
        // Redirect to Okta logout if domain is configured
        if (!empty($okta_domain)) {
            $logout_url = "https://{$okta_domain}/oauth2/v1/logout";
            $base_path = $this->get_base_path();
            $post_logout_redirect = urlencode("https://" . $_SERVER['HTTP_HOST'] . $base_path . 'login.php');
            
            header("Location: {$logout_url}?post_logout_redirect_uri={$post_logout_redirect}");
            exit;
        }
    }
    
    public function require_auth() {
        if (!$this->check_session()) {
            $base_path = $this->get_base_path();
            header('Location: ' . $base_path . 'login.php');
            exit;
        }
    }
    
    private function get_base_path() {
        // Get the correct base path for the application
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        
        if (strpos($script_name, '/') !== false) {
            $path_parts = explode('/', trim($script_name, '/'));
            if (count($path_parts) > 1) {
                // Remove the last part (filename) and keep directory structure
                array_pop($path_parts);
                return '/' . implode('/', $path_parts) . '/';
            }
        }
        
        return '/';
    }
    
    // PKCE helper methods
    private function generateCodeVerifier() {
        return bin2hex(random_bytes(32));
    }
    
    private function generateCodeChallenge($code_verifier) {
        return rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
    }
    
    // Test connection method for admin interface
    public function test_connection() {
        $domain = $this->config['okta_domain'] ?? '';
        if (empty($domain)) {
            return ['success' => false, 'message' => 'Okta domain not configured'];
        }
        
        // Test org-level authorization endpoint
        $auth_url = "https://{$domain}/oauth2/v1/authorize";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $auth_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'EDL-Manager/2.0');
        curl_setopt($ch, CURLOPT_NOBODY, true); // HEAD request to avoid needing parameters
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);
        
        if ($response === false) {
            return ['success' => false, 'message' => 'Connection failed: ' . $curl_error];
        }
        
        // 400 or 401 are expected for authorization endpoint without proper parameters
        if ($http_code === 400 || $http_code === 401) {
            return [
                'success' => true,
                'message' => 'Successfully connected to Okta (Org Authorization Server)',
                'auth_server' => 'Org Authorization Server',
                'endpoints' => [
                    'authorization' => "https://{$domain}/oauth2/v1/authorize",
                    'token' => "https://{$domain}/oauth2/v1/token",
                    'userinfo' => "https://{$domain}/oauth2/v1/userinfo",
                    'issuer' => "https://{$domain}"
                ]
            ];
        } else {
            return [
                'success' => false,
                'message' => "Unexpected response from authorization server: HTTP {$http_code}"
            ];
        }
    }
}
?>
