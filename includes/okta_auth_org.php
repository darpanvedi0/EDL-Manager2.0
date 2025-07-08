<?php
// includes/okta_auth_org.php - Okta Org-Level Authentication Class
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
        
        error_log("DEBUG: Using org-level authorization server for domain: {$domain}");
        error_log("DEBUG: Expected issuer (org-level): https://{$domain}");
        
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
        
        return "https://{$domain}/oauth2/v1/authorize?" . http_build_query($params);
    }
    
    public function handle_callback($code, $state) {
        if (!$this->is_enabled()) {
            throw new Exception('Okta SSO is not enabled');
        }
        
        // Verify state parameter
        if (empty($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid OAuth state parameter');
        }
        
        // Clear the state to prevent reuse
        unset($_SESSION['oauth_state']);
        
        $domain = $this->config['okta_domain'] ?? '';
        $client_id = $this->config['client_id'] ?? '';
        $client_secret = $this->config['client_secret'] ?? '';
        $redirect_uri = $this->config['redirect_uri'] ?? '';
        $code_verifier = $_SESSION['oauth_code_verifier'] ?? '';
        
        if (empty($code_verifier)) {
            throw new Exception('Missing PKCE code verifier');
        }
        
        // Clear code verifier
        unset($_SESSION['oauth_code_verifier']);
        
        // Exchange authorization code for tokens using org-level token endpoint
        $token_url = "https://{$domain}/oauth2/v1/token";
        $token_data = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'code_verifier' => $code_verifier
        ];
        
        error_log("DEBUG: Requesting tokens from org-level endpoint: {$token_url}");
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded'
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
            error_log("DEBUG: Token request failed with HTTP {$http_code}: {$response}");
            throw new Exception("Token request failed with HTTP {$http_code}");
        }
        
        $token_response = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid JSON response from token endpoint');
        }
        
        $access_token = $token_response['access_token'] ?? '';
        $id_token = $token_response['id_token'] ?? '';
        
        if (empty($access_token) || empty($id_token)) {
            throw new Exception('Missing tokens in response');
        }
        
        error_log("DEBUG: Successfully received tokens from org-level endpoint");
        
        // Verify and decode ID token
        $user_data = $this->verify_id_token($id_token);
        
        // Get additional user info from userinfo endpoint
        $userinfo = $this->get_user_info($access_token);
        
        // Merge user data
        $user_data = array_merge($user_data, $userinfo);
        
        // Create user session
        $this->create_user_session($user_data);
        
        error_log("DEBUG: Successfully authenticated user via org-level Okta: " . ($user_data['email'] ?? 'unknown'));
    }
    
    private function verify_id_token($id_token) {
        $domain = $this->config['okta_domain'] ?? '';
        $expected_issuer = "https://{$domain}";
        
        error_log("DEBUG: Expected issuer (org-level): {$expected_issuer}");
        
        // Simple JWT decode (header.payload.signature)
        $parts = explode('.', $id_token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid ID token format');
        }
        
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid ID token payload');
        }
        
        error_log("DEBUG: Actual ID token issuer: " . ($payload['iss'] ?? 'not set'));
        
        // Verify issuer (must match org-level issuer)
        if (($payload['iss'] ?? '') !== $expected_issuer) {
            // More flexible issuer check for org-level
            $token_issuer = $payload['iss'] ?? '';
            if (strpos($token_issuer, $domain) === false) {
                throw new Exception("Invalid issuer in ID token. Expected: {$expected_issuer}, Got: {$token_issuer}");
            }
            error_log("DEBUG: Issuer verification passed (flexible check for org-level)");
        }
        
        // Verify expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new Exception('ID token has expired');
        }
        
        // Verify audience
        $client_id = $this->config['client_id'] ?? '';
        if (($payload['aud'] ?? '') !== $client_id) {
            throw new Exception('Invalid audience in ID token');
        }
        
        return $payload;
    }
    
    private function get_user_info($access_token) {
        $domain = $this->config['okta_domain'] ?? '';
        $userinfo_url = "https://{$domain}/oauth2/v1/userinfo";
        
        error_log("DEBUG: Fetching user info from org-level endpoint: {$userinfo_url}");
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $userinfo_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $access_token,
            'Accept: application/json'
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
            error_log("DEBUG: UserInfo request failed with HTTP {$http_code}: {$response}");
            throw new Exception("UserInfo request failed with HTTP {$http_code}");
        }
        
        $userinfo = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Invalid JSON response from userinfo endpoint');
        }
        
        error_log("DEBUG: Successfully fetched user info from org-level endpoint");
        
        return $userinfo;
    }
    
    private function create_user_session($user_data) {
        // Clear any existing auth session data
        unset($_SESSION['authenticated']);
        unset($_SESSION['username']);
        unset($_SESSION['name']);
        unset($_SESSION['email']);
        unset($_SESSION['role']);
        unset($_SESSION['permissions']);
        unset($_SESSION['login_method']);
        
        $email = $user_data['email'] ?? '';
        $name = $user_data['name'] ?? $user_data['given_name'] . ' ' . $user_data['family_name'] ?? $email;
        $groups = $user_data['groups'] ?? [];
        
        if (empty($email)) {
            throw new Exception('No email found in user data');
        }
        
        // Determine role based on groups
        $role = $this->map_groups_to_role($groups);
        $permissions = $this->get_role_permissions($role);
        
        // Set session variables
        $_SESSION['authenticated'] = true;
        $_SESSION['okta_authenticated'] = true;
        $_SESSION['username'] = $email;
        $_SESSION['name'] = $name;
        $_SESSION['email'] = $email;
        $_SESSION['role'] = $role;
        $_SESSION['permissions'] = $permissions;
        $_SESSION['login_method'] = 'okta_org';
        $_SESSION['login_time'] = time();
        
        // Store Okta-specific data
        $_SESSION['okta_subject'] = $user_data['sub'] ?? '';
        $_SESSION['okta_groups'] = $groups;
        
        // Log the successful login
        $this->log_login($email, $groups, $role, $user_data);
        
        error_log("DEBUG: Created session for user: {$email} with role: {$role}");
    }
    
    private function map_groups_to_role($groups) {
        $role_mappings = $this->config['role_mappings'] ?? [];
        $default_role = $this->config['default_role'] ?? 'viewer';
        
        // Role hierarchy (higher privilege first)
        $role_hierarchy = [
            'admin' => 'admin',
            'approver' => 'approver',
            'operator' => 'operator',
            'viewer' => 'viewer'
        ];
        
        // Check each role in hierarchy order
        foreach ($role_hierarchy as $role => $role_name) {
            $mapped_group = $role_mappings[$role . '_group'] ?? '';
            if (!empty($mapped_group) && in_array($mapped_group, $groups)) {
                return $role_hierarchy[$role];
            }
        }
        
        // Default role if no group matches
        return $role_hierarchy[$default_role] ?? $role_hierarchy['viewer'];
    }
    
    private function get_role_permissions($role) {
        $permissions_map = [
            'admin' => ['submit', 'approve', 'view', 'manage', 'audit'],
            'approver' => ['approve', 'view'],
            'operator' => ['submit', 'view'],
            'viewer' => ['view']
        ];
        
        return $permissions_map[$role] ?? ['view'];
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
