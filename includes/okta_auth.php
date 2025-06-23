<?php
// includes/okta_auth.php - FIXED VERSION with correct paths
class OktaAuth {
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
        
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;
        
        $params = [
            'client_id' => $client_id,
            'response_type' => 'code',
            'scope' => 'openid email profile groups',
            'redirect_uri' => $redirect_uri,
            'state' => $state
        ];
        
        return "https://{$domain}/oauth2/default/v1/authorize?" . http_build_query($params);
    }
    
    public function handle_callback($code, $state) {
        if (!$this->is_enabled()) {
            throw new Exception('Okta SSO is not enabled');
        }
        
        // Verify state
        if (empty($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid state parameter');
        }
        unset($_SESSION['oauth_state']);
        
        // Exchange code for tokens
        $token_data = $this->exchange_code_for_tokens($code);
        
        // Get user info
        $user_info = $this->get_user_info($token_data['access_token']);
        
        // Process user and set session
        return $this->process_user($user_info);
    }
    
    private function exchange_code_for_tokens($code) {
        $domain = $this->config['okta_domain'];
        $client_id = $this->config['client_id'];
        $client_secret = $this->config['client_secret'];
        $redirect_uri = $this->config['redirect_uri'];
        
        $token_url = "https://{$domain}/oauth2/default/v1/token";
        
        $post_data = [
            'grant_type' => 'authorization_code',
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'code' => $code,
            'redirect_uri' => $redirect_uri
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            throw new Exception('Failed to exchange code for tokens: HTTP ' . $http_code);
        }
        
        $token_data = json_decode($response, true);
        if (!$token_data || !isset($token_data['access_token'])) {
            throw new Exception('Invalid token response');
        }
        
        return $token_data;
    }
    
    private function get_user_info($access_token) {
        $domain = $this->config['okta_domain'];
        $userinfo_url = "https://{$domain}/oauth2/default/v1/userinfo";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $userinfo_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer {$access_token}",
            'Accept: application/json'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            throw new Exception('Failed to get user info: HTTP ' . $http_code);
        }
        
        $user_info = json_decode($response, true);
        if (!$user_info || !isset($user_info['email'])) {
            throw new Exception('Invalid user info response');
        }
        
        return $user_info;
    }
    
    private function process_user($user_info) {
        $email = $user_info['email'] ?? '';
        $name = $user_info['name'] ?? $user_info['preferred_username'] ?? $email;
        $groups = $user_info['groups'] ?? [];
        
        if (empty($email)) {
            throw new Exception('Email not provided by Okta');
        }
        
        // Determine role based on group membership
        $user_role = $this->determine_role($groups);
        
        // Set session
        $_SESSION['authenticated'] = true;
        $_SESSION['okta_authenticated'] = true;
        $_SESSION['username'] = $email;
        $_SESSION['email'] = $email;
        $_SESSION['name'] = $name;
        $_SESSION['role'] = $user_role['role'];
        $_SESSION['permissions'] = $user_role['permissions'];
        $_SESSION['groups'] = $groups;
        $_SESSION['login_time'] = time();
        $_SESSION['login_method'] = 'okta_sso';
        
        // Log the login
        $this->log_login($email, $groups, $user_role['role']);
        
        return true;
    }
    
    private function determine_role($groups) {
        $group_mappings = $this->config['group_mappings'] ?? [];
        $default_role = $this->config['default_role'] ?? 'viewer';
        
        // Define role permissions
        $role_permissions = [
            'admin' => ['submit', 'approve', 'view', 'manage', 'audit'],
            'approver' => ['approve', 'view'],
            'operator' => ['submit', 'view'],
            'viewer' => ['view']
        ];
        
        // Check for admin first (highest priority)
        if (!empty($group_mappings['admin_group']) && in_array($group_mappings['admin_group'], $groups)) {
            return ['role' => 'admin', 'permissions' => $role_permissions['admin']];
        }
        
        // Check for approver
        if (!empty($group_mappings['approver_group']) && in_array($group_mappings['approver_group'], $groups)) {
            return ['role' => 'approver', 'permissions' => $role_permissions['approver']];
        }
        
        // Check for operator
        if (!empty($group_mappings['operator_group']) && in_array($group_mappings['operator_group'], $groups)) {
            return ['role' => 'operator', 'permissions' => $role_permissions['operator']];
        }
        
        // Check for viewer
        if (!empty($group_mappings['viewer_group']) && in_array($group_mappings['viewer_group'], $groups)) {
            return ['role' => 'viewer', 'permissions' => $role_permissions['viewer']];
        }
        
        // Default role
        return ['role' => $default_role, 'permissions' => $role_permissions[$default_role] ?? ['view']];
    }
    
    private function log_login($email, $groups, $role) {
        $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
        $audit_logs[] = [
            'id' => uniqid('audit_', true),
            'timestamp' => date('c'),
            'action' => 'okta_login',
            'entry' => 'User Authentication',
            'user' => $email,
            'details' => "Okta SSO login - Role: {$role}, Groups: " . implode(', ', $groups),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
    }
    
    public function check_session() {
        if (!isset($_SESSION['okta_authenticated'])) {
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
        // Clear session
        session_destroy();
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
}
?>