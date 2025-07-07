<?php
// includes/auth.php - FIXED VERSION to prevent Okta session conflicts
class EDLAuth {
    private $users_file;
    
    public function __construct() {
        // Ensure functions.php is loaded
        if (!function_exists('read_json_file')) {
            require_once dirname(__FILE__) . '/functions.php';
        }
        
        $this->users_file = DATA_DIR . '/users.json';
        $this->init_users();
    }
    
    private function init_users() {
        if (!file_exists($this->users_file)) {
            $default_users = [
                'admin' => [
                    'password' => '$2a$12$2NYBgFYaLKinqcdxS4l7xuoq5yxGkDB9pDRR0u1xg5GgHhJcSoLTK',
                    'name' => 'System Administrator',
                    'email' => 'admin@company.com',
                    'role' => 'admin',
                    'permissions' => ['submit', 'approve', 'view', 'manage', 'audit']
                ],
                'approver' => [
                    'password' => '$2a$12$5rKDqsbdZLe8t82K.weTnOtwDFtkOf/gp3yyWf7fF.p38l0SKVrOK',
                    'name' => 'Security Approver',
                    'email' => 'approver@company.com',
                    'role' => 'approver',
                    'permissions' => ['approve', 'view']
                ],
                'operator' => [
                    'password' => '$2a$12$3Vqfxz27vp98UviY152seuMM/bd8X4FYqEBkVIKwudVQq7UtN17R.',
                    'name' => 'EDL Operator',
                    'email' => 'operator@company.com',
                    'role' => 'operator',
                    'permissions' => ['submit', 'view']
                ],
                'viewer' => [
                    'password' => '$2a$12$K5s4dGj6w6D9zQy0jLm3HeK.f9Y7zD3MKL4.5k8N2mR7vT8qA9cBu',
                    'name' => 'EDL Viewer',
                    'email' => 'viewer@company.com',
                    'role' => 'viewer',
                    'permissions' => ['view']
                ]
            ];
            
            $this->save_users($default_users);
        }
    }
    
    public function authenticate($username, $password) {
        // IMPORTANT: Clear any leftover Okta session data when doing local auth
        $this->clear_okta_session_data();
        
        $users = $this->load_users();
        
        if (!isset($users[$username])) {
            return false;
        }
        
        $user = $users[$username];
        
        if (!password_verify($password, $user['password'])) {
            return false;
        }
        
        // Set LOCAL authentication session
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['name'] = $user['name'] ?? $username;
        $_SESSION['email'] = $user['email'] ?? '';
        $_SESSION['role'] = $user['role'] ?? 'viewer';
        $_SESSION['permissions'] = $user['permissions'] ?? ['view'];
        $_SESSION['login_time'] = time();
        $_SESSION['login_method'] = 'local'; // Mark as local login
        
        // Explicitly clear Okta flags to prevent conflicts
        unset($_SESSION['okta_authenticated']);
        unset($_SESSION['okta_sub']);
        unset($_SESSION['okta_iss']);
        unset($_SESSION['groups']);
        
        return true;
    }
    
    /**
     * Clear any leftover Okta session data that might interfere with local auth
     */
    private function clear_okta_session_data() {
        $okta_keys = [
            'okta_authenticated',
            'oauth_state', 
            'oauth_code_verifier',
            'okta_sub',
            'okta_iss',
            'groups'
        ];
        
        foreach ($okta_keys as $key) {
            if (isset($_SESSION[$key])) {
                unset($_SESSION[$key]);
            }
        }
    }
    
    public function check_session() {
        // Only check the main authenticated flag for local auth
        if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
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
    
    public function require_auth() {
        if (!$this->check_session()) {
            $this->redirect_to_login();
        }
    }
    
    public function require_permission($permission) {
        if (!$this->check_session()) {
            $this->redirect_to_login();
        }
        
        if (!$this->has_permission($permission)) {
            http_response_code(403);
            die('Access denied. Required permission: ' . $permission);
        }
    }
    
    public function has_permission($permission) {
        if (!$this->check_session()) {
            return false;
        }
        
        $permissions = $_SESSION['permissions'] ?? [];
        return in_array($permission, $permissions);
    }
    
    public function get_user_info() {
        if (!$this->check_session()) {
            return null;
        }
        
        return [
            'username' => $_SESSION['username'] ?? '',
            'name' => $_SESSION['name'] ?? '',
            'email' => $_SESSION['email'] ?? '',
            'role' => $_SESSION['role'] ?? 'viewer',
            'permissions' => $_SESSION['permissions'] ?? [],
            'login_method' => $_SESSION['login_method'] ?? 'unknown'
        ];
    }
    
    public function logout() {
        // Clear all session data
        session_destroy();
        session_start(); // Start fresh session for flash messages
        
        if (function_exists('show_flash')) {
            show_flash('You have been logged out successfully.', 'info');
        }
        
        $this->redirect_to_login();
    }
    
    private function redirect_to_login() {
        if (!headers_sent()) {
            $base_path = $this->get_app_root_path();
            header('Location: ' . $base_path . 'login.php');
            exit;
        }
    }
    
    private function get_app_root_path() {
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        
        // Extract the application root by finding common subdirectories
        if (strpos($script_name, '/') !== false) {
            $path_parts = explode('/', trim($script_name, '/'));
            
            // Find the application root (stop at known subdirectories)
            $app_root_parts = [];
            foreach ($path_parts as $part) {
                if ($part === 'pages' || $part === 'api' || $part === 'okta' || 
                    $part === 'includes' || pathinfo($part, PATHINFO_EXTENSION) === 'php') {
                    // Stop when we hit a subdirectory or PHP file
                    break;
                }
                $app_root_parts[] = $part;
            }
            
            // Build the application root path
            if (!empty($app_root_parts)) {
                return '/' . implode('/', $app_root_parts) . '/';
            }
        }
        
        return '/';
    }
    
    private function load_users() {
        if (function_exists('read_json_file')) {
            return read_json_file($this->users_file);
        } else {
            if (file_exists($this->users_file)) {
                $content = file_get_contents($this->users_file);
                return $content ? json_decode($content, true) : [];
            }
            return [];
        }
    }
    
    private function save_users($users) {
        if (function_exists('write_json_file')) {
            return write_json_file($this->users_file, $users);
        } else {
            $dir = dirname($this->users_file);
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
            return file_put_contents($this->users_file, json_encode($users, JSON_PRETTY_PRINT));
        }
    }
}

// Helper functions that don't depend on functions.php
if (!function_exists('is_authenticated')) {
    function is_authenticated() {
        return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
    }
}

if (!function_exists('has_permission')) {
    function has_permission($permission) {
        if (!is_authenticated()) return false;
        return in_array($permission, $_SESSION['permissions'] ?? []);
    }
}

if (!function_exists('get_app_base_path')) {
    function get_app_base_path() {
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        
        if (strpos($script_name, '/') !== false) {
            $path_parts = explode('/', trim($script_name, '/'));
            
            // Find the application root
            $app_root_parts = [];
            foreach ($path_parts as $part) {
                if ($part === 'pages' || $part === 'api' || $part === 'okta' || 
                    $part === 'includes' || pathinfo($part, PATHINFO_EXTENSION) === 'php') {
                    break;
                }
                $app_root_parts[] = $part;
            }
            
            if (!empty($app_root_parts)) {
                return '/' . implode('/', $app_root_parts) . '/';
            }
        }
        
        return '/';
    }
}
?>
