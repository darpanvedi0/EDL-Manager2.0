<?php
// includes/auth.php - FIXED VERSION with corrected login redirect
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
                    'name' => 'Security Operator',
                    'email' => 'operator@company.com',
                    'role' => 'operator',
                    'permissions' => ['submit', 'view']
                ]
            ];
            
            if (function_exists('write_json_file')) {
                write_json_file($this->users_file, $default_users);
            } else {
                file_put_contents($this->users_file, json_encode($default_users, JSON_PRETTY_PRINT));
            }
        }
    }
    
    public function authenticate($username, $password) {
        $users = $this->load_users();
        
        if (isset($users[$username])) {
            if (password_verify($password, $users[$username]['password'])) {
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['name'] = $users[$username]['name'];
                $_SESSION['email'] = $users[$username]['email'];
                $_SESSION['role'] = $users[$username]['role'];
                $_SESSION['permissions'] = $users[$username]['permissions'];
                $_SESSION['login_time'] = time();
                
                return true;
            }
        }
        
        return false;
    }
    
    public function logout() {
        session_destroy();
    }
    
    public function check_session() {
        if (!$this->is_authenticated()) {
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
    
    public function is_authenticated() {
        return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
    }
    
    public function has_permission($permission) {
        if (!$this->is_authenticated()) return false;
        return in_array($permission, $_SESSION['permissions'] ?? []);
    }
    
    public function require_auth() {
        if (!$this->check_session()) {
            // Get the correct base path for redirects - FIXED to always point to login.php in root
            $base_path = $this->get_app_root_path();
            header('Location: ' . $base_path . 'login.php');
            exit;
        }
    }
    
    public function require_permission($permission) {
        $this->require_auth();
        if (!$this->has_permission($permission)) {
            if (function_exists('show_flash')) {
                show_flash('Insufficient permissions', 'danger');
            }
            $base_path = $this->get_app_root_path();
            header('Location: ' . $base_path . 'index.php');
            exit;
        }
    }
    
    private function get_app_root_path() {
        // FIXED: Always return the application root path, regardless of current page location
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        
        // Extract the application root by finding the EDL-Manager2.0 directory
        if (strpos($script_name, '/') !== false) {
            $path_parts = explode('/', trim($script_name, '/'));
            
            // Find the application root (could be EDL-Manager2.0 or just root)
            $app_root_parts = [];
            foreach ($path_parts as $part) {
                if ($part === 'pages' || $part === 'api' || $part === 'okta' || pathinfo($part, PATHINFO_EXTENSION) === 'php') {
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
    
    // Keep the old method for backward compatibility but fix it too
    private function get_base_path() {
        return $this->get_app_root_path();
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
        // FIXED: Get the application root path correctly
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        
        if (strpos($script_name, '/') !== false) {
            $path_parts = explode('/', trim($script_name, '/'));
            
            // Find the application root
            $app_root_parts = [];
            foreach ($path_parts as $part) {
                if ($part === 'pages' || $part === 'api' || $part === 'okta' || pathinfo($part, PATHINFO_EXTENSION) === 'php') {
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
}
?>