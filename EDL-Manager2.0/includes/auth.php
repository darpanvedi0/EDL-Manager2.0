<?php
// EDL Manager Authentication - FIXED VERSION

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
            header('Location: /login.php');
            exit;
        }
    }
    
    public function require_permission($permission) {
        $this->require_auth();
        if (!$this->has_permission($permission)) {
            if (function_exists('show_flash')) {
                show_flash('Insufficient permissions', 'danger');
            }
            header('Location: /index.php');
            exit;
        }
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
?>