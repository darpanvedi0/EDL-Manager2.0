<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Load required files in correct order
require_once 'config/config.php';
require_once 'includes/functions.php';
require_once 'includes/auth.php';

$auth = new EDLAuth();
$error_message = '';

// Redirect if already authenticated
if ($auth->check_session()) {
    header('Location: index.php');
    exit;
}

// Handle login submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitize_input($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error_message = 'Please enter both username and password.';
    } else {
        if ($auth->authenticate($username, $password)) {
            header('Location: index.php');
            exit;
        } else {
            $error_message = 'Invalid username or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            padding: 0;
            overflow: hidden;
            max-width: 400px;
            width: 100%;
        }
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        .login-body {
            padding: 2rem;
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e9ecef;
            padding: 12px;
            font-size: 16px;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 12px;
            font-weight: 600;
            font-size: 16px;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .demo-accounts {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1rem;
            margin-top: 1rem;
        }
        .demo-btn {
            font-size: 12px;
            padding: 5px 10px;
            margin: 2px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
            background: white;
            cursor: pointer;
            transition: all 0.2s;
        }
        .demo-btn:hover {
            background: #e9ecef;
            transform: translateY(-1px);
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h3 class="mb-2">
                <i class="fas fa-shield-alt"></i>
                <?php echo APP_NAME; ?>
            </h3>
            <p class="mb-0 opacity-75">External Dynamic List Manager</p>
        </div>
        
        <div class="login-body">
            <?php if ($error_message): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <?php echo htmlspecialchars($error_message); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="needs-validation" novalidate>
                <div class="mb-3">
                    <label for="username" class="form-label fw-bold">Username</label>
                    <div class="input-group">
                        <span class="input-group-text bg-light">
                            <i class="fas fa-user text-muted"></i>
                        </span>
                        <input type="text" class="form-control" id="username" name="username" 
                               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                               required autocomplete="username" autofocus
                               placeholder="Enter your username">
                    </div>
                </div>
                
                <div class="mb-4">
                    <label for="password" class="form-label fw-bold">Password</label>
                    <div class="input-group">
                        <span class="input-group-text bg-light">
                            <i class="fas fa-lock text-muted"></i>
                        </span>
                        <input type="password" class="form-control" id="password" name="password" 
                               required autocomplete="current-password"
                               placeholder="Enter your password">
                        <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary btn-login">
                        <i class="fas fa-sign-in-alt me-2"></i>
                        Sign In
                    </button>
                </div>
            </form>
            
            <div class="demo-accounts">
                <h6 class="text-primary mb-2">
                    <i class="fas fa-vial"></i> Demo Accounts
                </h6>
                <div class="d-flex flex-wrap gap-1">
                    <button class="demo-btn" onclick="fillCredentials('admin', 'admin123')">
                        <i class="fas fa-user-shield"></i> Admin
                    </button>
                    <button class="demo-btn" onclick="fillCredentials('approver', 'approver123')">
                        <i class="fas fa-user-check"></i> Approver
                    </button>
                    <button class="demo-btn" onclick="fillCredentials('operator', 'operator123')">
                        <i class="fas fa-user-edit"></i> Operator
                    </button>
                    <button class="demo-btn" onclick="clearCredentials()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                </div>
                <small class="text-muted d-block mt-2">
                    Click any demo account button to auto-fill credentials
                </small>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password toggle
        document.getElementById('togglePassword').addEventListener('click', function() {
            const password = document.getElementById('password');
            const icon = this.querySelector('i');
            
            if (password.type === 'password') {
                password.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                password.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
        
        // Demo account functions
        function fillCredentials(username, password) {
            document.getElementById('username').value = username;
            document.getElementById('password').value = password;
            
            // Visual feedback
            const form = document.querySelector('form');
            form.style.animation = 'none';
            form.offsetHeight; // Trigger reflow
            form.style.animation = 'pulse 0.5s';
        }
        
        function clearCredentials() {
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('username').focus();
        }
        
        // Form validation
        (function() {
            const forms = document.querySelectorAll('.needs-validation');
            Array.prototype.slice.call(forms).forEach(function(form) {
                form.addEventListener('submit', function(event) {
                    if (!form.checkValidity()) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                });
            });
        })();
        
        // Add some animations
        document.addEventListener('DOMContentLoaded', function() {
            const loginContainer = document.querySelector('.login-container');
            loginContainer.style.opacity = '0';
            loginContainer.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                loginContainer.style.transition = 'all 0.5s ease';
                loginContainer.style.opacity = '1';
                loginContainer.style.transform = 'translateY(0)';
            }, 100);
        });
    </script>
    
    <style>
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.02); }
            100% { transform: scale(1); }
        }
    </style>
</body>
</html>