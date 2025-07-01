<?php
// login.php - Fixed with proper Okta integration + Favicon + Matrix Binary Rain Background
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Load required files in correct order
require_once 'config/config.php';
require_once 'includes/functions.php';
require_once 'includes/auth.php';

// Check if Okta auth file exists and load it
$okta_enabled = false;
$allow_local_fallback = true;
if (file_exists('includes/okta_auth.php')) {
    require_once 'includes/okta_auth.php';
    $okta_auth = new OktaAuth();
    $okta_enabled = $okta_auth->is_enabled();
    $allow_local_fallback = $okta_auth->allow_local_fallback();
}

$auth = new EDLAuth();
$error_message = '';

// If Okta is enabled and no local fallback, redirect to Okta
if ($okta_enabled && !$allow_local_fallback) {
    header('Location: okta/login.php');
    exit;
}

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

// Handle error messages
$error_param = $_GET['error'] ?? '';
if ($error_param === 'okta_failed') {
    $error_message = 'Okta authentication failed. Please try again.';
}

$message_param = $_GET['message'] ?? '';
$info_message = '';
if ($message_param === 'logged_out') {
    $info_message = 'You have been successfully logged out.';
}

// Generate base64 encoded security shield favicon
$favicon_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
    <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea"/>
            <stop offset="100%" style="stop-color:#764ba2"/>
        </linearGradient>
    </defs>
    <path d="M16 2L6 6v8c0 6.5 4.2 12.6 10 14.8 5.8-2.2 10-8.3 10-14.8V6L16 2z" fill="url(#shieldGradient)" stroke="#fff" stroke-width="1"/>
    <path d="M16 8c-2.2 0-4 1.8-4 4v2h-1v6h10v-6h-1v-2c0-2.2-1.8-4-4-4zm0 2c1.1 0 2 0.9 2 2v2h-4v-2c0-1.1 0.9-2 2-2z" fill="#fff"/>
</svg>';
$favicon_base64 = 'data:image/svg+xml;base64,' . base64_encode($favicon_svg);

// Generate ICO format for better browser support
$favicon_ico_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
    <defs>
        <linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea"/>
            <stop offset="100%" style="stop-color:#764ba2"/>
        </linearGradient>
    </defs>
    <path d="M8 1L3 3v4c0 3.25 2.1 6.3 5 7.4 2.9-1.1 5-4.15 5-7.4V3L8 1z" fill="url(#sg)" stroke="#fff" stroke-width="0.5"/>
    <path d="M8 4c-1.1 0-2 0.9-2 2v1h-0.5v3h5v-3H10V6c0-1.1-0.9-2-2-2zm0 1c0.55 0 1 0.45 1 1v1H7V6c0-0.55 0.45-1 1-1z" fill="#fff"/>
</svg>';
$favicon_ico_base64 = 'data:image/svg+xml;base64,' . base64_encode($favicon_ico_svg);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo APP_NAME; ?></title>
    
    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="<?php echo $favicon_base64; ?>">
    <link rel="icon" type="image/png" href="<?php echo $favicon_ico_base64; ?>">
    <link rel="shortcut icon" href="<?php echo $favicon_ico_base64; ?>">
    <link rel="apple-touch-icon" href="<?php echo $favicon_base64; ?>">
    <meta name="theme-color" content="#667eea">
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1421;
            overflow: hidden;
            position: relative;
        }
        
        /* Matrix Binary Rain Background */
        #matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(180deg, #0d1421 0%, #1a252f 50%, #0d1421 100%);
            z-index: 1;
            overflow: hidden;
        }
        
        .matrix-column {
            position: absolute;
            top: -100px;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 14px;
            font-weight: bold;
            text-shadow: 0 0 5px #00ff41;
            white-space: pre;
            opacity: 0.8;
            animation: fall linear infinite;
        }
        
        .matrix-column.blue {
            color: #00bfff;
            text-shadow: 0 0 5px #00bfff;
        }
        
        .matrix-column.cyan {
            color: #00ffff;
            text-shadow: 0 0 5px #00ffff;
        }
        
        @keyframes fall {
            to {
                transform: translateY(100vh);
            }
        }
        
        /* Content overlay */
        .content-overlay {
            position: relative;
            z-index: 10;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: rgba(13, 20, 33, 0.3);
            backdrop-filter: blur(1px);
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 255, 65, 0.1), 
                        0 5px 15px rgba(0, 0, 0, 0.3),
                        inset 0 1px 0 rgba(255, 255, 255, 0.1);
            padding: 0;
            overflow: hidden;
            max-width: 420px;
            width: 100%;
            border: 1px solid rgba(0, 255, 65, 0.2);
            backdrop-filter: blur(10px);
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from {
                box-shadow: 0 15px 35px rgba(0, 255, 65, 0.1), 
                           0 5px 15px rgba(0, 0, 0, 0.3),
                           inset 0 1px 0 rgba(255, 255, 255, 0.1);
            }
            to {
                box-shadow: 0 15px 35px rgba(0, 255, 65, 0.2), 
                           0 5px 15px rgba(0, 0, 0, 0.4),
                           inset 0 1px 0 rgba(255, 255, 255, 0.2);
            }
        }
        
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2.5rem 2rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .login-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.1) 50%, transparent 70%);
            animation: shimmer 3s ease-in-out infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .login-header h3 {
            position: relative;
            z-index: 1;
            font-size: 1.8rem;
            font-weight: 300;
            letter-spacing: 1px;
        }
        
        .login-header p {
            position: relative;
            z-index: 1;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .login-body {
            padding: 2.5rem 2rem;
            background: rgba(255, 255, 255, 0.98);
        }
        
        .form-control {
            border-radius: 12px;
            border: 2px solid #e9ecef;
            padding: 14px 16px;
            font-size: 16px;
            background: rgba(255, 255, 255, 0.9);
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #00ff41;
            box-shadow: 0 0 0 0.2rem rgba(0, 255, 65, 0.25),
                        0 0 20px rgba(0, 255, 65, 0.1);
            background: rgba(255, 255, 255, 1);
        }
        
        .input-group-text {
            border-radius: 12px 0 0 12px;
            border: 2px solid #e9ecef;
            border-right: none;
            background: rgba(248, 249, 250, 0.9);
        }
        
        .form-control:focus + .input-group-text,
        .input-group-text:has(+ .form-control:focus) {
            border-color: #00ff41;
        }
        
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 12px;
            padding: 14px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }
        
        .btn-login::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn-login:hover::before {
            left: 100%;
        }
        
        .btn-okta {
            background: linear-gradient(135deg, #007acc 0%, #0056a3 100%);
            border: none;
            border-radius: 12px;
            padding: 14px;
            font-weight: 600;
            font-size: 16px;
            color: white;
            width: 100%;
            margin-bottom: 1rem;
            text-decoration: none;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .btn-okta:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 122, 204, 0.4);
            color: white;
            text-decoration: none;
        }
        
        .divider {
            text-align: center;
            margin: 1.5rem 0;
            color: #6c757d;
            position: relative;
        }
        
        .divider span {
            background: rgba(255, 255, 255, 0.9);
            padding: 0 1rem;
            position: relative;
            z-index: 1;
        }
        
        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, #dee2e6, transparent);
        }
        
        .alert {
            border-radius: 12px;
            border: none;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #f8d7da 0%, #f1aeb5 100%);
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        
        .alert-info {
            background: linear-gradient(135deg, #d1ecf1 0%, #b8daff 100%);
            color: #055160;
            border-left: 4px solid #0dcaf0;
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
            .login-container {
                margin: 20px;
                max-width: calc(100% - 40px);
            }
            
            .login-header {
                padding: 2rem 1.5rem;
            }
            
            .login-body {
                padding: 2rem 1.5rem;
            }
            
            .matrix-column {
                font-size: 12px;
                line-height: 12px;
            }
        }
    </style>
</head>
<body>
    <!-- Matrix Binary Rain Background -->
    <div id="matrix-bg"></div>
    
    <!-- Content Overlay -->
    <div class="content-overlay">
        <div class="login-container">
            <div class="login-header">
                <h3 class="mb-3">
                    <i class="fas fa-shield-alt me-2"></i>
                    <?php echo APP_NAME; ?>
                </h3>
                <p class="mb-0">External Dynamic List Manager</p>
                <small class="d-block mt-1 opacity-75">Secure Access Portal</small>
            </div>
            
            <div class="login-body">
                <?php if ($error_message): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?php echo htmlspecialchars($error_message); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($info_message): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <?php echo htmlspecialchars($info_message); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($okta_enabled): ?>
                    <!-- Okta SSO Login Button -->
                    <a href="okta/login.php" class="btn btn-okta d-flex align-items-center justify-content-center">
                        <i class="fas fa-cloud me-2"></i>
                        Sign in with Okta SSO
                    </a>
                    
                    <?php if ($allow_local_fallback): ?>
                    <div class="divider">
                        <span>or use local account</span>
                    </div>
                    
                    <!-- Local Login Form (Fallback) -->
                    <form method="POST" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label for="username" class="form-label fw-bold">Username</label>
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-user text-muted"></i>
                                </span>
                                <input type="text" class="form-control" id="username" name="username" 
                                       value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                                       required autocomplete="username"
                                       placeholder="Local account username">
                            </div>
                        </div>
                        
                        <div class="mb-4">
                            <label for="password" class="form-label fw-bold">Password</label>
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-lock text-muted"></i>
                                </span>
                                <input type="password" class="form-control" id="password" name="password" 
                                       required autocomplete="current-password"
                                       placeholder="Local account password">
                                <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-login">
                                <i class="fas fa-key me-2"></i>
                                Local Login
                            </button>
                        </div>
                    </form>
                    <?php endif; ?>
                    
                <?php else: ?>
                    <!-- Traditional Login Form (SSO Disabled) -->
                    <form method="POST" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label for="username" class="form-label fw-bold">Username</label>
                            <div class="input-group">
                                <span class="input-group-text">
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
                                <span class="input-group-text">
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
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Matrix Binary Rain Effect
        function createMatrixRain() {
            const matrixBg = document.getElementById('matrix-bg');
            const columns = Math.floor(window.innerWidth / 20);
            
            for (let i = 0; i < columns; i++) {
                createColumn(i * 20);
            }
            
            function createColumn(x) {
                const column = document.createElement('div');
                column.className = 'matrix-column';
                
                // Random color variation
                const colors = ['', 'blue', 'cyan'];
                const randomColor = colors[Math.floor(Math.random() * colors.length)];
                if (randomColor) column.classList.add(randomColor);
                
                // Generate random binary digits
                let text = '';
                const length = Math.floor(Math.random() * 50) + 20;
                for (let j = 0; j < length; j++) {
                    text += Math.random() > 0.5 ? '1' : '0';
                    if (j % 25 === 24) text += '\n'; // Line break every 25 chars
                }
                
                column.textContent = text;
                column.style.left = x + 'px';
                column.style.animationDuration = (Math.random() * 3 + 2) + 's';
                column.style.animationDelay = Math.random() * 2 + 's';
                
                matrixBg.appendChild(column);
                
                // Remove and recreate column after animation
                setTimeout(() => {
                    if (column.parentNode) {
                        column.parentNode.removeChild(column);
                        createColumn(x);
                    }
                }, (parseFloat(column.style.animationDuration) + parseFloat(column.style.animationDelay)) * 1000);
            }
        }
        
        // Password toggle
        const togglePassword = document.getElementById('togglePassword');
        if (togglePassword) {
            togglePassword.addEventListener('click', function() {
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
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            // Start matrix rain effect
            createMatrixRain();
            
            // Login container entrance animation
            const loginContainer = document.querySelector('.login-container');
            loginContainer.style.opacity = '0';
            loginContainer.style.transform = 'translateY(50px) scale(0.9)';
            
            setTimeout(() => {
                loginContainer.style.transition = 'all 0.8s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
                loginContainer.style.opacity = '1';
                loginContainer.style.transform = 'translateY(0) scale(1)';
            }, 300);
        });
        
        // Handle window resize
        window.addEventListener('resize', function() {
            // Clear existing columns and recreate for new window size
            const matrixBg = document.getElementById('matrix-bg');
            matrixBg.innerHTML = '';
            setTimeout(createMatrixRain, 100);
        });
    </script>
</body>
</html>