<?php
// pages/okta_config.php - Simple Okta Configuration
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'Okta SSO Configuration';
$error_message = '';
$success_message = '';

// Okta configuration file
$okta_config_file = DATA_DIR . '/okta_config.json';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'save_okta_config') {
            $okta_config = [
                'enabled' => ($_POST['sso_enabled'] ?? 'off') === 'on',
                'okta_domain' => sanitize_input($_POST['okta_domain'] ?? ''),
                'client_id' => sanitize_input($_POST['client_id'] ?? ''),
                'client_secret' => sanitize_input($_POST['client_secret'] ?? ''),
                'redirect_uri' => sanitize_input($_POST['redirect_uri'] ?? ''),
                'allow_local_fallback' => ($_POST['allow_local_fallback'] ?? 'off') === 'on',
                'group_mappings' => [
                    'admin_group' => sanitize_input($_POST['admin_group'] ?? ''),
                    'approver_group' => sanitize_input($_POST['approver_group'] ?? ''),
                    'operator_group' => sanitize_input($_POST['operator_group'] ?? ''),
                    'viewer_group' => sanitize_input($_POST['viewer_group'] ?? '')
                ],
                'default_role' => sanitize_input($_POST['default_role'] ?? 'viewer'),
                'updated_at' => date('c'),
                'updated_by' => $_SESSION['username']
            ];
            
            if (write_json_file($okta_config_file, $okta_config)) {
                $success_message = 'Okta configuration saved successfully!';
                
                // Add audit log
                $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                $audit_logs[] = [
                    'id' => uniqid('audit_', true),
                    'timestamp' => date('c'),
                    'action' => 'okta_config_update',
                    'entry' => 'Okta SSO Configuration',
                    'user' => $_SESSION['username'],
                    'details' => 'Updated Okta SSO configuration - Enabled: ' . ($okta_config['enabled'] ? 'Yes' : 'No')
                ];
                write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
            } else {
                $error_message = 'Failed to save Okta configuration.';
            }
        }
        
        if ($action === 'test_connection') {
            $domain = sanitize_input($_POST['okta_domain'] ?? '');
            if (empty($domain)) {
                $error_message = 'Please enter Okta domain first.';
            } else {
                $test_result = test_okta_connection($domain);
                if ($test_result['success']) {
                    $success_message = 'Connection test successful: ' . $test_result['message'];
                } else {
                    $error_message = 'Connection test failed: ' . $test_result['message'];
                }
            }
        }
    }
}

// Load current configuration
$okta_config = read_json_file($okta_config_file);
if (empty($okta_config)) {
    $okta_config = [
        'enabled' => false,
        'okta_domain' => '',
        'client_id' => '',
        'client_secret' => '',
        'redirect_uri' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'your-domain.com') . '/okta/callback',
        'allow_local_fallback' => true,
        'group_mappings' => [
            'admin_group' => 'EDL-Admins',
            'approver_group' => 'EDL-Approvers', 
            'operator_group' => 'EDL-Operators',
            'viewer_group' => 'EDL-Viewers'
        ],
        'default_role' => 'viewer'
    ];
}

$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];

// Helper function
function test_okta_connection($domain) {
    $url = "https://{$domain}/.well-known/openid_configuration";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($response === false) {
        return ['success' => false, 'message' => 'Connection failed: ' . $error];
    }
    
    if ($http_code === 200) {
        $config = json_decode($response, true);
        if ($config && isset($config['authorization_endpoint'])) {
            return ['success' => true, 'message' => 'Successfully connected to Okta'];
        } else {
            return ['success' => false, 'message' => 'Invalid Okta response'];
        }
    } else {
        return ['success' => false, 'message' => "HTTP error: {$http_code}"];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?> - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            transition: all 0.3s ease;
        }
        .page-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .status-indicator {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 50px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        .status-enabled {
            background-color: rgba(25, 135, 84, 0.1);
            color: #198754;
        }
        .status-disabled {
            background-color: rgba(220, 53, 69, 0.1);
            color: #dc3545;
        }
        .group-mapping-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #007bff;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand fw-bold" href="../index.php">
                <i class="fas fa-shield-alt me-2"></i>
                <?php echo APP_NAME; ?>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="../index.php">
                            <i class="fas fa-tachometer-alt me-1"></i> Dashboard
                        </a>
                    </li>
                    <?php if (in_array('submit', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="submit_request.php">
                            <i class="fas fa-plus me-1"></i> Submit Request
                        </a>
                    </li>
                    <?php endif; ?>
                    <?php if (in_array('approve', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="approvals.php">
                            <i class="fas fa-check-circle me-1"></i> Approvals
                        </a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="edl_viewer.php">
                            <i class="fas fa-list me-1"></i> EDL Viewer
                        </a>
                    </li>
                    <?php if (in_array('manage', $user_permissions)): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle active" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item active" href="okta_config.php">
                                <i class="fas fa-cloud"></i> Okta SSO
                            </a></li>
                            <li><a class="dropdown-item" href="audit_log.php">
                                <i class="fas fa-clipboard-list"></i> Audit Log
                            </a></li>
                        </ul>
                    </li>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i>
                            <?php echo htmlspecialchars($user_name); ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li class="dropdown-item-text">
                                <div class="fw-bold"><?php echo htmlspecialchars($user_username); ?></div>
                                <small class="text-muted"><?php echo htmlspecialchars($user_email); ?></small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="../logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i> Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <?php if ($success_message): ?>
    <div class="container mt-3">
        <div class="alert alert-success alert-dismissible fade show">
            <i class="fas fa-check-circle"></i>
            <?php echo htmlspecialchars($success_message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <?php if ($error_message): ?>
    <div class="container mt-3">
        <div class="alert alert-danger alert-dismissible fade show">
            <i class="fas fa-exclamation-triangle"></i>
            <?php echo htmlspecialchars($error_message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <div class="container mt-4">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="mb-2">
                <i class="fas fa-cloud me-2"></i>
                Okta SSO Configuration
            </h1>
            <p class="mb-0 opacity-75">Configure Single Sign-On with Okta for role-based access</p>
        </div>
        
        <!-- Status Overview -->
        <div class="row mb-4">
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="status-indicator <?php echo $okta_config['enabled'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                            <i class="fas fa-<?php echo $okta_config['enabled'] ? 'check-circle' : 'times-circle'; ?> me-1"></i>
                            <?php echo $okta_config['enabled'] ? 'Enabled' : 'Disabled'; ?>
                        </div>
                        <h6 class="card-title">SSO Status</h6>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="mb-2">
                            <i class="fas fa-users fa-2x text-primary"></i>
                        </div>
                        <h6 class="card-title">4 Roles Configured</h6>
                        <small class="text-muted">Admin, Approver, Operator, Viewer</small>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="status-indicator <?php echo $okta_config['allow_local_fallback'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                            <i class="fas fa-<?php echo $okta_config['allow_local_fallback'] ? 'unlock' : 'lock'; ?> me-1"></i>
                            <?php echo $okta_config['allow_local_fallback'] ? 'Allowed' : 'Disabled'; ?>
                        </div>
                        <h6 class="card-title">Local Fallback</h6>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="mb-2">
                            <span class="badge bg-info"><?php echo ucfirst($okta_config['default_role']); ?></span>
                        </div>
                        <h6 class="card-title">Default Role</h6>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Configuration Form -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-cloud text-primary me-2"></i> Okta Integration Settings
                </h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="save_okta_config">
                    
                    <!-- Basic Settings -->
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label fw-bold">Enable Okta SSO</label>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="sso_enabled" name="sso_enabled" 
                                           <?php echo $okta_config['enabled'] ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="sso_enabled">
                                        Enable Single Sign-On with Okta
                                    </label>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label fw-bold">Allow Local Login Fallback</label>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="allow_local_fallback" name="allow_local_fallback" 
                                           <?php echo $okta_config['allow_local_fallback'] ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="allow_local_fallback">
                                        Keep local accounts as backup
                                    </label>
                                </div>
                                <div class="form-text">Recommended for emergency access</div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="default_role" class="form-label fw-bold">Default Role</label>
                                <select class="form-select" id="default_role" name="default_role">
                                    <option value="viewer" <?php echo $okta_config['default_role'] === 'viewer' ? 'selected' : ''; ?>>
                                        Viewer (Read Only)
                                    </option>
                                    <option value="operator" <?php echo $okta_config['default_role'] === 'operator' ? 'selected' : ''; ?>>
                                        Operator (Submit + View)
                                    </option>
                                    <option value="approver" <?php echo $okta_config['default_role'] === 'approver' ? 'selected' : ''; ?>>
                                        Approver (Approve + View)
                                    </option>
                                    <option value="admin" <?php echo $okta_config['default_role'] === 'admin' ? 'selected' : ''; ?>>
                                        Admin (Full Access)
                                    </option>
                                </select>
                                <div class="form-text">Role for users not in any mapped AD group</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Okta Connection Settings -->
                    <div class="group-mapping-section">
                        <h6><i class="fas fa-server text-primary me-2"></i>Okta Connection</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="okta_domain" class="form-label fw-bold">Okta Domain <span class="text-danger">*</span></label>
                                    <input type="text" class="form-control" id="okta_domain" name="okta_domain" 
                                           value="<?php echo htmlspecialchars($okta_config['okta_domain']); ?>"
                                           placeholder="company.okta.com" required>
                                    <div class="form-text">Your Okta organization domain (without https://)</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_id" class="form-label fw-bold">Client ID <span class="text-danger">*</span></label>
                                    <input type="text" class="form-control" id="client_id" name="client_id" 
                                           value="<?php echo htmlspecialchars($okta_config['client_id']); ?>"
                                           placeholder="0oa..." required>
                                    <div class="form-text">From your Okta app's General tab</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_secret" class="form-label fw-bold">Client Secret <span class="text-danger">*</span></label>
                                    <div class="input-group">
                                        <input type="password" class="form-control" id="client_secret" name="client_secret" 
                                               value="<?php echo htmlspecialchars($okta_config['client_secret']); ?>"
                                               placeholder="Enter client secret" required>
                                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('client_secret')">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="redirect_uri" class="form-label fw-bold">Redirect URI</label>
                                    <div class="input-group">
                                        <input type="url" class="form-control" id="redirect_uri" name="redirect_uri" 
                                               value="<?php echo htmlspecialchars($okta_config['redirect_uri']); ?>" readonly>
                                        <button class="btn btn-outline-info" type="button" onclick="copyToClipboard('redirect_uri')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                    <div class="form-text">Add this to your Okta app's redirect URIs</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- AD Group Mappings -->
                    <div class="group-mapping-section">
                        <h6><i class="fas fa-users-cog text-primary me-2"></i>Active Directory Group Mappings</h6>
                        <p class="text-muted mb-3">Map your AD groups to EDL Manager roles. Users will get the role of the first matching group.</p>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="admin_group" class="form-label fw-bold">
                                        <i class="fas fa-user-shield text-danger me-1"></i> Admin Group
                                    </label>
                                    <input type="text" class="form-control" id="admin_group" name="admin_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['admin_group']); ?>"
                                           placeholder="EDL-Admins">
                                    <div class="form-text">Full access to all functions</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="approver_group" class="form-label fw-bold">
                                        <i class="fas fa-user-check text-success me-1"></i> Approver Group
                                    </label>
                                    <input type="text" class="form-control" id="approver_group" name="approver_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['approver_group']); ?>"
                                           placeholder="EDL-Approvers">
                                    <div class="form-text">Can approve/deny requests</div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="operator_group" class="form-label fw-bold">
                                        <i class="fas fa-user-edit text-warning me-1"></i> Operator Group
                                    </label>
                                    <input type="text" class="form-control" id="operator_group" name="operator_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['operator_group']); ?>"
                                           placeholder="EDL-Operators">
                                    <div class="form-text">Can submit requests</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="viewer_group" class="form-label fw-bold">
                                        <i class="fas fa-user text-info me-1"></i> Viewer Group
                                    </label>
                                    <input type="text" class="form-control" id="viewer_group" name="viewer_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['viewer_group']); ?>"
                                           placeholder="EDL-Viewers">
                                    <div class="form-text">Read-only access</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="d-flex justify-content-between">
                        <div>
                            <a href="../index.php" class="btn btn-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Dashboard
                            </a>
                            <button type="button" class="btn btn-info ms-2" onclick="testConnection()">
                                <i class="fas fa-plug"></i> Test Connection
                            </button>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Configuration
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function togglePassword(fieldId) {
            const field = document.getElementById(fieldId);
            const button = field.nextElementSibling.querySelector('i');
            
            if (field.type === 'password') {
                field.type = 'text';
                button.classList.remove('fa-eye');
                button.classList.add('fa-eye-slash');
            } else {
                field.type = 'password';
                button.classList.remove('fa-eye-slash');
                button.classList.add('fa-eye');
            }
        }
        
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            element.select();
            element.setSelectionRange(0, 99999);
            
            try {
                document.execCommand('copy');
                alert('Copied to clipboard');
            } catch (err) {
                alert('Failed to copy to clipboard');
            }
        }
        
        function testConnection() {
            const domain = document.getElementById('okta_domain').value;
            if (!domain) {
                alert('Please enter Okta domain first');
                return;
            }
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.style.display = 'none';
            
            const csrfToken = document.createElement('input');
            csrfToken.type = 'hidden';
            csrfToken.name = 'csrf_token';
            csrfToken.value = '<?php echo generate_csrf_token(); ?>';
            
            const action = document.createElement('input');
            action.type = 'hidden';
            action.name = 'action';
            action.value = 'test_connection';
            
            const domainInput = document.createElement('input');
            domainInput.type = 'hidden';
            domainInput.name = 'okta_domain';
            domainInput.value = domain;
            
            form.appendChild(csrfToken);
            form.appendChild(action);
            form.appendChild(domainInput);
            
            document.body.appendChild(form);
            form.submit();
        }
    </script>
</body>
</html>