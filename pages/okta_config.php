<?php
// pages/okta_config.php - Complete fixed version with centralized header
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
                show_flash('Okta configuration saved successfully!', 'success');
                
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
                
                header('Location: okta_config.php');
                exit;
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
                    show_flash('Connection test successful: ' . $test_result['message'], 'success');
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
        'redirect_uri' => 'https://' . ($_SERVER['HTTP_HOST'] ?? 'your-domain.com') . dirname($_SERVER['REQUEST_URI']) . '/../okta/callback.php',
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

// Helper function to test Okta connection
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

// Include centralized header
include '../includes/header.php';
?>

<div class="container mt-4">
    <!-- Page Header -->
    <div class="page-header">
        <h1 class="mb-2">
            <i class="fas fa-cloud me-2"></i>
            Okta SSO Configuration
        </h1>
        <p class="mb-0 opacity-75">Configure Single Sign-On with Okta for role-based access</p>
    </div>
    
    <!-- Error Messages -->
    <?php if ($error_message): ?>
    <div class="alert alert-danger alert-dismissible fade show">
        <i class="fas fa-exclamation-triangle me-2"></i>
        <?php echo htmlspecialchars($error_message); ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <?php endif; ?>
    
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
        <div class="card-header bg-light">
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
    
    <!-- Help Card -->
    <div class="card mt-4">
        <div class="card-header bg-light">
            <h5 class="mb-0">
                <i class="fas fa-question-circle text-info me-2"></i> Setup Instructions
            </h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="fas fa-cloud text-primary me-2"></i>Okta Configuration Steps:</h6>
                    <ol class="list-group list-group-numbered">
                        <li class="list-group-item">Create a new Web application in Okta</li>
                        <li class="list-group-item">Copy the Client ID and Client Secret</li>
                        <li class="list-group-item">Set the redirect URI in your Okta app</li>
                        <li class="list-group-item">Configure group assignments</li>
                        <li class="list-group-item">Test the connection</li>
                    </ol>
                </div>
                <div class="col-md-6">
                    <h6><i class="fas fa-users text-success me-2"></i>Role Permissions:</h6>
                    <ul class="list-group">
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-user-shield text-danger me-2"></i>Admin</span>
                            <span class="badge bg-danger rounded-pill">All Access</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-user-check text-success me-2"></i>Approver</span>
                            <span class="badge bg-success rounded-pill">Approve + View</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-user-edit text-warning me-2"></i>Operator</span>
                            <span class="badge bg-warning text-dark rounded-pill">Submit + View</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <span><i class="fas fa-user text-info me-2"></i>Viewer</span>
                            <span class="badge bg-info rounded-pill">View Only</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<?php include '../includes/footer.php'; ?>

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
        showNotification('Copied to clipboard', 'success');
    } catch (err) {
        showNotification('Failed to copy to clipboard', 'danger');
    }
}

function testConnection() {
    const domain = document.getElementById('okta_domain').value;
    if (!domain) {
        showNotification('Please enter Okta domain first', 'warning');
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

// Initialize tooltips
var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
});

// Add some interactivity on page load
document.addEventListener('DOMContentLoaded', function() {
    // Animate status cards on load
    const statusCards = document.querySelectorAll('.card');
    statusCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
});
</script>