<?php
// pages/okta_config.php - Okta SSO Configuration with fixed header and cleaned content
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

// Load current configuration
$okta_config = read_json_file($okta_config_file);
if (!$okta_config) {
    $okta_config = [
        'enabled' => false,
        'okta_domain' => '',
        'client_id' => '',
        'client_secret' => '',
        'redirect_uri' => '',
        'allow_local_fallback' => true,
        'group_mappings' => [
            'admin_group' => '',
            'approver_group' => '',
            'operator_group' => '',
            'viewer_group' => ''
        ],
        'default_role' => 'viewer'
    ];
}

// Load SSL configuration for redirect URI generation
$ssl_config = read_json_file(DATA_DIR . '/ssl_config.json') ?: [];

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
    }
}

// Include centralized header
include '../includes/header.php';
?>

<div class="container mt-4">
    <!-- Error Messages -->
    <?php if ($error_message): ?>
    <div class="alert alert-danger alert-dismissible fade show">
        <i class="fas fa-exclamation-triangle me-2"></i>
        <?php echo htmlspecialchars($error_message); ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <?php endif; ?>

    <!-- Okta Integration Header -->
    <div class="okta-card mb-4">
        <div class="row align-items-center">
            <div class="col-md-8">
                <h1 class="mb-2">
                    <i class="fas fa-cloud me-2"></i>
                    Okta SSO Configuration
                </h1>
                <p class="mb-0">Configure Single Sign-On with Okta for role-based access using OIDC</p>
            </div>
            <div class="col-md-4 text-end">
                <i class="fas fa-cloud fa-3x opacity-50"></i>
            </div>
        </div>
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
                        <?php echo $okta_config['allow_local_fallback'] ? 'Allowed' : 'Blocked'; ?>
                    </div>
                    <h6 class="card-title">Local Fallback</h6>
                </div>
            </div>
        </div>
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card">
                <div class="card-body text-center">
                    <div class="mb-2">
                        <i class="fas fa-shield-alt fa-2x text-success"></i>
                    </div>
                    <h6 class="card-title">OIDC Protocol</h6>
                    <small class="text-muted">OAuth 2.0 + OpenID Connect</small>
                </div>
            </div>
        </div>
    </div>



    <!-- Configuration Form -->
    <div class="card">
        <div class="card-header bg-light">
            <h5 class="mb-0">
                <i class="fas fa-cog me-2"></i>
                OIDC Application Configuration
            </h5>
        </div>
        <div class="card-body">
            <form method="post" class="needs-validation" novalidate>
                <input type="hidden" name="action" value="save_okta_config">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                
                <!-- Enable SSO -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="sso_enabled" name="sso_enabled" 
                                   <?php echo $okta_config['enabled'] ? 'checked' : ''; ?>>
                            <label class="form-check-label fw-bold" for="sso_enabled">
                                Enable Okta Single Sign-On
                            </label>
                            <div class="form-text">Turn on/off Okta authentication for all users</div>
                        </div>
                    </div>
                </div>
                
                <div id="okta-config" style="<?php echo !$okta_config['enabled'] ? 'display: none;' : ''; ?>">
                    <!-- Okta Connection Settings -->
                    <div class="okta-connection-section">
                        <h6 class="fw-bold mb-3">
                            <i class="fas fa-link me-2"></i>
                            Okta Connection Settings
                        </h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="okta_domain" class="form-label fw-bold">Okta Domain</label>
                                    <input type="text" class="form-control" id="okta_domain" name="okta_domain" 
                                           value="<?php echo htmlspecialchars($okta_config['okta_domain']); ?>"
                                           placeholder="company.okta.com" required>
                                    <div class="form-text">Your Okta organization domain (without https://)</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="redirect_uri" class="form-label fw-bold">
                                        Redirect URI
                                        <button type="button" class="btn btn-sm btn-outline-primary ms-2" onclick="refreshRedirectUri()">
                                            <i class="fas fa-sync-alt"></i> Refresh
                                        </button>
                                    </label>
                                    <input type="text" class="form-control" id="redirect_uri" name="redirect_uri" 
                                           value="<?php echo htmlspecialchars($okta_config['redirect_uri']); ?>"
                                           required readonly>
                                    <div class="form-text">Callback URL for Okta (automatically generated)</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_id" class="form-label fw-bold">Client ID</label>
                                    <input type="text" class="form-control" id="client_id" name="client_id" 
                                           value="<?php echo htmlspecialchars($okta_config['client_id']); ?>"
                                           placeholder="0oa15gjdgxsotpAuZ2p8" required>
                                    <div class="form-text">Your Okta application's Client ID</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="client_secret" class="form-label fw-bold">Client Secret</label>
                                    <div class="input-group">
                                        <input type="password" class="form-control" id="client_secret" name="client_secret" 
                                               value="<?php echo htmlspecialchars($okta_config['client_secret']); ?>"
                                               placeholder="Enter client secret" required>
                                        <button type="button" class="btn btn-outline-secondary" onclick="togglePassword('client_secret')">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                    <div class="form-text">Your Okta application's Client Secret</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Group Mapping -->
                    <div class="group-mapping-section">
                        <h6 class="fw-bold mb-3">
                            <i class="fas fa-users me-2"></i>
                            Group to Role Mapping
                        </h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="admin_group" class="form-label fw-bold">Admin Group</label>
                                    <input type="text" class="form-control" id="admin_group" name="admin_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['admin_group']); ?>"
                                           placeholder="EDL-Admins">
                                    <div class="form-text">Okta group for admin users (full access)</div>
                                </div>
                                <div class="mb-3">
                                    <label for="approver_group" class="form-label fw-bold">Approver Group</label>
                                    <input type="text" class="form-control" id="approver_group" name="approver_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['approver_group']); ?>"
                                           placeholder="EDL-Approvers">
                                    <div class="form-text">Okta group for approvers (can approve requests)</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="operator_group" class="form-label fw-bold">Operator Group</label>
                                    <input type="text" class="form-control" id="operator_group" name="operator_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['operator_group']); ?>"
                                           placeholder="EDL-Operators">
                                    <div class="form-text">Okta group for operators (can submit requests)</div>
                                </div>
                                <div class="mb-3">
                                    <label for="viewer_group" class="form-label fw-bold">Viewer Group</label>
                                    <input type="text" class="form-control" id="viewer_group" name="viewer_group" 
                                           value="<?php echo htmlspecialchars($okta_config['group_mappings']['viewer_group']); ?>"
                                           placeholder="EDL-Viewers">
                                    <div class="form-text">Okta group for viewers (read-only access)</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="default_role" class="form-label fw-bold">Default Role</label>
                                    <select class="form-select" id="default_role" name="default_role">
                                        <option value="viewer" <?php echo $okta_config['default_role'] === 'viewer' ? 'selected' : ''; ?>>Viewer</option>
                                        <option value="operator" <?php echo $okta_config['default_role'] === 'operator' ? 'selected' : ''; ?>>Operator</option>
                                        <option value="approver" <?php echo $okta_config['default_role'] === 'approver' ? 'selected' : ''; ?>>Approver</option>
                                    </select>
                                    <div class="form-text">Role assigned when user doesn't match any group</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="allow_local_fallback" name="allow_local_fallback" 
                                               <?php echo $okta_config['allow_local_fallback'] ? 'checked' : ''; ?>>
                                        <label class="form-check-label fw-bold" for="allow_local_fallback">
                                            Allow Local Fallback
                                        </label>
                                        <div class="form-text">Allow local login when Okta is unavailable</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Form Actions -->
                <div class="row mt-4">
                    <div class="col-md-6">
                        <a href="../index.php" class="btn btn-secondary">
                            <i class="fas fa-arrow-left"></i> Back to Dashboard
                        </a>
                    </div>
                    <div class="col-md-6 text-end">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Configuration
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Okta Setup Instructions -->
    <div class="card mt-4">
        <div class="card-header bg-info text-white">
            <h5 class="mb-0">
                <i class="fas fa-book me-2"></i> Okta Application Setup Instructions
            </h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="fas fa-plus-circle text-primary"></i> Creating Your Okta App</h6>
                    <ol class="small">
                        <li>Log in to your Okta Admin Console</li>
                        <li>Go to <strong>Applications</strong> → <strong>Applications</strong></li>
                        <li>Click <strong>Create App Integration</strong></li>
                        <li>Select <strong>OIDC - OpenID Connect</strong></li>
                        <li>Choose <strong>Web Application</strong></li>
                        <li>Configure the application settings</li>
                    </ol>
                </div>
                <div class="col-md-6">
                    <h6><i class="fas fa-cogs text-success"></i> Application Settings</h6>
                    <ul class="small">
                        <li><strong>App name:</strong> EDL Manager</li>
                        <li><strong>Grant types:</strong> Authorization Code</li>
                        <li><strong>Sign-in redirect URI:</strong> Use the generated URI above</li>
                        <li><strong>Sign-out redirect URI:</strong> Your EDL Manager login page</li>
                        <li><strong>Assignments:</strong> Assign appropriate groups</li>
                    </ul>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        <strong>Important:</strong> Ensure your Okta groups match the group names configured above. 
                        Users must be assigned to the appropriate groups for proper role mapping.
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.status-indicator {
    padding: 0.25rem 0.5rem;
    border-radius: 0.375rem;
    font-weight: 600;
    font-size: 0.875rem;
}

.status-enabled {
    background-color: #d1e7dd;
    color: #0f5132;
}

.status-disabled {
    background-color: #f8d7da;
    color: #842029;
}

.okta-connection-section,
.group-mapping-section {
    padding: 1.5rem;
    background: #f8f9fa;
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
}

.okta-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 2rem;
    border-radius: 0.5rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    margin-bottom: 2rem;
}

.okta-card h1 {
    color: white;
}


</style>

<script>
// Toggle configuration section based on enabled checkbox
document.getElementById('sso_enabled').addEventListener('change', function() {
    const configSection = document.getElementById('okta-config');
    configSection.style.display = this.checked ? 'block' : 'none';
});

function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const icon = field.nextElementSibling.querySelector('i');
    
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

function refreshRedirectUri() {
    const redirectField = document.getElementById('redirect_uri');
    
    // Use PHP-generated values for consistency with SSL configuration
    const sslConfiguredDomain = '<?php echo addslashes($ssl_config['domain_name'] ?? ''); ?>';
    const sslEnabled = <?php echo !empty($ssl_config) && ($ssl_config['enabled'] ?? false) ? 'true' : 'false'; ?>;
    
    let protocol, domain;
    
    if (sslConfiguredDomain && sslConfiguredDomain !== 'localhost') {
        // Use SSL configured domain and protocol
        domain = sslConfiguredDomain;
        protocol = sslEnabled ? 'https:' : 'http:';
    } else {
        // Fall back to current location
        protocol = window.location.protocol;
        domain = window.location.host;
    }
    
    const pathname = window.location.pathname;
    
    // Extract base path by removing /pages/okta_config.php
    let basePath = '';
    if (pathname.includes('/pages/')) {
        basePath = pathname.substring(0, pathname.indexOf('/pages/'));
    } else {
        // Fallback: remove everything after the last directory
        const pathParts = pathname.split('/').filter(part => part);
        if (pathParts.length > 1) {
            pathParts.pop(); // Remove filename
            basePath = '/' + pathParts.join('/');
        }
    }
    
    // Construct clean redirect URI
    const newRedirectUri = `${protocol}//${domain}${basePath}/okta/callback.php`;
    
    redirectField.value = newRedirectUri;
    
    showNotification('Redirect URI refreshed. Click Save to update configuration.', 'info');
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 1050; max-width: 400px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Auto-generate redirect URI on page load if empty
document.addEventListener('DOMContentLoaded', function() {
    const redirectField = document.getElementById('redirect_uri');
    if (!redirectField.value.trim()) {
        refreshRedirectUri();
    }
});

// Form validation
(function() {
    'use strict';
    window.addEventListener('load', function() {
        var forms = document.getElementsByClassName('needs-validation');
        var validation = Array.prototype.filter.call(forms, function(form) {
            form.addEventListener('submit', function(event) {
                if (form.checkValidity() === false) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                form.classList.add('was-validated');
            }, false);
        });
    }, false);
})();
</script>

<?php require_once '../includes/footer.php'; ?>
