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
                // Try org-level test first
                if (file_exists('../includes/okta_auth_org.php')) {
                    require_once '../includes/okta_auth_org.php';
                    if (class_exists('OktaAuthOrg')) {
                        $okta_auth_org = new OktaAuthOrg();
                        $test_result = $okta_auth_org->test_connection();
                        if ($test_result['success']) {
                            show_flash('Connection test successful (Org-Level): ' . $test_result['message'], 'success');
                        } else {
                            // Try the original function as fallback
                            $test_result = test_okta_connection($domain);
                            if ($test_result['success']) {
                                show_flash('Connection test successful: ' . $test_result['message'], 'success');
                            } else {
                                $error_message = 'Connection test failed: ' . $test_result['message'];
                            }
                        }
                    } else {
                        $test_result = test_okta_connection($domain);
                        if ($test_result['success']) {
                            show_flash('Connection test successful: ' . $test_result['message'], 'success');
                        } else {
                            $error_message = 'Connection test failed: ' . $test_result['message'];
                        }
                    }
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
        
        if ($action === 'refresh_redirect_uri') {
            // Update the redirect URI to current calculated value
            $okta_config = read_json_file($okta_config_file);
            if (empty($okta_config)) {
                $okta_config = [];
            }
            $okta_config['redirect_uri'] = get_redirect_uri();
            
            if (write_json_file($okta_config_file, $okta_config)) {
                show_flash('Redirect URI updated successfully!', 'success');
                header('Location: okta_config.php');
                exit;
            } else {
                $error_message = 'Failed to update redirect URI.';
            }
        }
    }
}

// Helper function to construct proper redirect URI using SSL config domain
function get_redirect_uri() {
    // First, try to get domain from SSL configuration
    $ssl_config = read_json_file(DATA_DIR . '/ssl_config.json');
    $domain = '';
    $protocol = 'https'; // Default to HTTPS for security
    
    if (!empty($ssl_config) && !empty($ssl_config['domain_name']) && $ssl_config['domain_name'] !== 'localhost') {
        // Use SSL configured domain
        $domain = $ssl_config['domain_name'];
        $protocol = ($ssl_config['enabled'] ?? false) ? 'https' : 'http';
    } else {
        // Fall back to current request domain
        $domain = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    }
    
    // Get the application root path by analyzing the current script path
    $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
    $base_path = '';
    
    if (strpos($script_name, '/pages/') !== false) {
        // We're in /pages/okta_config.php, so get everything before /pages/
        $base_path = substr($script_name, 0, strpos($script_name, '/pages/'));
    } elseif (strpos($script_name, '/') !== false) {
        // Fallback: remove everything after the last directory that contains a file
        $path_parts = explode('/', trim($script_name, '/'));
        if (count($path_parts) > 1) {
            array_pop($path_parts); // Remove filename
            $base_path = '/' . implode('/', $path_parts);
        }
    }
    
    // Clean up any double slashes and ensure proper format
    $redirect_uri = "{$protocol}://{$domain}{$base_path}/okta/callback.php";
    $redirect_uri = str_replace('//', '/', $redirect_uri);
    $redirect_uri = str_replace(':/', '://', $redirect_uri); // Fix protocol
    
    return $redirect_uri;
}

// Load current configuration
$okta_config = read_json_file($okta_config_file);
if (empty($okta_config)) {
    $okta_config = [
        'enabled' => false,
        'okta_domain' => '',
        'client_id' => '',
        'client_secret' => '',
        'redirect_uri' => get_redirect_uri(),
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

// Update redirect_uri if it's still using the old format
if (empty($okta_config['redirect_uri']) || strpos($okta_config['redirect_uri'], 'your-domain.com') !== false) {
    $okta_config['redirect_uri'] = get_redirect_uri();
}

// Load SSL configuration for domain integration
$ssl_config = read_json_file(DATA_DIR . '/ssl_config.json');
if (empty($ssl_config)) {
    $ssl_config = ['enabled' => false, 'domain_name' => 'localhost'];
}

// Helper function to test Okta connection with auto-detection
function test_okta_connection($domain) {
    // Auto-detect authorization server (same logic as OktaAuth class)
    $auth_server_configs = [
        'default' => [
            'name' => 'Default Authorization Server',
            'well_known' => "https://{$domain}/oauth2/default/.well-known/openid_configuration"
        ],
        'org' => [
            'name' => 'Org Authorization Server', 
            'well_known' => "https://{$domain}/.well-known/openid_configuration"
        ]
    ];
    
    foreach ($auth_server_configs as $type => $config) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $config['well_known']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'EDL-Manager/2.0');
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);
        
        if ($response !== false && $http_code === 200) {
            $endpoint_config = json_decode($response, true);
            if ($endpoint_config && isset($endpoint_config['authorization_endpoint'])) {
                return [
                    'success' => true,
                    'message' => "Successfully connected to Okta ({$config['name']})",
                    'auth_server' => $config['name'],
                    'issuer' => $endpoint_config['issuer'] ?? 'Not provided',
                    'endpoints' => [
                        'authorization' => $endpoint_config['authorization_endpoint'],
                        'token' => $endpoint_config['token_endpoint'],
                        'userinfo' => $endpoint_config['userinfo_endpoint']
                    ]
                ];
            }
        }
    }
    
    return [
        'success' => false, 
        'message' => 'Could not connect to any Okta authorization server. Please check your domain.'
    ];
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
        <p class="mb-0 opacity-75">Configure Single Sign-On with Okta for role-based access using OIDC</p>
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
                <i class="fas fa-cloud text-primary me-2"></i> Okta OIDC Integration Settings
            </h5>
        </div>
        <div class="card-body">
            <form method="POST" id="oktaConfigForm">
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
                                    Allow local username/password login as backup
                                </label>
                            </div>
                            <div class="form-text">Recommended to keep enabled during initial setup</div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="default_role" class="form-label fw-bold">Default Role</label>
                            <select class="form-select" id="default_role" name="default_role">
                                <option value="viewer" <?php echo $okta_config['default_role'] === 'viewer' ? 'selected' : ''; ?>>Viewer</option>
                                <option value="operator" <?php echo $okta_config['default_role'] === 'operator' ? 'selected' : ''; ?>>Operator</option>
                                <option value="approver" <?php echo $okta_config['default_role'] === 'approver' ? 'selected' : ''; ?>>Approver</option>
                                <option value="admin" <?php echo $okta_config['default_role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                            </select>
                            <div class="form-text">Role assigned to users not in any mapped group</div>
                        </div>
                    </div>
                </div>
                
                <!-- Okta Connection Settings -->
                <div class="okta-connection-section mb-4">
                    <h6><i class="fas fa-cog text-primary me-2"></i>Okta Connection Details</h6>
                    <p class="text-muted mb-3">Configure your Okta organization and OIDC application settings.</p>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="okta_domain" class="form-label fw-bold">Okta Domain <span class="text-danger">*</span></label>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="okta_domain" name="okta_domain" 
                                           value="<?php echo htmlspecialchars($okta_config['okta_domain']); ?>"
                                           placeholder="dev-12345.okta.com" required>
                                    <button class="btn btn-outline-primary" type="button" onclick="testConnection()">
                                        <i class="fas fa-vial"></i> Test
                                    </button>
                                </div>
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
                                    <button class="btn btn-outline-secondary" type="button" onclick="refreshRedirectUri()">
                                        <i class="fas fa-sync-alt"></i>
                                    </button>
                                    <button class="btn btn-outline-info" type="button" onclick="copyToClipboard('redirect_uri')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <div class="form-text">
                                    <?php if (!empty($ssl_config['domain_name']) && $ssl_config['domain_name'] !== 'localhost'): ?>
                                        <i class="fas fa-link text-success"></i> Using domain from <a href="ssl_config.php">SSL/TLS Configuration</a>: <strong><?php echo htmlspecialchars($ssl_config['domain_name']); ?></strong>
                                    <?php else: ?>
                                        <i class="fas fa-exclamation-triangle text-warning"></i> Using current domain. <a href="ssl_config.php">Configure SSL/TLS</a> for centralized domain management.
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Okta Group Mappings -->
                <div class="group-mapping-section">
                    <h6><i class="fas fa-users-cog text-primary me-2"></i>Okta Group Mappings</h6>
                    <p class="text-muted mb-3">Map your Okta groups to EDL Manager roles. Users will inherit the role from their highest-privilege group.</p>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="admin_group" class="form-label fw-bold">
                                    <i class="fas fa-user-cog text-danger me-1"></i> Admin Group
                                </label>
                                <input type="text" class="form-control" id="admin_group" name="admin_group" 
                                       value="<?php echo htmlspecialchars($okta_config['group_mappings']['admin_group']); ?>"
                                       placeholder="EDL-Admins">
                                <div class="form-text">Okta group that can manage all aspects of EDL Manager</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="approver_group" class="form-label fw-bold">
                                    <i class="fas fa-user-check text-success me-1"></i> Approver Group
                                </label>
                                <input type="text" class="form-control" id="approver_group" name="approver_group" 
                                       value="<?php echo htmlspecialchars($okta_config['group_mappings']['approver_group']); ?>"
                                       placeholder="EDL-Approvers">
                                <div class="form-text">Okta group that can approve/deny EDL requests</div>
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
                                <div class="form-text">Okta group that can submit requests</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="viewer_group" class="form-label fw-bold">
                                    <i class="fas fa-user text-info me-1"></i> Viewer Group
                                </label>
                                <input type="text" class="form-control" id="viewer_group" name="viewer_group" 
                                       value="<?php echo htmlspecialchars($okta_config['group_mappings']['viewer_group']); ?>"
                                       placeholder="EDL-Viewers">
                                <div class="form-text">Okta group that can view EDL contents (read-only)</div>
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
                        <li>Select <strong>Web Application</strong></li>
                        <li>Configure the application settings</li>
                    </ol>
                </div>
                <div class="col-md-6">
                    <h6><i class="fas fa-cogs text-primary"></i> Application Configuration</h6>
                    <ul class="small">
                        <li><strong>App Name:</strong> EDL Manager</li>
                        <li><strong>Grant Types:</strong> Authorization Code</li>
                        <li><strong>Sign-in redirect URI:</strong> <code><?php echo htmlspecialchars($okta_config['redirect_uri']); ?></code></li>
                        <li><strong>Sign-out redirect URI:</strong> Your login page URL</li>
                        <li><strong>Assignment:</strong> Assign to appropriate groups</li>
                    </ul>
                </div>
            </div>
            
            <!-- Critical Redirect URI Configuration -->
            <div class="alert alert-warning mt-3">
                <h6><i class="fas fa-exclamation-triangle"></i> Critical: Redirect URI Configuration</h6>
                <p class="mb-2">To fix the <strong>400 Bad Request</strong> error, you must:</p>
                <ol class="mb-2">
                    <li>Copy the <strong>exact</strong> Redirect URI from the field above: <code><?php echo htmlspecialchars($okta_config['redirect_uri']); ?></code></li>
                    <li>Go to your Okta app: <a href="https://<?php echo htmlspecialchars($okta_config['okta_domain'] ?: 'your-domain.okta.com'); ?>/admin/apps" target="_blank">Okta Admin Console</a></li>
                    <li>Edit your EDL Manager app → <strong>General</strong> tab</li>
                    <li>In <strong>Sign-in redirect URIs</strong>, add the exact URI from step 1</li>
                    <li>Click <strong>Save</strong></li>
                </ol>
                <p class="mb-0"><strong>Important:</strong> The URI must match exactly - including protocol (http/https), port, and path.</p>
            </div>
        </div>
    </div>
    
    <!-- Troubleshooting Section -->
    <div class="card mt-4">
        <div class="card-header bg-warning">
            <h5 class="mb-0">
                <i class="fas fa-tools me-2"></i> Troubleshooting Common Issues
            </h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="fas fa-exclamation-circle text-danger"></i> 400 Bad Request Errors</h6>
                    <ul class="small">
                        <li><strong>Redirect URI mismatch:</strong> Ensure the URI in Okta exactly matches the one shown above</li>
                        <li><strong>Protocol mismatch:</strong> If using HTTPS, make sure the redirect URI uses https://</li>
                        <li><strong>Port issues:</strong> Include port number if not using standard ports (80/443)</li>
                        <li><strong>Path issues:</strong> Verify the /okta/callback.php path is correct</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6><i class="fas fa-network-wired text-info"></i> Connection Issues</h6>
                    <ul class="small">
                        <li><strong>Domain format:</strong> Use only the domain (e.g., dev-12345.okta.com)</li>
                        <li><strong>Firewall:</strong> Ensure outbound HTTPS (443) is allowed</li>
                        <li><strong>DNS:</strong> Verify your Okta domain resolves correctly</li>
                        <li><strong>SSL/TLS:</strong> Check certificate validation settings</li>
                    </ul>
                </div>
            </div>
            
            <div class="alert alert-info mt-3">
                <h6><i class="fas fa-info-circle"></i> Domain Management Integration</h6>
                <div class="row">
                    <div class="col-md-6">
                        <p class="mb-2"><strong>Current Domain Source:</strong></p>
                        <?php if (!empty($ssl_config['domain_name']) && $ssl_config['domain_name'] !== 'localhost'): ?>
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-shield-alt text-success me-2"></i>
                                <span class="text-success">SSL/TLS Configuration</span>
                            </div>
                            <p class="mb-2 small">Domain: <code><?php echo htmlspecialchars($ssl_config['domain_name']); ?></code></p>
                            <p class="mb-0 small">Protocol: <code><?php echo ($ssl_config['enabled'] ?? false) ? 'https' : 'http'; ?></code></p>
                        <?php else: ?>
                            <div class="d-flex align-items-center mb-2">
                                <i class="fas fa-globe text-warning me-2"></i>
                                <span class="text-warning">Current Request Domain</span>
                            </div>
                            <p class="mb-2 small">Domain: <code><?php echo htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'localhost'); ?></code></p>
                            <p class="mb-0 small">Protocol: <code><?php echo isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http'; ?></code></p>
                        <?php endif; ?>
                    </div>
                    <div class="col-md-6">
                        <p class="mb-2"><strong>Benefits of SSL Integration:</strong></p>
                        <ul class="mb-0 small">
                            <li>Centralized domain management</li>
                            <li>Consistent SSL/Okta configuration</li>
                            <li>Automatic protocol selection</li>
                            <li>Simplified administration</li>
                        </ul>
                        <?php if (empty($ssl_config['domain_name']) || $ssl_config['domain_name'] === 'localhost'): ?>
                            <a href="ssl_config.php" class="btn btn-sm btn-outline-primary mt-2">
                                <i class="fas fa-cog"></i> Configure SSL/TLS
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <div class="alert alert-info mt-3">
                <h6><i class="fas fa-lightbulb"></i> Quick Fix for Your Current Error</h6>
                <p class="mb-2">Your redirect URI should be clean and properly formatted. Update your Okta app to use:</p>
                <div class="bg-light p-2 border rounded">
                    <code><?php echo htmlspecialchars($okta_config['redirect_uri']); ?></code>
                    <button class="btn btn-sm btn-outline-primary ms-2" onclick="copyToClipboard('redirect_uri')">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                <p class="mt-2 mb-1"><strong>Remove any old URIs that contain:</strong></p>
                <ul class="small mb-2">
                    <li><code>../</code> (relative path references)</li>
                    <li><code>/pages/../</code> (unnecessary path navigation)</li>
                    <li>Any malformed URLs from previous configurations</li>
                </ul>
                <p class="mt-2 mb-0">
                    <a href="https://<?php echo htmlspecialchars($okta_config['okta_domain'] ?: 'lucid-admin.okta.com'); ?>/admin/app/oidc_client/instance/<?php echo htmlspecialchars($okta_config['client_id'] ?: '0oa15gjdgxsotpAuZ2p8'); ?>#tab-general" target="_blank" class="btn btn-sm btn-primary">
                        <i class="fas fa-external-link-alt"></i> Open Okta App Settings
                    </a>
                </p>
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

.page-header {
    padding: 2rem 0 1rem 0;
    border-bottom: 1px solid #dee2e6;
    margin-bottom: 2rem;
}
</style>

<script>
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
    
    if (sslConfiguredDomain && sslConfiguredDomain !== 'localhost') {
        showNotification('Redirect URI refreshed using SSL configured domain. Click Save to update configuration.', 'info');
    } else {
        showNotification('Redirect URI refreshed using current domain. Configure SSL for centralized domain management.', 'warning');
    }
}

function copyToClipboard(fieldId) {
    const field = document.getElementById(fieldId);
    field.select();
    field.setSelectionRange(0, 99999);
    
    try {
        document.execCommand('copy');
        showNotification('Copied to clipboard!', 'success');
    } catch (err) {
        showNotification('Failed to copy to clipboard', 'error');
    }
}

function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 'alert-warning';
    const icon = type === 'success' ? 'check-circle' : 'exclamation-triangle';
    
    const alert = document.createElement('div');
    alert.className = `alert ${alertClass} alert-dismissible fade show position-fixed`;
    alert.style.cssText = 'top: 20px; right: 20px; z-index: 1055; min-width: 300px;';
    alert.innerHTML = `
        <i class="fas fa-${icon} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alert);
    
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

function testConnection() {
    const domain = document.getElementById('okta_domain').value.trim();
    
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

<?php require_once '../includes/footer.php'; ?>
