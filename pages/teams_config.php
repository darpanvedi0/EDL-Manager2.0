<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'Teams Notifications Configuration';
$error_message = '';
$success_message = '';

// Teams configuration file
$teams_config_file = DATA_DIR . '/teams_config.json';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'save_teams_config') {
            $teams_config = [
                'enabled' => ($_POST['teams_enabled'] ?? 'off') === 'on',
                'webhook_url' => sanitize_input($_POST['webhook_url'] ?? ''),
                'channel_name' => sanitize_input($_POST['channel_name'] ?? ''),
                'custom_message' => sanitize_input($_POST['custom_message'] ?? ''),
                'notifications' => [
                    'new_requests' => ($_POST['notify_new_requests'] ?? 'off') === 'on',
                    'approved_requests' => ($_POST['notify_approved'] ?? 'off') === 'on',
                    'denied_requests' => ($_POST['notify_denied'] ?? 'off') === 'on',
                    'critical_priority' => ($_POST['notify_critical'] ?? 'off') === 'on'
                ],
                'mention_users' => array_filter(array_map('trim', explode(',', $_POST['mention_users'] ?? ''))),
                'updated_at' => date('c'),
                'updated_by' => $_SESSION['username']
            ];
            
            // Validate webhook URL if Teams is enabled
            if ($teams_config['enabled'] && empty($teams_config['webhook_url'])) {
                $error_message = 'Webhook URL is required when Teams notifications are enabled.';
            } elseif ($teams_config['enabled'] && !filter_var($teams_config['webhook_url'], FILTER_VALIDATE_URL)) {
                $error_message = 'Please enter a valid webhook URL.';
            } elseif ($teams_config['enabled'] && !preg_match('/webhook\.office\.com|outlook\.office\.com/', $teams_config['webhook_url'])) {
                $error_message = 'Please enter a valid Microsoft Teams webhook URL.';
            } else {
                if (write_json_file($teams_config_file, $teams_config)) {
                    $success_message = 'Teams configuration saved successfully!';
                    
                    // Add audit log
                    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                    $audit_logs[] = [
                        'id' => uniqid('audit_', true),
                        'timestamp' => date('c'),
                        'action' => 'teams_config_update',
                        'entry' => 'Teams Notifications Configuration',
                        'user' => $_SESSION['username'],
                        'details' => 'Updated Teams webhook configuration - Enabled: ' . ($teams_config['enabled'] ? 'Yes' : 'No')
                    ];
                    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                } else {
                    $error_message = 'Failed to save Teams configuration.';
                }
            }
        }
        
        if ($action === 'test_webhook') {
            $webhook_url = sanitize_input($_POST['webhook_url'] ?? '');
            if (empty($webhook_url)) {
                $error_message = 'Please enter a webhook URL first.';
            } else {
                $test_result = test_teams_webhook($webhook_url);
                if ($test_result['success']) {
                    $success_message = 'Test message sent successfully! Check your Teams channel.';
                } else {
                    $error_message = 'Webhook test failed: ' . $test_result['message'];
                }
            }
        }
    }
}

// Load current configuration
$teams_config = read_json_file($teams_config_file);
if (empty($teams_config)) {
    $teams_config = [
        'enabled' => false,
        'webhook_url' => '',
        'channel_name' => '#security-team',
        'custom_message' => '',
        'notifications' => [
            'new_requests' => true,
            'approved_requests' => false,
            'denied_requests' => false,
            'critical_priority' => true
        ],
        'mention_users' => []
    ];
}

$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];

// Helper function to test Teams webhook
function test_teams_webhook($webhook_url) {
    $test_message = [
        '@type' => 'MessageCard',
        '@context' => 'http://schema.org/extensions',
        'themeColor' => '0078D4',
        'summary' => 'EDL Manager Test Message',
        'sections' => [
            [
                'activityTitle' => '🧪 **EDL Manager Test Message**',
                'activitySubtitle' => 'Testing Teams webhook integration',
                'facts' => [
                    [
                        'name' => 'Test Time:',
                        'value' => date('Y-m-d H:i:s T')
                    ],
                    [
                        'name' => 'Tested By:',
                        'value' => $_SESSION['username'] ?? 'Admin'
                    ],
                    [
                        'name' => 'Status:',
                        'value' => '✅ Webhook is working correctly!'
                    ]
                ],
                'markdown' => true
            ]
        ]
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhook_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($test_message));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
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
        return ['success' => true, 'message' => 'Test message sent successfully'];
    } else {
        return ['success' => false, 'message' => "HTTP error: {$http_code}"];
    }
}

// Get recent notification logs if they exist
$teams_logs = [];
if (file_exists(DATA_DIR . '/teams_logs.json')) {
    $teams_logs = array_slice(array_reverse(read_json_file(DATA_DIR . '/teams_logs.json')), 0, 10);
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
        .teams-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #0078D4;
        }
        .webhook-preview {
            background: #1e1e1e;
            color: #ffffff;
            border-radius: 10px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
        .teams-card {
            background: linear-gradient(135deg, #0078D4 0%, #005a9e 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
            margin: 1rem 0;
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
                    <li class="nav-item">
                        <a class="nav-link" href="denied_entries.php">
                            <i class="fas fa-ban me-1"></i> Denied Entries
                        </a>
                    </li>
                    <?php if (in_array('manage', $user_permissions)): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle active" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu" aria-labelledby="adminDropdown">
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-server text-primary me-1"></i> Integration
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="okta_config.php">
                                <i class="fas fa-cloud text-primary me-2"></i> Okta SSO Configuration
                                <small class="text-muted d-block">Configure Single Sign-On</small>
                            </a></li>
                            <li><a class="dropdown-item active" href="teams_config.php">
                                <i class="fab fa-microsoft text-info me-2"></i> Teams Notifications
                                <small class="text-muted d-block">Configure Teams webhooks</small>
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-database text-secondary me-1"></i> Data Management
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="denied_entries.php">
                                <i class="fas fa-ban text-danger me-2"></i> Denied Entries
                                <small class="text-muted d-block">View rejected requests</small>
                            </a></li>
                            <li><a class="dropdown-item" href="audit_log.php">
                                <i class="fas fa-clipboard-list text-warning me-2"></i> Audit Log
                                <small class="text-muted d-block">System activity log</small>
                            </a></li>
                            <li><a class="dropdown-item" href="user_management.php">
                                <i class="fas fa-users text-success me-2"></i> User Management
                                <small class="text-muted d-block">Manage local accounts</small>
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
                            <li class="dropdown-item-text">
                                <small class="text-muted">
                                    Role: <span class="badge bg-primary"><?php echo ucfirst($user_role); ?></span>
                                </small>
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
                <i class="fab fa-microsoft me-2"></i>
                Microsoft Teams Configuration
            </h1>
            <p class="mb-0 opacity-75">Configure webhook notifications for EDL requests and approvals</p>
        </div>
        
        <!-- Status Overview -->
        <div class="row mb-4">
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="status-indicator <?php echo $teams_config['enabled'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                            <i class="fab fa-microsoft me-1"></i>
                            <?php echo $teams_config['enabled'] ? 'Enabled' : 'Disabled'; ?>
                        </div>
                        <h6 class="card-title">Teams Status</h6>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="mb-2">
                            <i class="fas fa-bell fa-2x text-info"></i>
                        </div>
                        <h6 class="card-title"><?php echo array_sum($teams_config['notifications'] ?? []); ?> Notification Types</h6>
                        <small class="text-muted">Configured alerts</small>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="mb-2">
                            <i class="fas fa-users fa-2x text-success"></i>
                        </div>
                        <h6 class="card-title"><?php echo count($teams_config['mention_users'] ?? []); ?> Users</h6>
                        <small class="text-muted">To mention</small>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card">
                    <div class="card-body text-center">
                        <div class="mb-2">
                            <i class="fas fa-history fa-2x text-warning"></i>
                        </div>
                        <h6 class="card-title"><?php echo count($teams_logs); ?> Recent Logs</h6>
                        <small class="text-muted">Notification history</small>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Teams Configuration Card -->
        <div class="teams-card">
            <div class="d-flex align-items-center mb-3">
                <i class="fab fa-microsoft fa-3x me-3"></i>
                <div>
                    <h4 class="mb-1">Microsoft Teams Integration</h4>
                    <p class="mb-0">Get real-time notifications about EDL requests directly in your Teams channel</p>
                </div>
            </div>
        </div>
        
        <!-- Configuration Form -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-cog text-primary me-2"></i> Webhook Configuration
                </h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="save_teams_config">
                    
                    <!-- Basic Settings -->
                    <div class="teams-section">
                        <h6><i class="fas fa-toggle-on text-info me-2"></i>Basic Settings</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label fw-bold">Enable Teams Notifications</label>
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="teams_enabled" name="teams_enabled" 
                                               <?php echo $teams_config['enabled'] ? 'checked' : ''; ?>>
                                        <label class="form-check-label" for="teams_enabled">
                                            Send notifications to Microsoft Teams
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="channel_name" class="form-label fw-bold">Channel Name</label>
                                    <input type="text" class="form-control" id="channel_name" name="channel_name" 
                                           value="<?php echo htmlspecialchars($teams_config['channel_name']); ?>"
                                           placeholder="#security-team">
                                    <div class="form-text">Display name for notifications (optional)</div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="custom_message" class="form-label fw-bold">Custom Message Prefix</label>
                                    <input type="text" class="form-control" id="custom_message" name="custom_message" 
                                           value="<?php echo htmlspecialchars($teams_config['custom_message']); ?>"
                                           placeholder="[SECURITY ALERT]">
                                    <div class="form-text">Optional prefix for all notifications</div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="mention_users" class="form-label fw-bold">Users to Mention</label>
                                    <input type="text" class="form-control" id="mention_users" name="mention_users" 
                                           value="<?php echo htmlspecialchars(implode(', ', $teams_config['mention_users'] ?? [])); ?>"
                                           placeholder="user1@company.com, user2@company.com">
                                    <div class="form-text">Comma-separated email addresses to mention in notifications</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Webhook Settings -->
                    <div class="teams-section">
                        <h6><i class="fas fa-link text-primary me-2"></i>Webhook Configuration</h6>
                        <div class="row">
                            <div class="col-md-8">
                                <div class="mb-3">
                                    <label for="webhook_url" class="form-label fw-bold">Teams Webhook URL <span class="text-danger">*</span></label>
                                    <input type="url" class="form-control" id="webhook_url" name="webhook_url" 
                                           value="<?php echo htmlspecialchars($teams_config['webhook_url']); ?>"
                                           placeholder="https://outlook.office.com/webhook/...">
                                    <div class="form-text">Get this URL from your Teams channel connector settings</div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">&nbsp;</label>
                                <div class="d-grid">
                                    <button type="button" class="btn btn-info" onclick="testWebhook()">
                                        <i class="fas fa-flask"></i> Test Webhook
                                    </button>
                                    <button type="button" class="btn btn-outline-secondary mt-2" onclick="showWebhookHelp()">
                                        <i class="fas fa-question-circle"></i> How to get URL?
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Notification Settings -->
                    <div class="teams-section">
                        <h6><i class="fas fa-bell text-warning me-2"></i>Notification Types</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="notify_new_requests" name="notify_new_requests" 
                                           <?php echo ($teams_config['notifications']['new_requests'] ?? false) ? 'checked' : ''; ?>>
                                    <label class="form-check-label fw-bold" for="notify_new_requests">
                                        <i class="fas fa-paper-plane text-info me-2"></i>New Requests
                                    </label>
                                    <div class="form-text">Notify when new EDL requests are submitted</div>
                                </div>
                                
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="notify_approved" name="notify_approved" 
                                           <?php echo ($teams_config['notifications']['approved_requests'] ?? false) ? 'checked' : ''; ?>>
                                    <label class="form-check-label fw-bold" for="notify_approved">
                                        <i class="fas fa-check-circle text-success me-2"></i>Approved Requests
                                    </label>
                                    <div class="form-text">Notify when requests are approved</div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="notify_denied" name="notify_denied" 
                                           <?php echo ($teams_config['notifications']['denied_requests'] ?? false) ? 'checked' : ''; ?>>
                                    <label class="form-check-label fw-bold" for="notify_denied">
                                        <i class="fas fa-times-circle text-danger me-2"></i>Denied Requests
                                    </label>
                                    <div class="form-text">Notify when requests are denied</div>
                                </div>
                                
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="notify_critical" name="notify_critical" 
                                           <?php echo ($teams_config['notifications']['critical_priority'] ?? false) ? 'checked' : ''; ?>>
                                    <label class="form-check-label fw-bold" for="notify_critical">
                                        <i class="fas fa-exclamation-triangle text-warning me-2"></i>Critical Priority
                                    </label>
                                    <div class="form-text">Always notify for critical priority requests</div>
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
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Configuration
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Recent Notifications -->
        <?php if (!empty($teams_logs)): ?>
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-history text-info me-2"></i> Recent Notifications
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Message Type</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($teams_logs as $log): ?>
                                <tr>
                                    <td>
                                        <small>
                                            <?php 
                                            $time = strtotime($log['timestamp']);
                                            echo $time ? date('M j, H:i', $time) : 'Unknown';
                                            ?>
                                        </small>
                                    </td>
                                    <td><?php echo htmlspecialchars($log['message_type'] ?? 'Unknown'); ?></td>
                                    <td>
                                        <?php if ($log['success'] ?? false): ?>
                                            <span class="badge bg-success">Success</span>
                                        <?php else: ?>
                                            <span class="badge bg-danger">Failed</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small class="text-muted">
                                            <?php if (isset($log['error']) && !empty($log['error'])): ?>
                                                Error: <?php echo htmlspecialchars($log['error']); ?>
                                            <?php else: ?>
                                                HTTP <?php echo $log['http_code'] ?? '200'; ?>
                                            <?php endif; ?>
                                        </small>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <!-- Message Preview -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-eye text-secondary me-2"></i> Message Preview
                </h5>
            </div>
            <div class="card-body">
                <p class="text-muted mb-3">This is how notifications will appear in your Teams channel:</p>
                <div class="webhook-preview">
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "0078D4",
  "summary": "New EDL Request Submitted",
  "sections": [
    {
      "activityTitle": "🛡️ **New EDL Request Submitted**",
      "activitySubtitle": "EDL Manager → #security-team",
      "facts": [
        {
          "name": "Entry:",
          "value": "`malicious.example.com`"
        },
        {
          "name": "Type:",
          "value": "🏢 DOMAIN"
        },
        {
          "name": "Priority:",
          "value": "🔴 **CRITICAL**"
        },
        {
          "name": "Submitted by:",
          "value": "security.analyst"
        },
        {
          "name": "Justification:",
          "value": "Malware hosting domain identified..."
        }
      ],
      "markdown": true
    }
  ]
}
                </div>
            </div>
        </div>
    </div>
    
    <!-- Webhook Help Modal -->
    <div class="modal fade" id="webhookHelpModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fab fa-microsoft text-info"></i> How to Get Teams Webhook URL
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-12">
                            <h6><i class="fas fa-step-forward text-primary me-2"></i>Step-by-Step Instructions:</h6>
                            <ol class="list-group list-group-numbered">
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Open Microsoft Teams</div>
                                        Navigate to your desired Teams channel
                                    </div>
                                    <span class="badge bg-primary rounded-pill">1</span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Access Channel Settings</div>
                                        Click the three dots (...) next to your channel name
                                    </div>
                                    <span class="badge bg-primary rounded-pill">2</span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Add Connector</div>
                                        Select "Connectors" from the dropdown menu
                                    </div>
                                    <span class="badge bg-primary rounded-pill">3</span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Find Incoming Webhook</div>
                                        Search for "Incoming Webhook" and click "Add"
                                    </div>
                                    <span class="badge bg-primary rounded-pill">4</span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Configure Webhook</div>
                                        Give it a name like "EDL Manager" and upload an icon (optional)
                                    </div>
                                    <span class="badge bg-primary rounded-pill">5</span>
                                </li>
                                <li class="list-group-item d-flex justify-content-between align-items-start">
                                    <div class="ms-2 me-auto">
                                        <div class="fw-bold">Copy URL</div>
                                        Copy the generated webhook URL and paste it in the configuration above
                                    </div>
                                    <span class="badge bg-success rounded-pill">6</span>
                                </li>
                            </ol>
                        </div>
                    </div>
                    
                    <div class="alert alert-info mt-3">
                        <i class="fas fa-info-circle"></i>
                        <strong>Note:</strong> The webhook URL should start with <code>https://outlook.office.com/webhook/</code> or <code>https://[tenant].webhook.office.com/</code>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <a href="https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook" 
                       target="_blank" class="btn btn-primary">
                        <i class="fas fa-external-link-alt"></i> Official Documentation
                    </a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <footer class="bg-light py-3 mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p class="mb-0 text-muted">
                        &copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?> v<?php echo APP_VERSION; ?>
                    </p>
                </div>
                <div class="col-md-6 text-end">
                    <small class="text-muted">
                        Last updated: <?php echo date('Y-m-d H:i:s'); ?>
                    </small>
                </div>
            </div>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function testWebhook() {
            const webhookUrl = document.getElementById('webhook_url').value;
            if (!webhookUrl) {
                alert('Please enter a webhook URL first');
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
            action.value = 'test_webhook';
            
            const webhookInput = document.createElement('input');
            webhookInput.type = 'hidden';
            webhookInput.name = 'webhook_url';
            webhookInput.value = webhookUrl;
            
            form.appendChild(csrfToken);
            form.appendChild(action);
            form.appendChild(webhookInput);
            
            document.body.appendChild(form);
            form.submit();
        }
        
        function showWebhookHelp() {
            const modal = new bootstrap.Modal(document.getElementById('webhookHelpModal'));
            modal.show();
        }
        
        // Auto-enable notifications when Teams is enabled
        document.getElementById('teams_enabled').addEventListener('change', function() {
            const notificationCheckboxes = [
                'notify_new_requests',
                'notify_critical'
            ];
            
            if (this.checked) {
                notificationCheckboxes.forEach(id => {
                    document.getElementById(id).checked = true;
                });
            }
        });
        
        // Validate webhook URL format
        document.getElementById('webhook_url').addEventListener('input', function() {
            const url = this.value;
            const isValid = url.includes('webhook.office.com') || url.includes('outlook.office.com/webhook');
            
            if (url && !isValid) {
                this.setCustomValidity('Please enter a valid Microsoft Teams webhook URL');
            } else {
                this.setCustomValidity('');
            }
        });
        
        // Show notification
        function showNotification(message, type = 'info') {
            const alertClass = 'alert-' + type;
            const notification = document.createElement('div');
            notification.className = `alert ${alertClass} alert-dismissible position-fixed`;
            notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'}"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        }
        
        // Initialize tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });
        
        // Form validation
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const teamsEnabled = document.getElementById('teams_enabled');
            const webhookUrl = document.getElementById('webhook_url');
            
            form.addEventListener('submit', function(e) {
                if (teamsEnabled.checked && !webhookUrl.value) {
                    e.preventDefault();
                    showNotification('Webhook URL is required when Teams notifications are enabled', 'danger');
                    webhookUrl.focus();
                    return false;
                }
            });
        });
    </script>
</body>
</html>