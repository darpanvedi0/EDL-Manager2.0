<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'Microsoft Teams Configuration';
$error_message = '';
$success_message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'save_config') {
            $teams_config = [
                'enabled' => isset($_POST['enabled']),
                'webhook_url' => sanitize_input($_POST['webhook_url'] ?? ''),
                'channel_name' => sanitize_input($_POST['channel_name'] ?? ''),
                'custom_message' => sanitize_input($_POST['custom_message'] ?? ''),
                'mention_users' => array_filter(array_map('trim', explode(',', $_POST['mention_users'] ?? ''))),
                'notifications' => [
                    'new_requests' => isset($_POST['notify_new_requests']),
                    'approved_requests' => isset($_POST['notify_approved']),
                    'denied_requests' => isset($_POST['notify_denied']),
                    'critical_priority' => isset($_POST['notify_critical'])
                ]
            ];
            
            write_json_file(DATA_DIR . '/teams_config.json', $teams_config);
            
            // Log configuration change
            $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
            $audit_logs[] = [
                'id' => uniqid('audit_', true),
                'timestamp' => date('c'),
                'action' => 'config_change',
                'entry' => 'teams_config',
                'user' => $_SESSION['username'],
                'details' => 'Updated Microsoft Teams configuration',
                'admin_comment' => $teams_config['enabled'] ? 'Teams notifications enabled' : 'Teams notifications disabled'
            ];
            write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
            
            show_flash('Teams configuration saved successfully.', 'success');
            header('Location: teams_config.php');
            exit;
        } elseif ($action === 'test_webhook') {
            $webhook_url = sanitize_input($_POST['webhook_url'] ?? '');
            if (!empty($webhook_url)) {
                $result = test_teams_webhook($webhook_url);
                if ($result['success']) {
                    show_flash($result['message'], 'success');
                } else {
                    $error_message = $result['message'];
                }
            } else {
                $error_message = 'Webhook URL is required for testing.';
            }
        }
    }
}

// Load current configuration
$teams_config = read_json_file(DATA_DIR . '/teams_config.json');
if (!$teams_config) {
    $teams_config = [
        'enabled' => false,
        'webhook_url' => '',
        'channel_name' => '',
        'custom_message' => '',
        'mention_users' => [],
        'notifications' => [
            'new_requests' => true,
            'approved_requests' => true,
            'denied_requests' => true,
            'critical_priority' => true
        ]
    ];
}

function test_teams_webhook($webhook_url) {
    $test_message = [
        "@type" => "MessageCard",
        "@context" => "http://schema.org/extensions",
        "themeColor" => "0078D4",
        "summary" => "EDL Manager Test Message",
        "sections" => [
            [
                "activityTitle" => "🧪 **Test Message from EDL Manager**",
                "activitySubtitle" => "Configuration Test",
                "activityImage" => "https://img.icons8.com/color/48/000000/test-tube.png",
                "text" => "This is a test message to verify your Teams webhook configuration is working correctly.",
                "facts" => [
                    ["name" => "Test Time", "value" => date('Y-m-d H:i:s')],
                    ["name" => "Source", "value" => "EDL Manager Teams Configuration"],
                    ["name" => "Status", "value" => "✅ Webhook Active"]
                ]
            ]
        ]
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhook_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($test_message));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        return ['success' => false, 'message' => 'Connection error: ' . $error];
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

// Include the centralized header
require_once '../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fab fa-microsoft me-2"></i>
        Microsoft Teams Configuration
    </h1>
    <p class="mb-0 opacity-75">Configure webhook notifications for EDL requests and approvals</p>
</div>

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo $error_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Status Overview -->
<div class="row mb-4">
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator <?php echo $teams_config['enabled'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                    <i class="fas fa-<?php echo $teams_config['enabled'] ? 'check-circle' : 'times-circle'; ?> me-1"></i>
                    <?php echo $teams_config['enabled'] ? 'Enabled' : 'Disabled'; ?>
                </div>
                <h6 class="card-title">Teams Status</h6>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator status-enabled mb-2">
                    <i class="fas fa-bell me-1"></i>
                    <?php echo count(array_filter($teams_config['notifications'] ?? [])); ?> Types
                </div>
                <h6 class="card-title">Notification Types</h6>
                <small class="text-muted">Configured alerts</small>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator status-enabled mb-2">
                    <i class="fas fa-users me-1"></i>
                    <?php echo count($teams_config['mention_users'] ?? []); ?> Users
                </div>
                <h6 class="card-title">Mentions</h6>
                <small class="text-muted">To notify</small>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator status-enabled mb-2">
                    <i class="fas fa-history me-1"></i>
                    <?php echo count($teams_logs); ?> Recent Logs
                </div>
                <h6 class="card-title">Notification History</h6>
            </div>
        </div>
    </div>
</div>

<!-- Microsoft Teams Integration Info -->
<div class="teams-card mb-4">
    <div class="row align-items-center">
        <div class="col-md-8">
            <h4 class="mb-2">
                <i class="fab fa-microsoft me-2"></i>
                Microsoft Teams Integration
            </h4>
            <p class="mb-0">Get real-time notifications about EDL requests directly in your Teams channel!</p>
        </div>
        <div class="col-md-4 text-end">
            <i class="fab fa-microsoft fa-3x opacity-50"></i>
        </div>
    </div>
</div>

<!-- Configuration Form -->
<div class="card">
    <div class="card-header bg-light">
        <h5 class="mb-0">
            <i class="fas fa-cog me-2"></i>
            Webhook Configuration
        </h5>
    </div>
    <div class="card-body">
        <form method="post" class="needs-validation" novalidate>
            <input type="hidden" name="action" value="save_config">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            
            <!-- Enable Teams -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="enabled" name="enabled" 
                               <?php echo $teams_config['enabled'] ? 'checked' : ''; ?>>
                        <label class="form-check-label fw-bold" for="enabled">
                            Enable Microsoft Teams Notifications
                        </label>
                        <div class="form-text">Turn on/off all Teams notifications</div>
                    </div>
                </div>
            </div>
            
            <div id="teams-config" style="<?php echo !$teams_config['enabled'] ? 'display: none;' : ''; ?>">
                <!-- Webhook URL -->
                <div class="row mb-3">
                    <div class="col-12">
                        <label for="webhook_url" class="form-label fw-bold">
                            <i class="fas fa-link me-1"></i>
                            Webhook URL <span class="text-danger">*</span>
                        </label>
                        <input type="url" class="form-control" id="webhook_url" name="webhook_url" 
                               value="<?php echo htmlspecialchars($teams_config['webhook_url']); ?>"
                               placeholder="https://outlook.office.com/webhook/..." required>
                        <div class="form-text">
                            <i class="fas fa-info-circle me-1"></i>
                            Get this URL from your Teams channel → Connectors → Incoming Webhook
                        </div>
                    </div>
                </div>
                
                <!-- Channel Name -->
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label for="channel_name" class="form-label">
                            <i class="fas fa-hashtag me-1"></i>
                            Channel Name
                        </label>
                        <input type="text" class="form-control" id="channel_name" name="channel_name" 
                               value="<?php echo htmlspecialchars($teams_config['channel_name']); ?>"
                               placeholder="security-alerts">
                        <div class="form-text">Display name for the channel (optional)</div>
                    </div>
                    <div class="col-md-6">
                        <label for="custom_message" class="form-label">
                            <i class="fas fa-comment me-1"></i>
                            Custom Message Prefix
                        </label>
                        <input type="text" class="form-control" id="custom_message" name="custom_message" 
                               value="<?php echo htmlspecialchars($teams_config['custom_message']); ?>"
                               placeholder="🛡️ Security Alert">
                        <div class="form-text">Optional prefix for all messages</div>
                    </div>
                </div>
                
                <!-- Mention Users -->
                <div class="row mb-3">
                    <div class="col-12">
                        <label for="mention_users" class="form-label">
                            <i class="fas fa-at me-1"></i>
                            Mention Users (Optional)
                        </label>
                        <input type="text" class="form-control" id="mention_users" name="mention_users" 
                               value="<?php echo htmlspecialchars(implode(', ', $teams_config['mention_users'])); ?>"
                               placeholder="user1@company.com, user2@company.com">
                        <div class="form-text">Comma-separated list of email addresses to mention in notifications</div>
                    </div>
                </div>
                
                <!-- Notification Types -->
                <div class="teams-section mb-4">
                    <h6 class="fw-bold mb-3">
                        <i class="fas fa-bell me-2"></i>
                        Notification Types
                    </h6>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="notify_new_requests" name="notify_new_requests" 
                                       <?php echo ($teams_config['notifications']['new_requests'] ?? false) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="notify_new_requests">
                                    <i class="fas fa-plus text-primary me-1"></i>
                                    New EDL Requests
                                </label>
                            </div>
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="notify_approved" name="notify_approved" 
                                       <?php echo ($teams_config['notifications']['approved_requests'] ?? false) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="notify_approved">
                                    <i class="fas fa-check-circle text-success me-1"></i>
                                    Approved Requests
                                </label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="notify_denied" name="notify_denied" 
                                       <?php echo ($teams_config['notifications']['denied_requests'] ?? false) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="notify_denied">
                                    <i class="fas fa-times-circle text-danger me-1"></i>
                                    Denied Requests
                                </label>
                            </div>
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="notify_critical" name="notify_critical" 
                                       <?php echo ($teams_config['notifications']['critical_priority'] ?? false) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="notify_critical">
                                    <i class="fas fa-exclamation-triangle text-warning me-1"></i>
                                    Critical Priority (Always)
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Action Buttons -->
                <div class="row">
                    <div class="col-md-6">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-1"></i>
                            Save Configuration
                        </button>
                    </div>
                    <div class="col-md-6 text-end">
                        <button type="submit" name="action" value="test_webhook" class="btn btn-outline-info" 
                                onclick="return confirm('Send a test message to Teams?');">
                            <i class="fas fa-paper-plane me-1"></i>
                            Test Webhook
                        </button>
                    </div>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Message Preview -->
<?php if ($teams_config['enabled']): ?>
<div class="card mt-4">
    <div class="card-header bg-light">
        <h5 class="mb-0">
            <i class="fas fa-eye me-2"></i>
            Message Preview
        </h5>
    </div>
    <div class="card-body">
        <div class="webhook-preview">
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "0078D4",
  "summary": "New EDL Request",
  "sections": [
    {
      "activityTitle": "<?php echo !empty($teams_config['custom_message']) ? $teams_config['custom_message'] . ' ' : ''; ?>🛡️ **New EDL Request Submitted**",
      "activitySubtitle": "Priority: Medium | Type: IP Address",
      "activityImage": "https://img.icons8.com/color/48/000000/security-checked.png",
      "text": "A new EDL request has been submitted and requires approval.",
      "facts": [
        {"name": "Entry", "value": "192.168.1.100"},
        {"name": "Type", "value": "IP Address"},
        {"name": "Priority", "value": "Medium"},
        {"name": "Submitted By", "value": "<?php echo htmlspecialchars($_SESSION['username']); ?>"},
        {"name": "Business Justification", "value": "Malicious IP detected in security logs"}
      ]
    }
  ]<?php if (!empty($teams_config['mention_users'])): ?>,
  "potentialAction": [
    {
      "@type": "OpenUri",
      "name": "View Request",
      "targets": [
        {"os": "default", "uri": "<?php echo (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']); ?>/approvals.php"}
      ]
    }
  ]<?php endif; ?>
}
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Recent Notification Logs -->
<?php if (!empty($teams_logs)): ?>
<div class="card mt-4">
    <div class="card-header bg-light">
        <h5 class="mb-0">
            <i class="fas fa-history me-2"></i>
            Recent Notifications
        </h5>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event</th>
                        <th>Entry</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($teams_logs as $log): ?>
                    <tr>
                        <td><?php echo date('M j, H:i', strtotime($log['timestamp'] ?? '')); ?></td>
                        <td><?php echo htmlspecialchars($log['event_type'] ?? ''); ?></td>
                        <td><code><?php echo htmlspecialchars($log['entry'] ?? ''); ?></code></td>
                        <td>
                            <span class="badge bg-<?php echo ($log['success'] ?? false) ? 'success' : 'danger'; ?>">
                                <?php echo ($log['success'] ?? false) ? 'Sent' : 'Failed'; ?>
                            </span>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
<?php endif; ?>

<script>
// Toggle configuration section based on enabled checkbox
document.getElementById('enabled').addEventListener('change', function() {
    const configSection = document.getElementById('teams-config');
    configSection.style.display = this.checked ? 'block' : 'none';
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