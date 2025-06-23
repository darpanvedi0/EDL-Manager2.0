<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

// Load Teams notifications if file exists (optional)
if (file_exists('../includes/teams_notifications.php')) {
    require_once '../includes/teams_notifications.php';
}

$auth = new EDLAuth();
$auth->require_permission('submit');

$page_title = 'Submit Request';
$error_message = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $entry = sanitize_input($_POST['entry'] ?? '');
        $type = sanitize_input($_POST['type'] ?? '');
        $comment = sanitize_input($_POST['comment'] ?? '');
        $justification = sanitize_input($_POST['justification'] ?? '');
        $priority = sanitize_input($_POST['priority'] ?? 'medium');
        
        $errors = [];
        
        // Validate required fields
        if (empty($entry)) $errors[] = 'Entry is required';
        if (empty($justification)) $errors[] = 'Justification is required';
        
        // Auto-detect type if not specified
        if (empty($type) || $type === 'auto') {
            if (preg_match('/^https?:\/\//', $entry)) {
                $type = 'url';
            } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                $type = 'ip';
            } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $entry)) {
                $type = 'domain';
            } else {
                $errors[] = 'Could not determine entry type. Please select manually.';
            }
        }
        
        // Check if entry already exists
        if (!empty($entry) && !empty($type)) {
            $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
            $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
            $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
            
            // Check denied entries FIRST (highest priority)
            foreach ($denied_entries as $den) {
                if ($den['entry'] === $entry && $den['type'] === $type) {
                    $denied_reason = htmlspecialchars($den['reason'] ?? 'No reason provided');
                    $denied_by = htmlspecialchars($den['denied_by'] ?? 'Admin');
                    $denied_date = isset($den['denied_at']) ? date('M j, Y', strtotime($den['denied_at'])) : 'Unknown';
                    
                    $errors[] = "This entry was previously denied and cannot be submitted.<br>" .
                               "<strong>Denial Reason:</strong> {$denied_reason}<br>" .
                               "<strong>Denied by:</strong> {$denied_by} on {$denied_date}<br>" .
                               "<em>Contact an administrator if you believe this is an error.</em>";
                    break;
                }
            }
            
            // Only check other lists if not denied
            if (empty($errors)) {
                // Check pending
                foreach ($pending_requests as $req) {
                    if ($req['entry'] === $entry && $req['status'] === 'pending') {
                        $errors[] = 'Entry already has a pending request';
                        break;
                    }
                }
                
                // Check approved
                foreach ($approved_entries as $ent) {
                    if ($ent['entry'] === $entry && $ent['status'] === 'active') {
                        $errors[] = 'Entry already exists in approved list';
                        break;
                    }
                }
            }
        }
        
        if (empty($errors)) {
            // Create new request
            $request = [
                'id' => uniqid('req_', true),
                'entry' => $entry,
                'type' => $type,
                'comment' => $comment,
                'justification' => $justification,
                'priority' => $priority,
                'submitted_by' => $_SESSION['username'],
                'submitted_at' => date('c'),
                'status' => 'pending'
            ];
            
            // Save request
            $requests = read_json_file(DATA_DIR . '/pending_requests.json');
            $requests[] = $request;
            
            if (write_json_file(DATA_DIR . '/pending_requests.json', $requests)) {
                // Add audit log
                $logs = read_json_file(DATA_DIR . '/audit_logs.json');
                $logs[] = [
                    'id' => uniqid('audit_', true),
                    'timestamp' => date('c'),
                    'action' => 'submit',
                    'entry' => $entry,
                    'user' => $_SESSION['username'],
                    'details' => "Submitted {$type} request",
                    'request_id' => $request['id']
                ];
                write_json_file(DATA_DIR . '/audit_logs.json', $logs);
                
                // Send Teams notification for new request (if Teams integration exists)
                $teams_notification_sent = false;
                if (function_exists('notify_teams_new_request')) {
                    try {
                        $teams_notification_sent = notify_teams_new_request($request);
                    } catch (Exception $e) {
                        error_log('Teams notification failed: ' . $e->getMessage());
                    }
                }
                
                if ($teams_notification_sent) {
                    show_flash('Request submitted successfully! Teams notification sent. You will be notified when it is reviewed.', 'success');
                } else {
                    show_flash('Request submitted successfully! You will be notified when it is reviewed.', 'success');
                }
                
                header('Location: submit_request.php');
                exit;
            } else {
                $error_message = 'Failed to save request. Please try again.';
            }
        } else {
            $error_message = implode('<br>', $errors);
        }
    }
}

// Get user's recent requests
$user_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$user_requests = array_filter($user_requests, function($r) {
    return $r['submitted_by'] === $_SESSION['username'];
});
$user_requests = array_slice(array_reverse($user_requests), 0, 5);

$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];
$flash = get_flash();
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
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        .btn {
            border-radius: 10px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-1px);
        }
        .alert {
            border: none;
            border-radius: 10px;
            border-left: 4px solid;
        }
        .alert-success {
            border-left-color: #198754;
            background-color: rgba(25, 135, 84, 0.1);
        }
        .dropdown-menu {
            border: none;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            border-radius: 10px;
        }
        .page-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
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
                        <a class="nav-link active" href="submit_request.php">
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
                    
                    <!-- Fixed Admin Dropdown -->
                    <?php if (in_array('manage', $user_permissions)): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
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
                            <li><a class="dropdown-item" href="teams_config.php">
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
    
    <?php if ($flash): ?>
    <div class="container mt-3">
        <div class="alert alert-<?php echo $flash['type']; ?> alert-dismissible fade show">
            <i class="fas fa-check-circle"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <?php if ($error_message): ?>
    <div class="container mt-3">
        <div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle"></i>
            <?php echo $error_message; ?>
        </div>
    </div>
    <?php endif; ?>
    
    <div class="container mt-4">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="mb-2">
                <i class="fas fa-plus me-2"></i>
                Submit EDL Request
            </h1>
            <p class="mb-0 opacity-75">Request to add IP addresses, domains, or URLs to the blocklist</p>
        </div>
        
        <div class="row">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-light">
                        <h5 class="mb-0">
                            <i class="fas fa-edit me-2"></i> New Request Details
                        </h5>
                    </div>
                    <div class="card-body">
                        <form method="POST" class="needs-validation" novalidate>
                            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                            
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="mb-3">
                                        <label for="entry" class="form-label">
                                            Entry to Block <span class="text-danger">*</span>
                                        </label>
                                        <input type="text" class="form-control" id="entry" name="entry" 
                                               value="<?php echo htmlspecialchars($_POST['entry'] ?? ''); ?>"
                                               placeholder="192.168.1.1, malicious.com, or https://bad-site.com"
                                               required>
                                        <div class="form-text">
                                            Enter the IP address, domain, or URL you want to block
                                        </div>
                                        <div id="type-indicator" class="small mt-1"></div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="mb-3">
                                        <label for="type" class="form-label">
                                            Type <span class="text-danger">*</span>
                                        </label>
                                        <select class="form-select" id="type" name="type" required>
                                            <option value="auto" <?php echo ($_POST['type'] ?? 'auto') === 'auto' ? 'selected' : ''; ?>>
                                                Auto-detect
                                            </option>
                                            <option value="ip" <?php echo ($_POST['type'] ?? '') === 'ip' ? 'selected' : ''; ?>>
                                                IP Address
                                            </option>
                                            <option value="domain" <?php echo ($_POST['type'] ?? '') === 'domain' ? 'selected' : ''; ?>>
                                                Domain
                                            </option>
                                            <option value="url" <?php echo ($_POST['type'] ?? '') === 'url' ? 'selected' : ''; ?>>
                                                URL
                                            </option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="priority" class="form-label">Priority</label>
                                        <select class="form-select" id="priority" name="priority">
                                            <option value="low" <?php echo ($_POST['priority'] ?? 'medium') === 'low' ? 'selected' : ''; ?>>
                                                Low - Routine cleanup
                                            </option>
                                            <option value="medium" <?php echo ($_POST['priority'] ?? 'medium') === 'medium' ? 'selected' : ''; ?>>
                                                Medium - Standard threat
                                            </option>
                                            <option value="high" <?php echo ($_POST['priority'] ?? 'medium') === 'high' ? 'selected' : ''; ?>>
                                                High - Active threat
                                            </option>
                                            <option value="critical" <?php echo ($_POST['priority'] ?? 'medium') === 'critical' ? 'selected' : ''; ?>>
                                                Critical - Immediate action
                                            </option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="justification" class="form-label">
                                    Business Justification <span class="text-danger">*</span>
                                </label>
                                <textarea class="form-control" id="justification" name="justification" 
                                          rows="4" required
                                          placeholder="Explain why this entry should be blocked. Include threat intelligence, incident details, or business requirements."><?php echo htmlspecialchars($_POST['justification'] ?? ''); ?></textarea>
                                <div class="form-text">
                                    Provide clear justification for blocking this entry
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label for="comment" class="form-label">Additional Comments</label>
                                <textarea class="form-control" id="comment" name="comment" 
                                          rows="3"
                                          placeholder="Any additional context or notes for the approver (optional)"><?php echo htmlspecialchars($_POST['comment'] ?? ''); ?></textarea>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <a href="../index.php" class="btn btn-secondary">
                                        <i class="fas fa-arrow-left"></i> Back to Dashboard
                                    </a>
                                </div>
                                <div class="col-md-6 text-end">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-paper-plane"></i> Submit Request
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-4">
                <!-- Guidelines -->
                <div class="card">
                    <div class="card-header bg-light">
                        <h6 class="mb-0">
                            <i class="fas fa-info-circle text-info"></i> Entry Format Examples
                        </h6>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <h6><i class="fas fa-network-wired text-primary"></i> IP Address:</h6>
                            <code class="small d-block">192.168.1.100</code>
                            <code class="small d-block">10.0.0.0/24</code>
                            <code class="small d-block">2001:db8::1</code>
                        </div>
                        
                        <div class="mb-3">
                            <h6><i class="fas fa-globe text-success"></i> Domain:</h6>
                            <code class="small d-block">malicious.com</code>
                            <code class="small d-block">evil.example.org</code>
                        </div>
                        
                        <div class="mb-3">
                            <h6><i class="fas fa-link text-info"></i> URL:</h6>
                            <code class="small d-block">https://bad-site.com/malware</code>
                            <code class="small d-block">http://phishing.example.com</code>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Requests -->
                <div class="card mt-3">
                    <div class="card-header bg-light">
                        <h6 class="mb-0">
                            <i class="fas fa-history text-secondary"></i> Your Recent Requests
                        </h6>
                    </div>
                    <div class="card-body">
                        <?php if (empty($user_requests)): ?>
                            <div class="text-center text-muted">
                                <i class="fas fa-inbox fa-2x mb-2"></i><br>
                                <small>No recent requests</small>
                            </div>
                        <?php else: ?>
                            <?php foreach ($user_requests as $request): ?>
                                <div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom">
                                    <div>
                                        <code class="small"><?php echo htmlspecialchars($request['entry']); ?></code><br>
                                        <small class="text-muted">
                                            <?php 
                                            $time = strtotime($request['submitted_at']);
                                            echo $time ? date('M j, H:i', $time) : 'Unknown';
                                            ?>
                                        </small>
                                    </div>
                                    <span class="badge <?php 
                                        echo $request['status'] === 'pending' ? 'bg-warning text-dark' : 
                                             ($request['status'] === 'approved' ? 'bg-success' : 'bg-danger'); 
                                    ?>">
                                        <?php echo ucfirst($request['status']); ?>
                                    </span>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
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
        // Auto-detect entry type and check against denied entries
        document.getElementById('entry').addEventListener('input', function() {
            const entry = this.value.trim();
            const typeSelect = document.getElementById('type');
            const indicator = document.getElementById('type-indicator');
            
            if (entry && typeSelect.value === 'auto') {
                let detectedType = 'unknown';
                let icon = '';
                
                if (/^https?:\/\//.test(entry)) {
                    detectedType = 'url';
                    icon = 'fas fa-link';
                    typeSelect.value = 'url';
                } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(entry)) {
                    detectedType = 'ip';
                    icon = 'fas fa-network-wired';
                    typeSelect.value = 'ip';
                } else if (/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/.test(entry)) {
                    detectedType = 'domain';
                    icon = 'fas fa-globe';
                    typeSelect.value = 'domain';
                }
                
                if (detectedType !== 'unknown') {
                    indicator.innerHTML = `<i class="${icon} text-success"></i> Auto-detected as ${detectedType.toUpperCase()}`;
                    indicator.className = 'small text-success mt-1';
                } else {
                    indicator.innerHTML = '<i class="fas fa-question-circle text-warning"></i> Could not auto-detect type';
                    indicator.className = 'small text-warning mt-1';
                }
            } else {
                indicator.innerHTML = '';
            }
            
            // Check against denied entries in real-time
            if (entry.length > 3) {
                checkDeniedEntries(entry, typeSelect.value);
            } else {
                clearDeniedWarning();
            }
        });
        
        // Function to check denied entries via AJAX
        function checkDeniedEntries(entry, type) {
            fetch('../api/check_denied.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    entry: entry,
                    type: type
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.denied) {
                    showDeniedWarning(data.reason, data.denied_by, data.denied_date);
                } else {
                    clearDeniedWarning();
                }
            })
            .catch(error => {
                console.warn('Error checking denied entries:', error);
            });
        }
        
        // Show denied warning
        function showDeniedWarning(reason, deniedBy, deniedDate) {
            const existingWarning = document.getElementById('denied-warning');
            if (existingWarning) {
                existingWarning.remove();
            }
            
            const entryField = document.getElementById('entry');
            const warning = document.createElement('div');
            warning.id = 'denied-warning';
            warning.className = 'alert alert-danger mt-2';
            warning.innerHTML = `
                <i class="fas fa-ban"></i> <strong>Entry Previously Denied</strong><br>
                <small><strong>Reason:</strong> ${reason}<br>
                <strong>Denied by:</strong> ${deniedBy} on ${deniedDate}<br>
                <em>This entry cannot be submitted. Contact an administrator if needed.</em></small>
            `;
            
            entryField.parentNode.appendChild(warning);
            entryField.classList.add('is-invalid');
        }
        
        // Clear denied warning
        function clearDeniedWarning() {
            const warning = document.getElementById('denied-warning');
            if (warning) {
                warning.remove();
            }
            const entryField = document.getElementById('entry');
            entryField.classList.remove('is-invalid');
        }
        
        // Form validation
        (function() {
            const forms = document.querySelectorAll('.needs-validation');
            Array.prototype.slice.call(forms).forEach(function(form) {
                form.addEventListener('submit', function(event) {
                    // Check if there's a denied warning
                    const deniedWarning = document.getElementById('denied-warning');
                    if (deniedWarning) {
                        event.preventDefault();
                        event.stopPropagation();
                        showNotification('Cannot submit a denied entry', 'danger');
                        return false;
                    }
                    
                    if (!form.checkValidity()) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                });
            });
        })();
        
        // Show notification function
        function showNotification(message, type = 'info') {
            const alertClass = 'alert-' + type;
            const notification = document.createElement('div');
            notification.className = `alert ${alertClass} alert-dismissible position-fixed`;
            notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            
            notification.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 3000);
        }
        
        // Initialize tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });
    </script>
</body>
</html>