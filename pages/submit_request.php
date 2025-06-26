<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/validation.php';

// Load Teams notifications if file exists (optional)
if (file_exists('../includes/teams_notifications.php')) {
    require_once '../includes/teams_notifications.php';
}

$auth = new EDLAuth();
$auth->require_permission('submit');

$page_title = 'Submit Request';
$error_message = '';

// Enhanced ServiceNow ticket validation function
function validate_servicenow_ticket_enhanced($ticket) {
    if (empty($ticket)) {
        return ['valid' => false, 'error' => 'ServiceNow ticket is required'];
    }
    
    $pattern = '/^(INC|REQ|CHG|RITM|TASK|SCTASK|SIR)[0-9]{7}$/';
    if (!preg_match($pattern, $ticket)) {
        return ['valid' => false, 'error' => 'Invalid ServiceNow ticket format. Use: INC1234567, REQ1234567, CHG1234567, SIR1234567, etc.'];
    }
    
    return ['valid' => true, 'type' => 'ServiceNow Ticket'];
}

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
        $servicenow_ticket = sanitize_input($_POST['servicenow_ticket'] ?? '');
        
        $errors = [];
        
        // Validate required fields
        if (empty($entry)) $errors[] = 'Entry is required';
        if (empty($justification)) $errors[] = 'Justification is required';
        if (empty($servicenow_ticket)) $errors[] = 'ServiceNow ticket is required';
        
        // Validate ServiceNow ticket format using enhanced validation
        if (!empty($servicenow_ticket)) {
            $snow_validation = validate_servicenow_ticket_enhanced($servicenow_ticket);
            if (!$snow_validation['valid']) {
                $errors[] = $snow_validation['error'];
            }
        }
        
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
                    $denied_date = isset($den['denied_at']) ? 
                        date('M j, Y H:i', strtotime($den['denied_at'])) : 'Unknown';
                    
                    $errors[] = "⚠️ This entry was previously <strong>DENIED</strong> on {$denied_date} by {$denied_by}.<br>" .
                               "<strong>Reason:</strong> {$denied_reason}<br>" .
                               "Please contact your administrator if you believe this should be reconsidered.";
                    break;
                }
            }
            
            // Check pending requests
            if (empty($errors)) {
                foreach ($pending_requests as $pending) {
                    if ($pending['entry'] === $entry && $pending['type'] === $type) {
                        $pending_by = htmlspecialchars($pending['submitted_by'] ?? 'Unknown');
                        $pending_date = isset($pending['submitted_at']) ? 
                            date('M j, Y H:i', strtotime($pending['submitted_at'])) : 'Unknown';
                        
                        if ($pending['submitted_by'] === $_SESSION['username']) {
                            $errors[] = "You already have a pending request for this entry (submitted on {$pending_date}).";
                        } else {
                            $errors[] = "This entry is already pending approval (submitted by {$pending_by} on {$pending_date}).";
                        }
                        break;
                    }
                }
            }
            
            // Check approved entries - FIXED: Only check entries with 'active' status
            if (empty($errors)) {
                foreach ($approved_entries as $approved) {
                    if ($approved['entry'] === $entry && 
                        $approved['type'] === $type && 
                        isset($approved['status']) && 
                        $approved['status'] === 'active') {
                        
                        $approved_by = htmlspecialchars($approved['approved_by'] ?? 'Unknown');
                        $approved_date = isset($approved['approved_at']) ? 
                            date('M j, Y H:i', strtotime($approved['approved_at'])) : 'Unknown';
                        
                        $errors[] = "This entry is already approved and active on the EDL (approved by {$approved_by} on {$approved_date}).";
                        break;
                    }
                }
            }
        }
        
        if (empty($errors)) {
            $request = [
                'id' => uniqid('req_', true),
                'entry' => $entry,
                'type' => $type,
                'comment' => $comment,
                'justification' => $justification,
                'priority' => $priority,
                'servicenow_ticket' => $servicenow_ticket,
                'submitted_by' => $_SESSION['username'],
                'submitted_at' => date('c'),
                'status' => 'pending'
            ];
            
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
                    'details' => "Submitted {$type} request (ServiceNow: {$servicenow_ticket})",
                    'request_id' => $request['id'],
                    'servicenow_ticket' => $servicenow_ticket
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

// Include the centralized header
require_once '../includes/header.php';
?>

<div class="container mt-4">

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo $error_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-plus me-2"></i>
        Submit EDL Request
    </h1>
    <p class="mb-0 opacity-75">Submit a new entry for review and approval to the External Dynamic List</p>
</div>

<!-- Form -->
<div class="row">
    <div class="col-lg-8">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">
                    <i class="fas fa-edit me-1"></i> Request Information
                </h5>
            </div>
            <div class="card-body">
                <form method="POST" class="needs-validation" novalidate>
                    <?php echo csrf_token_field(); ?>
                    
                    <div class="row mb-3">
                        <div class="col-md-8">
                            <label for="entry" class="form-label fw-bold">Entry <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="entry" name="entry" 
                                   value="<?php echo htmlspecialchars($_POST['entry'] ?? ''); ?>"
                                   placeholder="e.g., 192.168.1.100, malicious.com, or https://bad-site.com"
                                   required>
                            <div class="form-text">Enter the IP address, domain, or URL to be blocked</div>
                        </div>
                        <div class="col-md-4">
                            <label for="type" class="form-label fw-bold">Type</label>
                            <select class="form-select" id="type" name="type">
                                <option value="auto" <?php echo ($_POST['type'] ?? '') === 'auto' ? 'selected' : ''; ?>>Auto-detect</option>
                                <option value="ip" <?php echo ($_POST['type'] ?? '') === 'ip' ? 'selected' : ''; ?>>IP Address</option>
                                <option value="domain" <?php echo ($_POST['type'] ?? '') === 'domain' ? 'selected' : ''; ?>>Domain</option>
                                <option value="url" <?php echo ($_POST['type'] ?? '') === 'url' ? 'selected' : ''; ?>>URL</option>
                            </select>
                            <div id="type-indicator" class="mt-1"></div>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label for="priority" class="form-label fw-bold">Priority</label>
                            <select class="form-select" id="priority" name="priority">
                                <option value="low" <?php echo ($_POST['priority'] ?? 'medium') === 'low' ? 'selected' : ''; ?>>
                                    🔵 Low - Routine blocking
                                </option>
                                <option value="medium" <?php echo ($_POST['priority'] ?? 'medium') === 'medium' ? 'selected' : ''; ?>>
                                    🟡 Medium - Standard security concern
                                </option>
                                <option value="high" <?php echo ($_POST['priority'] ?? 'medium') === 'high' ? 'selected' : ''; ?>>
                                    🟠 High - Active threat
                                </option>
                                <option value="critical" <?php echo ($_POST['priority'] ?? 'medium') === 'critical' ? 'selected' : ''; ?>>
                                    🔴 Critical - Immediate action required
                                </option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label for="servicenow_ticket" class="form-label fw-bold">ServiceNow Ticket <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="servicenow_ticket" name="servicenow_ticket" 
                                   value="<?php echo htmlspecialchars($_POST['servicenow_ticket'] ?? ''); ?>"
                                   placeholder="e.g., INC1234567, REQ1234567, SIR1234567"
                                   required>
                            <div class="form-text">Required for audit and tracking purposes</div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="justification" class="form-label fw-bold">Justification <span class="text-danger">*</span></label>
                        <textarea class="form-control" id="justification" name="justification" rows="3" 
                                  placeholder="Explain why this entry should be blocked..."
                                  required><?php echo htmlspecialchars($_POST['justification'] ?? ''); ?></textarea>
                        <div class="form-text">Provide a clear business justification for blocking this entry</div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="comment" class="form-label fw-bold">Additional Comments</label>
                        <textarea class="form-control" id="comment" name="comment" rows="2" 
                                  placeholder="Any additional context or technical details..."><?php echo htmlspecialchars($_POST['comment'] ?? ''); ?></textarea>
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
        
        <!-- ServiceNow Ticket Guidelines -->
        <div class="card mt-3">
            <div class="card-header bg-light">
                <h6 class="mb-0">
                    <i class="fas fa-ticket-alt text-warning"></i> ServiceNow Ticket Guidelines
                </h6>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h6><i class="fas fa-exclamation-triangle text-danger"></i> Incident:</h6>
                    <code class="small d-block">INC1234567</code>
                    <small class="text-muted">For security incidents</small>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-shield-alt text-danger"></i> Security Incident:</h6>
                    <code class="small d-block">SIR1234567</code>
                    <small class="text-muted">For security incident response</small>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-clipboard-list text-primary"></i> Request:</h6>
                    <code class="small d-block">REQ1234567</code>
                    <small class="text-muted">For service requests</small>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-wrench text-info"></i> Change:</h6>
                    <code class="small d-block">CHG1234567</code>
                    <small class="text-muted">For change requests</small>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-tasks text-secondary"></i> Other:</h6>
                    <code class="small d-block">RITM1234567</code>
                    <code class="small d-block">TASK1234567</code>
                    <code class="small d-block">SCTASK1234567</code>
                </div>
                
                <div class="alert alert-warning">
                    <small>
                        <i class="fas fa-info-circle"></i>
                        <strong>Note:</strong> ServiceNow ticket is mandatory and will be included in all logs and notifications.
                    </small>
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
                                    <?php if (!empty($request['servicenow_ticket'])): ?>
                                        <br><span class="badge bg-info"><?php echo htmlspecialchars($request['servicenow_ticket']); ?></span>
                                    <?php endif; ?>
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
            indicator.innerHTML = `<small class="text-success"><i class="${icon}"></i> Detected: ${detectedType}</small>`;
        } else {
            indicator.innerHTML = '<small class="text-muted">Could not auto-detect type</small>';
        }
    } else {
        indicator.innerHTML = '';
    }
});

// Validate ServiceNow ticket format (including SIR support)
document.getElementById('servicenow_ticket').addEventListener('input', function() {
    const ticket = this.value.trim().toUpperCase();
    this.value = ticket;
    
    const patterns = [
        /^INC\d{7}$/,
        /^REQ\d{7}$/,
        /^CHG\d{7}$/,
        /^RITM\d{7}$/,
        /^TASK\d{7}$/,
        /^SCTASK\d{7}$/,
        /^SIR\d{7}$/  // Added SIR support
    ];
    
    const isValid = patterns.some(pattern => pattern.test(ticket));
    
    if (ticket && !isValid) {
        this.classList.add('is-invalid');
        // Show helpful feedback
        const feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = 'Format: INC1234567, REQ1234567, CHG1234567, SIR1234567, etc.';
        
        // Remove existing feedback
        const existingFeedback = this.parentNode.querySelector('.invalid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }
        
        this.parentNode.appendChild(feedback);
    } else {
        this.classList.remove('is-invalid');
        // Remove feedback
        const existingFeedback = this.parentNode.querySelector('.invalid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }
    }
});

// Bootstrap form validation
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