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
$auth->require_permission('approve');

$page_title = 'Approvals';
$error_message = '';
$success_message = '';

// Function to generate EDL files after approval
function generate_edl_files() {
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    
    $ip_entries = [];
    $domain_entries = [];
    $url_entries = [];
    
    foreach ($approved_entries as $entry) {
        if (isset($entry['status']) && $entry['status'] === 'active') {
            switch ($entry['type']) {
                case 'ip':
                    $ip_entries[] = $entry['entry'];
                    break;
                case 'domain':
                    $domain_entries[] = $entry['entry'];
                    break;
                case 'url':
                    $url_entries[] = $entry['entry'];
                    break;
            }
        }
    }
    
    // Write EDL files
    file_put_contents(EDL_FILES_DIR . '/ip_blocklist.txt', implode("\n", $ip_entries));
    file_put_contents(EDL_FILES_DIR . '/domain_blocklist.txt', implode("\n", $domain_entries));
    file_put_contents(EDL_FILES_DIR . '/url_blocklist.txt', implode("\n", $url_entries));
}

// Enhanced Teams notification function for bulk operations
function send_bulk_teams_notification($action, $requests, $admin_comment = '', $processed_by = '') {
    if (!function_exists('send_teams_notification')) {
        return false;
    }
    
    $count = count($requests);
    if ($count === 0) return false;
    
    // Group requests by type
    $by_type = [];
    foreach ($requests as $request) {
        $type = $request['type'];
        if (!isset($by_type[$type])) {
            $by_type[$type] = 0;
        }
        $by_type[$type]++;
    }
    
    $type_summary = [];
    foreach ($by_type as $type => $count) {
        $type_summary[] = "{$count} {$type}" . ($count > 1 ? 's' : '');
    }
    
    $bulk_data = [
        'count' => $count,
        'type_summary' => implode(', ', $type_summary),
        'processed_by' => $processed_by,
        'comment' => $admin_comment,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    // Use the first request as template but add bulk context
    $template_request = $requests[0];
    $template_request['bulk_operation'] = true;
    $template_request['bulk_count'] = $count;
    $template_request['bulk_summary'] = implode(', ', $type_summary);
    
    return send_teams_notification($action === 'approve' ? 'bulk_approved' : 'bulk_denied', $template_request, $bulk_data);
}

// Handle approval/denial actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        $admin_comment = sanitize_input($_POST['admin_comment'] ?? '');
        
        // Handle bulk operations
        if (in_array($action, ['bulk_approve', 'bulk_deny'])) {
            $selected_requests = $_POST['selected_requests'] ?? [];
            
            if (empty($selected_requests)) {
                $error_message = 'No requests selected for ' . ($action === 'bulk_approve' ? 'approval' : 'denial') . '.';
            } elseif ($action === 'bulk_deny' && empty($admin_comment)) {
                $error_message = 'Reason is required when denying requests.';
            } else {
                $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
                $requests_to_process = [];
                $processed_count = 0;
                
                // Find all selected requests
                foreach ($selected_requests as $request_id) {
                    foreach ($pending_requests as $key => $request) {
                        if ($request['id'] === $request_id && (!isset($request['status']) || $request['status'] === 'pending')) {
                            $requests_to_process[] = [
                                'request' => $request,
                                'key' => $key
                            ];
                            break;
                        }
                    }
                }
                
                if (empty($requests_to_process)) {
                    $error_message = 'No valid pending requests found to process.';
                } else {
                    if ($action === 'bulk_approve') {
                        // Bulk approve
                        $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
                        $approved_requests = [];
                        
                        foreach ($requests_to_process as $item) {
                            $request = $item['request'];
                            
                            // Validate entry before approving
                            $validation = validate_entry_comprehensive($request['entry'], $request['type']);
                            if (!$validation['valid']) {
                                continue; // Skip invalid entries
                            }
                            
                            // Check if already exists
                            $exists = false;
                            foreach ($approved_entries as $existing) {
                                if ($existing['entry'] === $request['entry'] && $existing['status'] === 'active') {
                                    $exists = true;
                                    break;
                                }
                            }
                            
                            if (!$exists) {
                                $approved_entry = [
                                    'id' => uniqid('app_', true),
                                    'entry' => $request['entry'],
                                    'type' => $request['type'],
                                    'comment' => $request['comment'] ?? '',
                                    'justification' => $request['justification'],
                                    'priority' => $request['priority'],
                                    'submitted_by' => $request['submitted_by'],
                                    'submitted_at' => $request['submitted_at'],
                                    'approved_by' => $_SESSION['username'],
                                    'approved_at' => date('c'),
                                    'status' => 'active',
                                    'admin_comment' => $admin_comment,
                                    'request_id' => $request['id'],
                                    'source' => 'request'
                                ];
                                
                                if (isset($request['servicenow_ticket'])) {
                                    $approved_entry['servicenow_ticket'] = $request['servicenow_ticket'];
                                }
                                
                                $approved_entries[] = $approved_entry;
                                $approved_requests[] = $request;
                                $processed_count++;
                            }
                        }
                        
                        if ($processed_count > 0) {
                            write_json_file(DATA_DIR . '/approved_entries.json', $approved_entries);
                            
                            // Remove processed requests from pending
                            $keys_to_remove = [];
                            foreach ($requests_to_process as $item) {
                                $keys_to_remove[] = $item['key'];
                            }
                            
                            // Sort keys in descending order to avoid index issues
                            rsort($keys_to_remove);
                            foreach ($keys_to_remove as $key) {
                                unset($pending_requests[$key]);
                            }
                            $pending_requests = array_values($pending_requests);
                            write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests);
                            
                            // Generate EDL files
                            generate_edl_files();
                            
                            // Send bulk Teams notification
                            if (function_exists('send_teams_notification')) {
                                send_bulk_teams_notification('approve', $approved_requests, $admin_comment, $_SESSION['username']);
                            }
                            
                            // Add bulk audit log
                            $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                            $audit_logs[] = [
                                'id' => uniqid('audit_', true),
                                'timestamp' => date('c'),
                                'action' => 'bulk_approve',
                                'user' => $_SESSION['username'],
                                'details' => "Bulk approved {$processed_count} requests",
                                'admin_comment' => $admin_comment,
                                'processed_count' => $processed_count
                            ];
                            write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                            
                            show_flash("Successfully approved {$processed_count} requests. Entries added to blocklists.", 'success');
                        } else {
                            $error_message = 'No valid requests were approved (may be duplicates or invalid entries).';
                        }
                        
                    } else if ($action === 'bulk_deny') {
                        // Bulk deny
                        $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                        $denied_requests = [];
                        
                        foreach ($requests_to_process as $item) {
                            $request = $item['request'];
                            
                            $denied_entry = [
                                'id' => uniqid('den_', true),
                                'entry' => $request['entry'],
                                'type' => $request['type'],
                                'comment' => $request['comment'] ?? '',
                                'justification' => $request['justification'],
                                'priority' => $request['priority'],
                                'submitted_by' => $request['submitted_by'],
                                'submitted_at' => $request['submitted_at'],
                                'denied_by' => $_SESSION['username'],
                                'denied_at' => date('c'),
                                'reason' => $admin_comment,
                                'request_id' => $request['id']
                            ];
                            
                            if (isset($request['servicenow_ticket'])) {
                                $denied_entry['servicenow_ticket'] = $request['servicenow_ticket'];
                            }
                            
                            $denied_entries[] = $denied_entry;
                            $denied_requests[] = $request;
                            $processed_count++;
                        }
                        
                        write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries);
                        
                        // Remove processed requests from pending
                        $keys_to_remove = [];
                        foreach ($requests_to_process as $item) {
                            $keys_to_remove[] = $item['key'];
                        }
                        
                        rsort($keys_to_remove);
                        foreach ($keys_to_remove as $key) {
                            unset($pending_requests[$key]);
                        }
                        $pending_requests = array_values($pending_requests);
                        write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests);
                        
                        // Send bulk Teams notification
                        if (function_exists('send_teams_notification')) {
                            send_bulk_teams_notification('deny', $denied_requests, $admin_comment, $_SESSION['username']);
                        }
                        
                        // Add bulk audit log
                        $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                        $audit_logs[] = [
                            'id' => uniqid('audit_', true),
                            'timestamp' => date('c'),
                            'action' => 'bulk_deny',
                            'user' => $_SESSION['username'],
                            'details' => "Bulk denied {$processed_count} requests",
                            'admin_comment' => $admin_comment,
                            'processed_count' => $processed_count
                        ];
                        write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                        
                        show_flash("Successfully denied {$processed_count} requests.", 'success');
                    }
                }
            }
        }
        // Handle individual operations (existing logic)
        elseif (in_array($action, ['approve', 'deny'])) {
            $request_id = sanitize_input($_POST['request_id'] ?? '');
            
            if (empty($request_id)) {
                $error_message = 'Invalid request ID.';
            } else {
                $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
                $request_found = false;
                $request_to_process = null;
                $request_key = null;
                
                // Find the request
                foreach ($pending_requests as $key => $request) {
                    if ($request['id'] === $request_id && (!isset($request['status']) || $request['status'] === 'pending')) {
                        $request_found = true;
                        $request_to_process = $request;
                        $request_key = $key;
                        break;
                    }
                }
                
                if ($request_found && $request_to_process) {
                    if ($action === 'approve') {
                        // Validate the entry before approving
                        $validation = validate_entry_comprehensive($request_to_process['entry'], $request_to_process['type']);
                        
                        if (!$validation['valid']) {
                            $error_message = 'Cannot approve invalid entry: ' . $validation['error'];
                        } else {
                            // Check if entry already exists in approved list
                            $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
                            $exists = false;
                            foreach ($approved_entries as $existing) {
                                if ($existing['entry'] === $request_to_process['entry'] && $existing['status'] === 'active') {
                                    $exists = true;
                                    break;
                                }
                            }
                            
                            if ($exists) {
                                $error_message = 'Entry already exists in approved list.';
                            } else {
                                // Add to approved entries
                                $approved_entry = [
                                    'id' => uniqid('app_', true),
                                    'entry' => $request_to_process['entry'],
                                    'type' => $request_to_process['type'],
                                    'comment' => $request_to_process['comment'] ?? '',
                                    'justification' => $request_to_process['justification'],
                                    'priority' => $request_to_process['priority'],
                                    'submitted_by' => $request_to_process['submitted_by'],
                                    'submitted_at' => $request_to_process['submitted_at'],
                                    'approved_by' => $_SESSION['username'],
                                    'approved_at' => date('c'),
                                    'status' => 'active',
                                    'admin_comment' => $admin_comment,
                                    'request_id' => $request_id,
                                    'source' => 'request'
                                ];
                                
                                // Add ServiceNow ticket if present
                                if (isset($request_to_process['servicenow_ticket'])) {
                                    $approved_entry['servicenow_ticket'] = $request_to_process['servicenow_ticket'];
                                }
                                
                                $approved_entries[] = $approved_entry;
                                write_json_file(DATA_DIR . '/approved_entries.json', $approved_entries);
                                
                                // Remove from pending requests
                                unset($pending_requests[$request_key]);
                                $pending_requests = array_values($pending_requests);
                                write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests);
                                
                                // Generate EDL files
                                generate_edl_files();
                                
                                // Send Teams notification for individual approval
                                if (function_exists('send_teams_notification')) {
                                    send_teams_notification('approved', $request_to_process, [
                                        'processed_by' => $_SESSION['username'],
                                        'comment' => $admin_comment
                                    ]);
                                }
                                
                                // Add audit log
                                $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                                $audit_logs[] = [
                                    'id' => uniqid('audit_', true),
                                    'timestamp' => date('c'),
                                    'action' => 'approve',
                                    'entry' => $request_to_process['entry'],
                                    'user' => $_SESSION['username'],
                                    'details' => "Approved {$request_to_process['type']} request from {$request_to_process['submitted_by']}",
                                    'request_id' => $request_id,
                                    'admin_comment' => $admin_comment
                                ];
                                write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                                
                                show_flash("Request approved successfully. Entry added to {$request_to_process['type']} blocklist.", 'success');
                            }
                        }
                        
                    } else if ($action === 'deny') {
                        if (empty($admin_comment)) {
                            $error_message = 'Reason is required when denying a request.';
                        } else {
                            // Add to denied entries
                            $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                            $denied_entry = [
                                'id' => uniqid('den_', true),
                                'entry' => $request_to_process['entry'],
                                'type' => $request_to_process['type'],
                                'comment' => $request_to_process['comment'] ?? '',
                                'justification' => $request_to_process['justification'],
                                'priority' => $request_to_process['priority'],
                                'submitted_by' => $request_to_process['submitted_by'],
                                'submitted_at' => $request_to_process['submitted_at'],
                                'denied_by' => $_SESSION['username'],
                                'denied_at' => date('c'),
                                'reason' => $admin_comment,
                                'request_id' => $request_id
                            ];
                            
                            // Add ServiceNow ticket if present
                            if (isset($request_to_process['servicenow_ticket'])) {
                                $denied_entry['servicenow_ticket'] = $request_to_process['servicenow_ticket'];
                            }
                            
                            $denied_entries[] = $denied_entry;
                            write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries);
                            
                            // Remove from pending requests
                            unset($pending_requests[$request_key]);
                            $pending_requests = array_values($pending_requests);
                            write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests);
                            
                            // Send Teams notification for individual denial
                            if (function_exists('send_teams_notification')) {
                                send_teams_notification('denied', $request_to_process, [
                                    'processed_by' => $_SESSION['username'],
                                    'comment' => $admin_comment
                                ]);
                            }
                            
                            // Add audit log
                            $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                            $audit_logs[] = [
                                'id' => uniqid('audit_', true),
                                'timestamp' => date('c'),
                                'action' => 'deny',
                                'entry' => $request_to_process['entry'],
                                'user' => $_SESSION['username'],
                                'details' => "Denied {$request_to_process['type']} request from {$request_to_process['submitted_by']}",
                                'request_id' => $request_id,
                                'admin_comment' => $admin_comment
                            ];
                            write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                            
                            show_flash('Request denied successfully.', 'success');
                        }
                    }
                } else {
                    $error_message = 'Request not found or already processed.';
                }
            }
        }
    }
}

// Get pending requests
$pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$pending_requests = array_filter($pending_requests, function($r) {
    return !isset($r['status']) || $r['status'] === 'pending';
});

// Sort by priority and date
usort($pending_requests, function($a, $b) {
    $priority_order = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
    $a_priority = $priority_order[$a['priority'] ?? 'medium'] ?? 2;
    $b_priority = $priority_order[$b['priority'] ?? 'medium'] ?? 2;
    
    if ($a_priority !== $b_priority) {
        return $b_priority - $a_priority; // Higher priority first
    }
    
    return strtotime($a['submitted_at'] ?? '0') - strtotime($b['submitted_at'] ?? '0'); // Older first
});

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
        <i class="fas fa-tasks me-2"></i>
        Pending Approvals
    </h1>
    <p class="mb-0 opacity-75">Review and approve or deny EDL requests from users</p>
</div>

<?php if (empty($pending_requests)): ?>
<div class="card">
    <div class="card-body text-center py-5">
        <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
        <h4>No Pending Requests</h4>
        <p class="text-muted">All requests have been reviewed. Great job!</p>
        <a href="../index.php" class="btn btn-primary">
            <i class="fas fa-arrow-left"></i> Back to Dashboard
        </a>
    </div>
</div>

<?php else: ?>

<!-- Bulk Actions Section -->
<div class="card mb-4">
    <div class="card-header bg-warning text-dark">
        <h5 class="mb-0">
            <i class="fas fa-layer-group me-1"></i> Bulk Actions
            <span class="badge bg-secondary ms-2"><?php echo count($pending_requests); ?> Pending</span>
        </h5>
    </div>
    <div class="card-body">
        <form method="post" id="bulk-form" class="needs-validation" novalidate>
            <?php echo csrf_token_field(); ?>
            
            <div class="row mb-3">
                <div class="col-md-8">
                    <label for="bulk_admin_comment" class="form-label fw-bold">
                        Reason/Comment <span class="text-danger" id="comment-required" style="display: none;">*</span>
                    </label>
                    <textarea class="form-control" id="bulk_admin_comment" name="admin_comment" rows="2" 
                              placeholder="Enter reason for approval/denial (required for denials)..."></textarea>
                </div>
                <div class="col-md-4">
                    <label class="form-label fw-bold">Actions</label>
                    <div class="d-grid gap-2">
                        <button type="submit" name="action" value="bulk_approve" class="btn btn-success" 
                                onclick="return confirmBulkAction('approve')" disabled id="bulk-approve-btn">
                            <i class="fas fa-check"></i> Bulk Approve
                        </button>
                        <button type="submit" name="action" value="bulk_deny" class="btn btn-danger"
                                onclick="return confirmBulkAction('deny')" disabled id="bulk-deny-btn">
                            <i class="fas fa-times"></i> Bulk Deny
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="select-all">
                    <label class="form-check-label fw-bold" for="select-all">
                        Select All Requests
                    </label>
                </div>
            </div>
            
            <!-- Requests List -->
            <div class="row">
                <?php foreach ($pending_requests as $request): ?>
                <div class="col-lg-6 mb-3">
                    <div class="card request-card priority-<?php echo $request['priority'] ?? 'medium'; ?>">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div class="form-check">
                                <input class="form-check-input request-checkbox" type="checkbox" 
                                       name="selected_requests[]" value="<?php echo $request['id']; ?>" 
                                       id="req_<?php echo $request['id']; ?>">
                                <label class="form-check-label fw-bold" for="req_<?php echo $request['id']; ?>">
                                    <?php echo htmlspecialchars($request['entry']); ?>
                                </label>
                            </div>
                            <div>
                                <?php echo get_priority_badge($request['priority'] ?? 'medium'); ?>
                                <span class="badge bg-info ms-1"><?php echo ucfirst($request['type']); ?></span>
                            </div>
                        </div>
                        <div class="card-body">
                            <p class="card-text">
                                <strong>Justification:</strong><br>
                                <?php echo nl2br(htmlspecialchars($request['justification'])); ?>
                            </p>
                            
                            <?php if (!empty($request['comment'])): ?>
                            <p class="card-text">
                                <strong>Additional Comments:</strong><br>
                                <?php echo nl2br(htmlspecialchars($request['comment'])); ?>
                            </p>
                            <?php endif; ?>
                            
                            <div class="row text-muted small">
                                <div class="col-6">
                                    <strong>Submitted by:</strong><br>
                                    <?php echo htmlspecialchars($request['submitted_by']); ?>
                                </div>
                                <div class="col-6">
                                    <strong>Date:</strong><br>
                                    <?php echo format_datetime($request['submitted_at']); ?>
                                </div>
                            </div>
                            
                            <?php if (!empty($request['servicenow_ticket'])): ?>
                            <div class="mt-2">
                                <span class="badge bg-primary">
                                    <i class="fas fa-ticket-alt"></i> <?php echo htmlspecialchars($request['servicenow_ticket']); ?>
                                </span>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </form>
    </div>
</div>

<!-- Individual Actions Section -->
<div class="card">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">
            <i class="fas fa-user me-1"></i> Individual Actions
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <?php foreach ($pending_requests as $request): ?>
            <div class="col-lg-6 mb-4">
                <div class="card request-card priority-<?php echo $request['priority'] ?? 'medium'; ?>">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0"><?php echo htmlspecialchars($request['entry']); ?></h6>
                        <div>
                            <?php echo get_priority_badge($request['priority'] ?? 'medium'); ?>
                            <span class="badge bg-info ms-1"><?php echo ucfirst($request['type']); ?></span>
                        </div>
                    </div>
                    <div class="card-body">
                        <p class="card-text">
                            <strong>Justification:</strong><br>
                            <?php echo nl2br(htmlspecialchars($request['justification'])); ?>
                        </p>
                        
                        <?php if (!empty($request['comment'])): ?>
                        <p class="card-text">
                            <strong>Additional Comments:</strong><br>
                            <?php echo nl2br(htmlspecialchars($request['comment'])); ?>
                        </p>
                        <?php endif; ?>
                        
                        <div class="row text-muted small mb-3">
                            <div class="col-6">
                                <strong>Submitted by:</strong><br>
                                <?php echo htmlspecialchars($request['submitted_by']); ?>
                            </div>
                            <div class="col-6">
                                <strong>Date:</strong><br>
                                <?php echo format_datetime($request['submitted_at']); ?>
                            </div>
                        </div>
                        
                        <?php if (!empty($request['servicenow_ticket'])): ?>
                        <div class="mb-3">
                            <span class="badge bg-primary">
                                <i class="fas fa-ticket-alt"></i> <?php echo htmlspecialchars($request['servicenow_ticket']); ?>
                            </span>
                        </div>
                        <?php endif; ?>
                        
                        <!-- Individual Action Form -->
                        <form method="post" class="individual-action-form">
                            <?php echo csrf_token_field(); ?>
                            <input type="hidden" name="request_id" value="<?php echo $request['id']; ?>">
                            
                            <div class="mb-3">
                                <label class="form-label">Admin Comment/Reason:</label>
                                <textarea class="form-control admin-comment" name="admin_comment" rows="2" 
                                          placeholder="Optional for approval, required for denial..."></textarea>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <button type="submit" name="action" value="approve" class="btn btn-success" 
                                        onclick="return confirm('Approve this request?')">
                                    <i class="fas fa-check"></i> Approve
                                </button>
                                <button type="submit" name="action" value="deny" class="btn btn-danger deny-btn"
                                        onclick="return validateDenial(this.form)">
                                    <i class="fas fa-times"></i> Deny
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<?php endif; ?>

</div>

<script>
// Bulk operations JavaScript
document.addEventListener('DOMContentLoaded', function() {
    const selectAllCheckbox = document.getElementById('select-all');
    const requestCheckboxes = document.querySelectorAll('.request-checkbox');
    const bulkApproveBtn = document.getElementById('bulk-approve-btn');
    const bulkDenyBtn = document.getElementById('bulk-deny-btn');
    const commentRequired = document.getElementById('comment-required');
    
    // Select all functionality
    selectAllCheckbox?.addEventListener('change', function() {
        requestCheckboxes.forEach(checkbox => {
            checkbox.checked = this.checked;
        });
        updateBulkButtons();
    });
    
    // Individual checkbox change
    requestCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            updateBulkButtons();
            
            // Update select all checkbox
            const checkedCount = document.querySelectorAll('.request-checkbox:checked').length;
            selectAllCheckbox.checked = checkedCount === requestCheckboxes.length;
            selectAllCheckbox.indeterminate = checkedCount > 0 && checkedCount < requestCheckboxes.length;
        });
    });
    
    function updateBulkButtons() {
        const checkedCount = document.querySelectorAll('.request-checkbox:checked').length;
        bulkApproveBtn.disabled = checkedCount === 0;
        bulkDenyBtn.disabled = checkedCount === 0;
        
        // Show/hide required indicator for bulk comment
        if (checkedCount > 0) {
            commentRequired.style.display = 'inline';
        } else {
            commentRequired.style.display = 'none';
        }
    }
});

function confirmBulkAction(action) {
    const checkedCount = document.querySelectorAll('.request-checkbox:checked').length;
    const adminComment = document.getElementById('bulk_admin_comment').value.trim();
    
    if (checkedCount === 0) {
        alert('Please select at least one request.');
        return false;
    }
    
    if (action === 'deny' && adminComment === '') {
        alert('Reason is required when denying requests.');
        document.getElementById('bulk_admin_comment').focus();
        return false;
    }
    
    const actionText = action === 'approve' ? 'approve' : 'deny';
    return confirm(`Are you sure you want to ${actionText} ${checkedCount} request(s)?`);
}

// Individual denial validation
function validateDenial(form) {
    const adminComment = form.querySelector('.admin-comment').value.trim();
    if (adminComment === '') {
        alert('Reason is required when denying a request.');
        form.querySelector('.admin-comment').focus();
        return false;
    }
    return confirm('Are you sure you want to deny this request?');
}

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
