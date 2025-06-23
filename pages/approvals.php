<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/validation.php';

$auth = new EDLAuth();
$auth->require_permission('approve');

$page_title = 'Approvals';
$error_message = '';
$success_message = '';

// Handle approval/denial actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        $request_id = sanitize_input($_POST['request_id'] ?? '');
        $admin_comment = sanitize_input($_POST['admin_comment'] ?? '');
        
        if (in_array($action, ['approve', 'deny']) && !empty($request_id)) {
            $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
            $request_found = false;
            
            // Find the request
            foreach ($pending_requests as $key => $request) {
                if ($request['id'] === $request_id && $request['status'] === 'pending') {
                    $request_found = true;
                    
                    if ($action === 'approve') {
                        // Validate the entry before approving
                        $validation = validate_entry_comprehensive($request['entry'], $request['type']);
                        
                        if (!$validation['valid']) {
                            $error_message = 'Cannot approve invalid entry: ' . $validation['error'];
                            break;
                        }
                        
                        // Check if entry already exists in approved list
                        $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
                        $exists = false;
                        foreach ($approved_entries as $existing) {
                            if ($existing['entry'] === $request['entry'] && $existing['status'] === 'active') {
                                $exists = true;
                                break;
                            }
                        }
                        
                        if ($exists) {
                            $error_message = 'Entry already exists in approved list.';
                            break;
                        }
                        
                        // Approve the request
                        $approved_entry = [
                            'id' => uniqid('app_', true),
                            'entry' => $request['entry'],
                            'type' => $request['type'],
                            'comment' => $request['comment'],
                            'justification' => $request['justification'],
                            'priority' => $request['priority'],
                            'submitted_by' => $request['submitted_by'],
                            'submitted_at' => $request['submitted_at'],
                            'approved_by' => $_SESSION['username'],
                            'approved_at' => date('c'),
                            'admin_comment' => $admin_comment,
                            'status' => 'active',
                            'request_id' => $request_id
                        ];
                        
                        // Add to approved entries
                        $approved_entries[] = $approved_entry;
                        write_json_file(DATA_DIR . '/approved_entries.json', $approved_entries);
                        
                        // Update request status
                        $pending_requests[$key]['status'] = 'approved';
                        $pending_requests[$key]['approved_by'] = $_SESSION['username'];
                        $pending_requests[$key]['approved_at'] = date('c');
                        $pending_requests[$key]['admin_comment'] = $admin_comment;
                        
                        // Generate EDL files
                        generate_edl_files();
                        
                        show_flash("Request approved successfully. Entry added to {$request['type']} blocklist.", 'success');
                        
                    } else if ($action === 'deny') {
                        if (empty($admin_comment)) {
                            $error_message = 'Reason is required when denying a request.';
                            break;
                        }
                        
                        // Add to denied entries
                        $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                        $denied_entry = [
                            'id' => uniqid('den_', true),
                            'entry' => $request['entry'],
                            'type' => $request['type'],
                            'comment' => $request['comment'],
                            'justification' => $request['justification'],
                            'priority' => $request['priority'],
                            'submitted_by' => $request['submitted_by'],
                            'submitted_at' => $request['submitted_at'],
                            'denied_by' => $_SESSION['username'],
                            'denied_at' => date('c'),
                            'reason' => $admin_comment,
                            'request_id' => $request_id
                        ];
                        
                        $denied_entries[] = $denied_entry;
                        write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries);
                        
                        // Update request status
                        $pending_requests[$key]['status'] = 'denied';
                        $pending_requests[$key]['denied_by'] = $_SESSION['username'];
                        $pending_requests[$key]['denied_at'] = date('c');
                        $pending_requests[$key]['admin_comment'] = $admin_comment;
                        
                        show_flash("Request denied. Reason provided to submitter.", 'success');
                    }
                    
                    // Save updated pending requests
                    write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests);
                    
                    // Add audit log
                    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                    $audit_logs[] = [
                        'id' => uniqid('audit_', true),
                        'timestamp' => date('c'),
                        'action' => $action,
                        'entry' => $request['entry'],
                        'user' => $_SESSION['username'],
                        'details' => ucfirst($action) . "ed {$request['type']} request from {$request['submitted_by']}",
                        'request_id' => $request_id,
                        'admin_comment' => $admin_comment
                    ];
                    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                    
                    // Redirect to prevent resubmission
                    header('Location: approvals.php');
                    exit;
                }
            }
            
            if (!$request_found) {
                $error_message = 'Request not found or already processed.';
            }
        } else {
            $error_message = 'Invalid action or missing request ID.';
        }
    }
}

// Get all pending requests
$pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$pending_requests = array_filter($pending_requests, function($r) {
    return $r['status'] === 'pending';
});

// Sort by priority and date
usort($pending_requests, function($a, $b) {
    $priority_order = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
    $a_priority = $priority_order[$a['priority']] ?? 2;
    $b_priority = $priority_order[$b['priority']] ?? 2;
    
    if ($a_priority === $b_priority) {
        return strtotime($a['submitted_at']) - strtotime($b['submitted_at']);
    }
    return $b_priority - $a_priority;
});

// Statistics
$stats = [
    'total_pending' => count($pending_requests),
    'critical' => count(array_filter($pending_requests, fn($r) => $r['priority'] === 'critical')),
    'high' => count(array_filter($pending_requests, fn($r) => $r['priority'] === 'high')),
    'medium' => count(array_filter($pending_requests, fn($r) => $r['priority'] === 'medium')),
    'low' => count(array_filter($pending_requests, fn($r) => $r['priority'] === 'low'))
];

$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];
$flash = get_flash();

// Helper function to generate EDL files
function generate_edl_files() {
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $active_entries = array_filter($approved_entries, fn($e) => $e['status'] === 'active');
    
    $ip_list = [];
    $domain_list = [];
    $url_list = [];
    
    foreach ($active_entries as $entry) {
        switch ($entry['type']) {
            case 'ip':
                $ip_list[] = $entry['entry'];
                break;
            case 'domain':
                $domain_list[] = $entry['entry'];
                break;
            case 'url':
                $url_list[] = $entry['entry'];
                break;
        }
    }
    
    // Write EDL files
    if (!is_dir(EDL_FILES_DIR)) {
        mkdir(EDL_FILES_DIR, 0755, true);
    }
    
    file_put_contents(EDL_FILES_DIR . '/ip_blocklist.txt', implode("\n", $ip_list));
    file_put_contents(EDL_FILES_DIR . '/domain_blocklist.txt', implode("\n", $domain_list));
    file_put_contents(EDL_FILES_DIR . '/url_blocklist.txt', implode("\n", $url_list));
    
    return [
        'ip_count' => count($ip_list),
        'domain_count' => count($domain_list),
        'url_count' => count($url_list)
    ];
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
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        .stat-card {
            border-radius: 15px;
            color: white;
            overflow: hidden;
            position: relative;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 100%);
            pointer-events: none;
        }
        .stat-icon {
            opacity: 0.8;
            font-size: 2.5rem;
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
        .priority-critical { border-left: 4px solid #dc3545; }
        .priority-high { border-left: 4px solid #fd7e14; }
        .priority-medium { border-left: 4px solid #ffc107; }
        .priority-low { border-left: 4px solid #28a745; }
        .request-card {
            transition: all 0.3s ease;
            border-radius: 10px;
        }
        .request-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
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
                        <a class="nav-link active" href="approvals.php">
                            <i class="fas fa-check-circle me-1"></i> Approvals
                            <?php if ($stats['total_pending'] > 0): ?>
                                <span class="badge bg-warning text-dark"><?php echo $stats['total_pending']; ?></span>
                            <?php endif; ?>
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
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="audit_log.php">
                                <i class="fas fa-clipboard-list me-2"></i> Audit Log
                            </a></li>
                            <li><a class="dropdown-item" href="user_management.php">
                                <i class="fas fa-users me-2"></i> User Management
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
            <i class="fas fa-<?php echo $flash['type'] === 'success' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <?php if ($error_message): ?>
    <div class="container mt-3">
        <div class="alert alert-danger alert-dismissible fade show">
            <i class="fas fa-exclamation-triangle"></i>
            <?php echo $error_message; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <div class="container mt-4">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="mb-2">
                <i class="fas fa-check-circle me-2"></i>
                Pending Approvals
            </h1>
            <p class="mb-0 opacity-75">Review and approve/deny EDL requests</p>
        </div>
        
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-warning">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1 text-dark"><?php echo $stats['total_pending']; ?></h3>
                                <p class="mb-0 text-dark">Total Pending</p>
                            </div>
                            <div>
                                <i class="fas fa-clock stat-icon text-dark"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-danger">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1"><?php echo $stats['critical']; ?></h3>
                                <p class="mb-0">Critical</p>
                            </div>
                            <div>
                                <i class="fas fa-exclamation-triangle stat-icon"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-warning">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1 text-dark"><?php echo $stats['high']; ?></h3>
                                <p class="mb-0 text-dark">High</p>
                            </div>
                            <div>
                                <i class="fas fa-exclamation-circle stat-icon text-dark"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-info">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1"><?php echo $stats['medium'] + $stats['low']; ?></h3>
                                <p class="mb-0">Medium/Low</p>
                            </div>
                            <div>
                                <i class="fas fa-info-circle stat-icon"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Pending Requests -->
        <?php if (empty($pending_requests)): ?>
        <div class="card">
            <div class="card-body text-center py-5">
                <i class="fas fa-check-double fa-3x text-success mb-3"></i>
                <h4>All Caught Up!</h4>
                <p class="text-muted">No pending requests to review at this time.</p>
                <a href="../index.php" class="btn btn-primary">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </a>
            </div>
        </div>
        <?php else: ?>
        <div class="row">
            <?php foreach ($pending_requests as $request): ?>
            <div class="col-lg-6 mb-4">
                <div class="card request-card priority-<?php echo $request['priority']; ?>">
                    <div class="card-header bg-light d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-<?php 
                                echo $request['priority'] === 'critical' ? 'danger' : 
                                     ($request['priority'] === 'high' ? 'warning text-dark' : 
                                      ($request['priority'] === 'medium' ? 'info' : 'success')); 
                            ?>">
                                <?php echo strtoupper($request['priority']); ?> PRIORITY
                            </span>
                            <span class="badge bg-secondary ms-2">
                                <i class="fas fa-<?php 
                                    echo $request['type'] === 'ip' ? 'network-wired' : 
                                         ($request['type'] === 'domain' ? 'globe' : 'link'); 
                                ?>"></i>
                                <?php echo strtoupper($request['type']); ?>
                            </span>
                        </div>
                        <small class="text-muted">
                            <?php 
                            $time = strtotime($request['submitted_at']);
                            echo $time ? date('M j, H:i', $time) : 'Unknown';
                            ?>
                        </small>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <h6 class="mb-1">Entry to Block:</h6>
                            <code class="fs-6 user-select-all"><?php echo htmlspecialchars($request['entry']); ?></code>
                        </div>
                        
                        <div class="mb-3">
                            <h6 class="mb-1">Business Justification:</h6>
                            <p class="mb-0"><?php echo nl2br(htmlspecialchars($request['justification'])); ?></p>
                        </div>
                        
                        <?php if (!empty($request['comment'])): ?>
                        <div class="mb-3">
                            <h6 class="mb-1">Additional Comments:</h6>
                            <p class="mb-0 text-muted"><?php echo nl2br(htmlspecialchars($request['comment'])); ?></p>
                        </div>
                        <?php endif; ?>
                        
                        <div class="mb-3">
                            <small class="text-muted">
                                <strong>Submitted by:</strong> <?php echo htmlspecialchars($request['submitted_by']); ?><br>
                                <strong>Request ID:</strong> <?php echo htmlspecialchars($request['id']); ?>
                            </small>
                        </div>
                        
                        <!-- Action Buttons -->
                        <div class="d-flex gap-2">
                            <button type="button" class="btn btn-success btn-sm" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#approveModal<?php echo md5($request['id']); ?>">
                                <i class="fas fa-check"></i> Approve
                            </button>
                            <button type="button" class="btn btn-danger btn-sm" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#denyModal<?php echo md5($request['id']); ?>">
                                <i class="fas fa-times"></i> Deny
                            </button>
                            <button type="button" class="btn btn-outline-info btn-sm" 
                                    onclick="copyToClipboard('<?php echo htmlspecialchars($request['entry']); ?>')">
                                <i class="fas fa-copy"></i> Copy
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Approve Modal -->
            <div class="modal fade" id="approveModal<?php echo md5($request['id']); ?>" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-check-circle text-success"></i> Approve Request
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <form method="POST">
                            <div class="modal-body">
                                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                <input type="hidden" name="action" value="approve">
                                <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request['id']); ?>">
                                
                                <div class="alert alert-info">
                                    <strong>Entry:</strong> <code><?php echo htmlspecialchars($request['entry']); ?></code><br>
                                    <strong>Type:</strong> <?php echo strtoupper($request['type']); ?><br>
                                    <strong>Submitted by:</strong> <?php echo htmlspecialchars($request['submitted_by']); ?>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="admin_comment_approve" class="form-label">Approval Comments (optional):</label>
                                    <textarea class="form-control" name="admin_comment" id="admin_comment_approve" 
                                              rows="3" placeholder="Any notes about this approval..."></textarea>
                                </div>
                                
                                <p class="text-success">
                                    <i class="fas fa-info-circle"></i>
                                    This entry will be added to the <?php echo $request['type']; ?> blocklist and EDL files will be updated.
                                </p>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="submit" class="btn btn-success">
                                    <i class="fas fa-check"></i> Approve Request
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Deny Modal -->
            <div class="modal fade" id="denyModal<?php echo md5($request['id']); ?>" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-times-circle text-danger"></i> Deny Request
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <form method="POST">
                            <div class="modal-body">
                                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                <input type="hidden" name="action" value="deny">
                                <input type="hidden" name="request_id" value="<?php echo htmlspecialchars($request['id']); ?>">
                                
                                <div class="alert alert-warning">
                                    <strong>Entry:</strong> <code><?php echo htmlspecialchars($request['entry']); ?></code><br>
                                    <strong>Type:</strong> <?php echo strtoupper($request['type']); ?><br>
                                    <strong>Submitted by:</strong> <?php echo htmlspecialchars($request['submitted_by']); ?>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="admin_comment_deny" class="form-label">
                                        Reason for Denial <span class="text-danger">*</span>
                                    </label>
                                    <textarea class="form-control" name="admin_comment" id="admin_comment_deny" 
                                              rows="4" required
                                              placeholder="Explain why this request is being denied..."></textarea>
                                    <div class="form-text">This reason will be provided to the submitter.</div>
                                </div>
                                
                                <p class="text-danger">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    This request will be denied and moved to the denied entries list.
                                </p>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="submit" class="btn btn-danger">
                                    <i class="fas fa-times"></i> Deny Request
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
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
        // Copy to clipboard function
        function copyToClipboard(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showNotification('Copied to clipboard: ' + text, 'success');
                }).catch(() => {
                    fallbackCopy(text);
                });
            } else {
                fallbackCopy(text);
            }
        }
        
        function fallbackCopy(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            
            try {
                document.execCommand('copy');
                showNotification('Copied to clipboard: ' + text, 'success');
            } catch (err) {
                showNotification('Failed to copy to clipboard', 'danger');
            }
            
            document.body.removeChild(textArea);
        }
        
        // Show notification
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
        
        // Add some interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Animate stats cards on load
            const statCards = document.querySelectorAll('.stat-card');
            statCards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                
                setTimeout(() => {
                    card.style.transition = 'all 0.5s ease';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, index * 100);
            });
            
            // Auto-refresh page every 60 seconds to check for new requests
            setTimeout(() => {
                window.location.reload();
            }, 60000);
        });
    </script>
</body>
</html>