<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_auth(); // Allow all authenticated users

$page_title = 'Denied Entries';
$error_message = '';
$success_message = '';

$is_admin = has_permission('manage');

// Handle actions (only for admins)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $is_admin) {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'remove_denial') {
            $entry_id = sanitize_input($_POST['entry_id'] ?? '');
            if (!empty($entry_id)) {
                $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                $removed = false;
                
                foreach ($denied_entries as $key => $entry) {
                    if ($entry['id'] === $entry_id) {
                        // Add audit log
                        $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                        $audit_logs[] = [
                            'id' => uniqid('audit_', true),
                            'timestamp' => date('c'),
                            'action' => 'remove_denial',
                            'entry' => $entry['entry'],
                            'user' => $_SESSION['username'],
                            'details' => "Removed {$entry['type']} from denied list",
                            'admin_comment' => "Previously denied: " . ($entry['reason'] ?? 'No reason')
                        ];
                        write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                        
                        unset($denied_entries[$key]);
                        $removed = true;
                        break;
                    }
                }
                
                if ($removed) {
                    write_json_file(DATA_DIR . '/denied_entries.json', array_values($denied_entries));
                    show_flash('Entry removed from denied list successfully.', 'success');
                } else {
                    $error_message = 'Entry not found in denied list.';
                }
            }
        } elseif ($action === 'add_manual_denial') {
            $entry = sanitize_input($_POST['entry'] ?? '');
            $type = sanitize_input($_POST['type'] ?? '');
            $reason = sanitize_input($_POST['reason'] ?? '');
            
            $errors = [];
            if (empty($entry)) $errors[] = 'Entry is required';
            if (empty($type)) $errors[] = 'Type is required';
            if (empty($reason)) $errors[] = 'Denial reason is required';
            
            // Auto-detect type if not specified
            if (!empty($entry) && $type === 'auto') {
                if (preg_match('/^https?:\/\//', $entry)) {
                    $type = 'url';
                } elseif (filter_var($entry, FILTER_VALIDATE_IP) || preg_match('/^[\d\.\/]+$/', $entry)) {
                    $type = 'ip';
                } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $entry)) {
                    $type = 'domain';
                } else {
                    $errors[] = 'Could not determine entry type. Please select manually.';
                }
            }
            
            // Check if already exists in denied list
            if (!empty($entry) && !empty($type)) {
                $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                foreach ($denied_entries as $denied) {
                    if ($denied['entry'] === $entry && $denied['type'] === $type) {
                        $errors[] = 'Entry already exists in denied list.';
                        break;
                    }
                }
            }
            
            if (empty($errors)) {
                $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                
                $new_denial = [
                    'id' => uniqid('den_', true),
                    'entry' => $entry,
                    'type' => $type,
                    'reason' => $reason,
                    'denied_by' => $_SESSION['username'],
                    'denied_at' => date('c'),
                    'manual_entry' => true
                ];
                
                $denied_entries[] = $new_denial;
                write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries);
                
                // Add audit log
                $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                $audit_logs[] = [
                    'id' => uniqid('audit_', true),
                    'timestamp' => date('c'),
                    'action' => 'manual_denial',
                    'entry' => $entry,
                    'user' => $_SESSION['username'],
                    'details' => "Manually added {$type} to denied list",
                    'admin_comment' => $reason
                ];
                write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                
                show_flash('Entry added to denied list successfully.', 'success');
                header('Location: denied_entries.php');
                exit;
            } else {
                $error_message = implode('<br>', $errors);
            }
        }
    }
}

// Get all denied entries
$denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');

// Sort by date (newest first)
usort($denied_entries, function($a, $b) {
    return strtotime($b['denied_at']) - strtotime($a['denied_at']);
});

// Get statistics
$stats = [
    'total_denied' => count($denied_entries),
    'ip_denied' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'ip')),
    'domain_denied' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'domain')),
    'url_denied' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'url')),
    'manual_denials' => count(array_filter($denied_entries, fn($e) => isset($e['manual_entry']) && $e['manual_entry']))
];

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
        .denied-entry {
            border-left: 4px solid #dc3545;
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
                        <a class="nav-link active" href="denied_entries.php">
                            <i class="fas fa-ban me-1"></i> Denied Entries
                        </a>
                    </li>
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
                            <li><a class="dropdown-item active" href="denied_entries.php">
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
                <i class="fas fa-ban me-2"></i>
                Denied Entries<?php echo $is_admin ? ' Management' : ''; ?>
            </h1>
            <p class="mb-0 opacity-75">
                <?php if ($is_admin): ?>
                    Manage entries that have been denied and will be automatically rejected
                <?php else: ?>
                    View entries that have been denied and cannot be submitted
                <?php endif; ?>
            </p>
        </div>
        
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-danger">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1"><?php echo $stats['total_denied']; ?></h3>
                                <p class="mb-0">Total Denied</p>
                            </div>
                            <div>
                                <i class="fas fa-ban stat-icon"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-primary">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1"><?php echo $stats['ip_denied']; ?></h3>
                                <p class="mb-0">IP Addresses</p>
                            </div>
                            <div>
                                <i class="fas fa-network-wired stat-icon"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6 mb-3">
                <div class="card stat-card bg-success">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h3 class="fw-bold mb-1"><?php echo $stats['domain_denied']; ?></h3>
                                <p class="mb-0">Domains</p>
                            </div>
                            <div>
                                <i class="fas fa-globe stat-icon"></i>
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
                                <h3 class="fw-bold mb-1"><?php echo $stats['url_denied']; ?></h3>
                                <p class="mb-0">URLs</p>
                            </div>
                            <div>
                                <i class="fas fa-link stat-icon"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add Manual Denial (Admin Only) -->
        <?php if ($is_admin): ?>
        <div class="card mb-4">
            <div class="card-header bg-light">
                <h5 class="mb-0">
                    <i class="fas fa-plus-circle me-2"></i> Add Manual Denial
                </h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="add_manual_denial">
                    
                    <div class="row g-3">
                        <div class="col-md-4">
                            <label for="entry" class="form-label">Entry <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="entry" name="entry" 
                                   placeholder="IP, domain, or URL" required>
                        </div>
                        <div class="col-md-2">
                            <label for="type" class="form-label">Type <span class="text-danger">*</span></label>
                            <select class="form-select" id="type" name="type" required>
                                <option value="auto">Auto-detect</option>
                                <option value="ip">IP Address</option>
                                <option value="domain">Domain</option>
                                <option value="url">URL</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label for="reason" class="form-label">Denial Reason <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="reason" name="reason" 
                                   placeholder="Why this entry should always be denied" required>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <button type="submit" class="btn btn-danger w-100">
                                <i class="fas fa-ban"></i> Add Denial
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        <?php else: ?>
        <!-- Info for Regular Users -->
        <div class="alert alert-info">
            <i class="fas fa-info-circle"></i>
            <strong>About Denied Entries:</strong> These entries have been previously denied by administrators and cannot be submitted for approval. 
            If you believe an entry should be reconsidered, please contact an administrator.
        </div>
        <?php endif; ?>
        
        <!-- Denied Entries List -->
        <div class="card">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="fas fa-list me-2"></i> Denied Entries
                </h5>
                <small class="text-muted">
                    <?php echo number_format($stats['total_denied']); ?> entries will be automatically rejected
                </small>
            </div>
            <div class="card-body">
                <?php if (empty($denied_entries)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-ban fa-3x text-muted mb-3"></i>
                        <h4>No Denied Entries</h4>
                        <p class="text-muted">No entries have been denied yet. Denied entries will appear here.</p>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Entry</th>
                                    <th>Type</th>
                                    <th>Denial Reason</th>
                                    <th>Denied By</th>
                                    <th>Date Denied</th>
                                    <th>Source</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($denied_entries as $entry): ?>
                                    <tr class="denied-entry">
                                        <td>
                                            <code class="user-select-all"><?php echo htmlspecialchars($entry['entry']); ?></code>
                                        </td>
                                        <td>
                                            <?php
                                            $icons = [
                                                'ip' => 'fas fa-network-wired',
                                                'domain' => 'fas fa-globe',
                                                'url' => 'fas fa-link'
                                            ];
                                            $icon = $icons[$entry['type']] ?? 'fas fa-question-circle';
                                            ?>
                                            <span class="badge bg-secondary">
                                                <i class="<?php echo $icon; ?>"></i>
                                                <?php echo strtoupper($entry['type']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="text-truncate d-inline-block" style="max-width: 300px;" 
                                                  title="<?php echo htmlspecialchars($entry['reason']); ?>">
                                                <?php echo htmlspecialchars($entry['reason']); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($entry['denied_by']); ?></td>
                                        <td>
                                            <small>
                                                <?php 
                                                $time = strtotime($entry['denied_at']);
                                                echo $time ? date('Y-m-d H:i', $time) : 'Unknown';
                                                ?>
                                            </small>
                                        </td>
                                        <td>
                                            <?php if (isset($entry['manual_entry']) && $entry['manual_entry']): ?>
                                                <span class="badge bg-warning text-dark">Manual</span>
                                            <?php else: ?>
                                                <span class="badge bg-info">Request</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($is_admin): ?>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-danger" 
                                                        data-bs-toggle="modal" 
                                                        data-bs-target="#removeModal<?php echo md5($entry['id']); ?>"
                                                        title="Remove from denied list">
                                                    <i class="fas fa-times"></i>
                                                </button>
                                                <button type="button" class="btn btn-outline-info" 
                                                        onclick="copyToClipboard('<?php echo htmlspecialchars($entry['entry']); ?>')"
                                                        title="Copy to clipboard">
                                                    <i class="fas fa-copy"></i>
                                                </button>
                                            </div>
                                            <?php else: ?>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-info" 
                                                        onclick="copyToClipboard('<?php echo htmlspecialchars($entry['entry']); ?>')"
                                                        title="Copy to clipboard">
                                                    <i class="fas fa-copy"></i>
                                                </button>
                                                <span class="badge bg-secondary">View Only</span>
                                            </div>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Remove Modals (Admin Only) -->
    <?php if ($is_admin): ?>
        <?php foreach ($denied_entries as $entry): ?>
        <div class="modal fade" id="removeModal<?php echo md5($entry['id']); ?>" tabindex="-1">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-times-circle text-danger"></i> Remove from Denied List
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form method="POST">
                        <div class="modal-body">
                            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                            <input type="hidden" name="action" value="remove_denial">
                            <input type="hidden" name="entry_id" value="<?php echo htmlspecialchars($entry['id']); ?>">
                            
                            <div class="alert alert-warning">
                                <h6 class="alert-heading">
                                    <i class="fas fa-exclamation-triangle"></i> Confirm Removal
                                </h6>
                                <hr>
                                <div class="row">
                                    <div class="col-sm-3"><strong>Entry:</strong></div>
                                    <div class="col-sm-9"><code><?php echo htmlspecialchars($entry['entry']); ?></code></div>
                                </div>
                                <div class="row">
                                    <div class="col-sm-3"><strong>Type:</strong></div>
                                    <div class="col-sm-9"><?php echo strtoupper($entry['type']); ?></div>
                                </div>
                                <div class="row">
                                    <div class="col-sm-3"><strong>Reason:</strong></div>
                                    <div class="col-sm-9"><?php echo htmlspecialchars($entry['reason']); ?></div>
                                </div>
                            </div>
                            
                            <div class="bg-light p-3 rounded">
                                <p class="mb-0 text-warning">
                                    <i class="fas fa-info-circle"></i>
                                    <strong>Warning:</strong> Removing this entry from the denied list will allow users to submit it again for approval.
                                </p>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                                <i class="fas fa-times"></i> Cancel
                            </button>
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-trash"></i> Remove from Denied List
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>
    
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
        
        // Auto-detect entry type (Admin only)
        <?php if ($is_admin): ?>
        document.getElementById('entry').addEventListener('input', function() {
            const entry = this.value.trim();
            const typeSelect = document.getElementById('type');
            
            if (entry && typeSelect.value === 'auto') {
                if (/^https?:\/\//.test(entry)) {
                    typeSelect.value = 'url';
                } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(entry) || /^[\d\.\/]+$/.test(entry)) {
                    typeSelect.value = 'ip';
                } else if (/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/.test(entry)) {
                    typeSelect.value = 'domain';
                }
            }
        });
        <?php endif; ?>
        
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
        });
    </script>
</body>
</html>