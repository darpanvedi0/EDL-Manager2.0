<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'Audit Log';

// Get filter parameters
$filter_action = $_GET['action'] ?? 'all';
$filter_user = $_GET['user'] ?? 'all';
$filter_date = $_GET['date'] ?? '';
$search_term = $_GET['search'] ?? '';

// Load audit logs
$audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');

// Sort by timestamp (newest first)
usort($audit_logs, function($a, $b) {
    return strtotime($b['timestamp']) - strtotime($a['timestamp']);
});

// Apply filters
$filtered_logs = $audit_logs;

// Filter by action
if ($filter_action !== 'all') {
    $filtered_logs = array_filter($filtered_logs, function($log) use ($filter_action) {
        return isset($log['action']) && $log['action'] === $filter_action;
    });
}

// Filter by user
if ($filter_user !== 'all') {
    $filtered_logs = array_filter($filtered_logs, function($log) use ($filter_user) {
        return isset($log['user']) && $log['user'] === $filter_user;
    });
}

// Filter by date
if (!empty($filter_date)) {
    $filtered_logs = array_filter($filtered_logs, function($log) use ($filter_date) {
        if (!isset($log['timestamp'])) return false;
        $log_date = date('Y-m-d', strtotime($log['timestamp']));
        return $log_date === $filter_date;
    });
}

// Search filter
if (!empty($search_term)) {
    $filtered_logs = array_filter($filtered_logs, function($log) use ($search_term) {
        $searchable = implode(' ', [
            $log['entry'] ?? '',
            $log['details'] ?? '',
            $log['admin_comment'] ?? '',
            $log['user'] ?? ''
        ]);
        return stripos($searchable, $search_term) !== false;
    });
}

// Pagination
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 25;
$total_logs = count($filtered_logs);
$total_pages = ceil($total_logs / $per_page);
$offset = ($page - 1) * $per_page;
$paged_logs = array_slice($filtered_logs, $offset, $per_page);

// Get unique users and actions for filters
$all_users = array_unique(array_column($audit_logs, 'user'));
$all_actions = array_unique(array_column($audit_logs, 'action'));
sort($all_users);
sort($all_actions);

// Statistics
$stats = [
    'total_logs' => count($audit_logs),
    'submit_count' => count(array_filter($audit_logs, fn($l) => $l['action'] === 'submit')),
    'approve_count' => count(array_filter($audit_logs, fn($l) => $l['action'] === 'approve')),
    'deny_count' => count(array_filter($audit_logs, fn($l) => $l['action'] === 'deny')),
    'unique_users' => count($all_users),
    'today_logs' => count(array_filter($audit_logs, function($l) {
        return isset($l['timestamp']) && date('Y-m-d', strtotime($l['timestamp'])) === date('Y-m-d');
    }))
];

$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];
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
        .log-entry {
            transition: all 0.2s ease;
        }
        .log-entry:hover {
            background-color: rgba(0,0,0,0.02);
        }
        .action-submit { border-left: 4px solid #0dcaf0; }
        .action-approve { border-left: 4px solid #198754; }
        .action-deny { border-left: 4px solid #dc3545; }
        .action-remove_denial { border-left: 4px solid #fd7e14; }
        .action-manual_denial { border-left: 4px solid #6f42c1; }
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
                        <a class="nav-link dropdown-toggle active" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item active" href="audit_log.php">
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
    
    <div class="container mt-4">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="mb-2">
                <i class="fas fa-clipboard-list me-2"></i>
                Audit Log
            </h1>
            <p class="mb-0 opacity-75">Monitor all system activities and user actions</p>
        </div>
        
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-primary">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1"><?php echo $stats['total_logs']; ?></h4>
                                <p class="mb-0 small">Total Logs</p>
                            </div>
                            <i class="fas fa-clipboard-list stat-icon"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-info">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1"><?php echo $stats['submit_count']; ?></h4>
                                <p class="mb-0 small">Submissions</p>
                            </div>
                            <i class="fas fa-paper-plane stat-icon"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-success">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1"><?php echo $stats['approve_count']; ?></h4>
                                <p class="mb-0 small">Approvals</p>
                            </div>
                            <i class="fas fa-check-circle stat-icon"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-danger">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1"><?php echo $stats['deny_count']; ?></h4>
                                <p class="mb-0 small">Denials</p>
                            </div>
                            <i class="fas fa-times-circle stat-icon"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-warning">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1 text-dark"><?php echo $stats['unique_users']; ?></h4>
                                <p class="mb-0 small text-dark">Active Users</p>
                            </div>
                            <i class="fas fa-users stat-icon text-dark"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
                <div class="card stat-card bg-secondary">
                    <div class="card-body text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="fw-bold mb-1"><?php echo $stats['today_logs']; ?></h4>
                                <p class="mb-0 small">Today</p>
                            </div>
                            <i class="fas fa-calendar-day stat-icon"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="card mb-4">
            <div class="card-header bg-light">
                <h5 class="mb-0">
                    <i class="fas fa-filter me-2"></i> Filters & Search
                </h5>
            </div>
            <div class="card-body">
                <form method="GET" class="row g-3">
                    <div class="col-md-2">
                        <label for="action" class="form-label">Action</label>
                        <select class="form-select" id="action" name="action">
                            <option value="all" <?php echo $filter_action === 'all' ? 'selected' : ''; ?>>All Actions</option>
                            <?php foreach ($all_actions as $action): ?>
                                <option value="<?php echo htmlspecialchars($action); ?>" 
                                        <?php echo $filter_action === $action ? 'selected' : ''; ?>>
                                    <?php echo ucfirst($action); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="col-md-2">
                        <label for="user" class="form-label">User</label>
                        <select class="form-select" id="user" name="user">
                            <option value="all" <?php echo $filter_user === 'all' ? 'selected' : ''; ?>>All Users</option>
                            <?php foreach ($all_users as $user): ?>
                                <option value="<?php echo htmlspecialchars($user); ?>" 
                                        <?php echo $filter_user === $user ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($user); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="col-md-2">
                        <label for="date" class="form-label">Date</label>
                        <input type="date" class="form-control" id="date" name="date" 
                               value="<?php echo htmlspecialchars($filter_date); ?>">
                    </div>
                    
                    <div class="col-md-4">
                        <label for="search" class="form-label">Search</label>
                        <input type="text" class="form-control" id="search" name="search" 
                               value="<?php echo htmlspecialchars($search_term); ?>" 
                               placeholder="Search entries, details, or comments...">
                    </div>
                    
                    <div class="col-md-2">
                        <label class="form-label">&nbsp;</label>
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> Search
                            </button>
                            <a href="audit_log.php" class="btn btn-outline-secondary">
                                <i class="fas fa-times"></i> Clear
                            </a>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Export Options -->
        <div class="card mb-4">
            <div class="card-header bg-light">
                <h5 class="mb-0">
                    <i class="fas fa-download me-2"></i> Export Options
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3">
                        <button onclick="exportToCSV()" class="btn btn-success w-100">
                            <i class="fas fa-file-csv me-2"></i> Export to CSV
                        </button>
                    </div>
                    <div class="col-md-3">
                        <button onclick="exportToJSON()" class="btn btn-info w-100">
                            <i class="fas fa-file-code me-2"></i> Export to JSON
                        </button>
                    </div>
                    <div class="col-md-3">
                        <button onclick="printReport()" class="btn btn-secondary w-100">
                            <i class="fas fa-print me-2"></i> Print Report
                        </button>
                    </div>
                    <div class="col-md-3">
                        <button onclick="copyToClipboard(getFilteredData())" class="btn btn-outline-primary w-100">
                            <i class="fas fa-copy me-2"></i> Copy Data
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Audit Log Entries -->
        <div class="card">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="fas fa-list me-2"></i> Audit Log Entries
                </h5>
                <small class="text-muted">
                    Showing <?php echo number_format($offset + 1); ?>-<?php echo number_format(min($offset + $per_page, $total_logs)); ?> 
                    of <?php echo number_format($total_logs); ?> entries
                </small>
            </div>
            <div class="card-body">
                <?php if (empty($paged_logs)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-search fa-3x text-muted mb-3"></i>
                        <h4>No Log Entries Found</h4>
                        <p class="text-muted">No audit log entries match your current filters.</p>
                        <a href="audit_log.php" class="btn btn-primary">
                            <i class="fas fa-undo"></i> Clear Filters
                        </a>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover" id="auditTable">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Action</th>
                                    <th>Entry</th>
                                    <th>User</th>
                                    <th>Details</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($paged_logs as $log): ?>
                                    <tr class="log-entry action-<?php echo $log['action'] ?? 'unknown'; ?>">
                                        <td>
                                            <small>
                                                <?php 
                                                if (isset($log['timestamp'])) {
                                                    $time = strtotime($log['timestamp']);
                                                    echo $time ? date('M j, Y H:i:s', $time) : 'Unknown';
                                                } else {
                                                    echo 'Unknown';
                                                }
                                                ?>
                                            </small>
                                        </td>
                                        <td>
                                            <?php
                                            $action_colors = [
                                                'submit' => 'info',
                                                'approve' => 'success',
                                                'deny' => 'danger',
                                                'remove_denial' => 'warning text-dark',
                                                'manual_denial' => 'dark'
                                            ];
                                            $action_icons = [
                                                'submit' => 'fas fa-paper-plane',
                                                'approve' => 'fas fa-check-circle',
                                                'deny' => 'fas fa-times-circle',
                                                'remove_denial' => 'fas fa-undo',
                                                'manual_denial' => 'fas fa-ban'
                                            ];
                                            $action = $log['action'] ?? 'unknown';
                                            $color = $action_colors[$action] ?? 'secondary';
                                            $icon = $action_icons[$action] ?? 'fas fa-question-circle';
                                            ?>
                                            <span class="badge bg-<?php echo $color; ?>">
                                                <i class="<?php echo $icon; ?>"></i>
                                                <?php echo ucfirst($action); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if (!empty($log['entry'])): ?>
                                                <code class="small user-select-all"><?php echo htmlspecialchars($log['entry']); ?></code>
                                            <?php else: ?>
                                                <span class="text-muted">N/A</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="fw-bold"><?php echo htmlspecialchars($log['user'] ?? 'Unknown'); ?></span>
                                        </td>
                                        <td>
                                            <span class="text-truncate d-inline-block" style="max-width: 300px;" 
                                                  title="<?php echo htmlspecialchars($log['details'] ?? ''); ?>">
                                                <?php echo htmlspecialchars($log['details'] ?? 'No details'); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <button type="button" class="btn btn-outline-primary btn-sm" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#detailModal<?php echo md5($log['id'] ?? uniqid()); ?>"
                                                    title="View full details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Audit log pagination" class="mt-3">
                            <ul class="pagination justify-content-center">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>">
                                            <i class="fas fa-chevron-left"></i> Previous
                                        </a>
                                    </li>
                                <?php endif; ?>
                                
                                <?php
                                $start_page = max(1, $page - 2);
                                $end_page = min($total_pages, $page + 2);
                                
                                for ($i = $start_page; $i <= $end_page; $i++):
                                ?>
                                    <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                                        <a class="page-link" href="?<?php echo http_build_query(array_merge($_GET, ['page' => $i])); ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if ($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>">
                                            Next <i class="fas fa-chevron-right"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Detail Modals -->
    <?php foreach ($paged_logs as $log): 
        $modal_id = md5($log['id'] ?? uniqid());
    ?>
        <div class="modal fade" id="detailModal<?php echo $modal_id; ?>" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-info-circle"></i> Audit Log Details
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Basic Information</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>Action:</strong></td>
                                        <td>
                                            <?php
                                            $action = $log['action'] ?? 'unknown';
                                            $color = $action_colors[$action] ?? 'secondary';
                                            $icon = $action_icons[$action] ?? 'fas fa-question-circle';
                                            ?>
                                            <span class="badge bg-<?php echo $color; ?>">
                                                <i class="<?php echo $icon; ?>"></i>
                                                <?php echo ucfirst($action); ?>
                                            </span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><strong>User:</strong></td>
                                        <td><?php echo htmlspecialchars($log['user'] ?? 'Unknown'); ?></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Timestamp:</strong></td>
                                        <td>
                                            <?php 
                                            if (isset($log['timestamp'])) {
                                                $time = strtotime($log['timestamp']);
                                                echo $time ? date('Y-m-d H:i:s T', $time) : 'Unknown';
                                            } else {
                                                echo 'Unknown';
                                            }
                                            ?>
                                        </td>
                                    </tr>
                                    <?php if (!empty($log['entry'])): ?>
                                    <tr>
                                        <td><strong>Entry:</strong></td>
                                        <td><code class="user-select-all"><?php echo htmlspecialchars($log['entry']); ?></code></td>
                                    </tr>
                                    <?php endif; ?>
                                    <?php if (!empty($log['request_id'])): ?>
                                    <tr>
                                        <td><strong>Request ID:</strong></td>
                                        <td><code class="small"><?php echo htmlspecialchars($log['request_id']); ?></code></td>
                                    </tr>
                                    <?php endif; ?>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6>Additional Information</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>Log ID:</strong></td>
                                        <td><code class="small"><?php echo htmlspecialchars($log['id'] ?? 'N/A'); ?></code></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Session:</strong></td>
                                        <td><span class="badge bg-info">Active</span></td>
                                    </tr>
                                    <tr>
                                        <td><strong>IP Address:</strong></td>
                                        <td><?php echo $_SERVER['REMOTE_ADDR'] ?? 'Unknown'; ?></td>
                                    </tr>
                                    <tr>
                                        <td><strong>User Agent:</strong></td>
                                        <td><small class="text-muted"><?php echo substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 50) . '...'; ?></small></td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                        
                        <?php if (!empty($log['details'])): ?>
                            <div class="row mt-3">
                                <div class="col-12">
                                    <h6>Details</h6>
                                    <div class="bg-light p-3 rounded">
                                        <?php echo nl2br(htmlspecialchars($log['details'])); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($log['admin_comment'])): ?>
                            <div class="row mt-3">
                                <div class="col-12">
                                    <h6>Admin Comment</h6>
                                    <div class="bg-warning bg-opacity-10 p-3 rounded border-start border-warning border-3">
                                        <?php echo nl2br(htmlspecialchars($log['admin_comment'])); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-primary" onclick="copyLogData('<?php echo htmlspecialchars(json_encode($log)); ?>')">
                            <i class="fas fa-copy"></i> Copy Log Data
                        </button>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
    
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
        // Export functions
        function exportToCSV() {
            const table = document.getElementById('auditTable');
            const csv = [];
            const rows = table.querySelectorAll('tr');
            
            rows.forEach(row => {
                const cols = row.querySelectorAll('td, th');
                const rowData = [];
                
                // Skip actions column (last column)
                for (let j = 0; j < cols.length - 1; j++) {
                    let text = cols[j].textContent.replace(/"/g, '""').trim();
                    text = text.replace(/\s+/g, ' ');
                    rowData.push('"' + text + '"');
                }
                
                csv.push(rowData.join(','));
            });
            
            const csvContent = csv.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = 'audit_log_' + new Date().toISOString().split('T')[0] + '.csv';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
            
            showNotification('Audit log exported to CSV', 'success');
        }
        
        function exportToJSON() {
            const auditData = <?php echo json_encode($paged_logs); ?>;
            const blob = new Blob([JSON.stringify(auditData, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = 'audit_log_' + new Date().toISOString().split('T')[0] + '.json';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
            
            showNotification('Audit log exported to JSON', 'success');
        }
        
        function printReport() {
            const printWindow = window.open('', '_blank');
            const table = document.getElementById('auditTable').outerHTML;
            
            printWindow.document.write(`
                <html>
                    <head>
                        <title>Audit Log Report</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
                        <style>
                            @media print {
                                .btn { display: none; }
                                .table { font-size: 12px; }
                            }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>Audit Log Report</h1>
                            <p>Generated on: ${new Date().toLocaleString()}</p>
                            ${table}
                        </div>
                    </body>
                </html>
            `);
            
            printWindow.document.close();
            printWindow.print();
        }
        
        function getFilteredData() {
            const auditData = <?php echo json_encode($paged_logs); ?>;
            return JSON.stringify(auditData, null, 2);
        }
        
        function copyLogData(logData) {
            const data = JSON.parse(logData);
            const formattedData = JSON.stringify(data, null, 2);
            copyToClipboard(formattedData);
        }
        
        // Copy to clipboard function
        function copyToClipboard(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showNotification('Data copied to clipboard', 'success');
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
                showNotification('Data copied to clipboard', 'success');
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
            
            // Auto-refresh page every 5 minutes
            setTimeout(() => {
                window.location.reload();
            }, 300000);
        });
    </script>
</body>
</html>