<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'Audit Log';
$error_message = '';

// Pagination settings
$items_per_page = 25;
$current_page = max(1, intval($_GET['page'] ?? 1));

// Load audit logs
$audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
$audit_logs = array_reverse($audit_logs); // Show newest first

// Filter functionality
$filter_action = sanitize_input($_GET['action'] ?? '');
$filter_user = sanitize_input($_GET['user'] ?? '');
$filter_date = sanitize_input($_GET['date'] ?? '');

if (!empty($filter_action) || !empty($filter_user) || !empty($filter_date)) {
    $audit_logs = array_filter($audit_logs, function($log) use ($filter_action, $filter_user, $filter_date) {
        $match = true;
        
        if (!empty($filter_action) && $log['action'] !== $filter_action) {
            $match = false;
        }
        
        if (!empty($filter_user) && stripos($log['user'] ?? '', $filter_user) === false) {
            $match = false;
        }
        
        if (!empty($filter_date)) {
            $log_date = date('Y-m-d', strtotime($log['timestamp'] ?? ''));
            if ($log_date !== $filter_date) {
                $match = false;
            }
        }
        
        return $match;
    });
}

// Calculate statistics
$stats = [
    'total_logs' => count($audit_logs),
    'submit_count' => count(array_filter($audit_logs, fn($l) => ($l['action'] ?? '') === 'submit')),
    'approve_count' => count(array_filter($audit_logs, fn($l) => ($l['action'] ?? '') === 'approve')),
    'deny_count' => count(array_filter($audit_logs, fn($l) => ($l['action'] ?? '') === 'deny')),
    'unique_users' => count(array_unique(array_column($audit_logs, 'user')))
];

// Pagination
$total_logs = count($audit_logs);
$total_pages = ceil($total_logs / $items_per_page);
$offset = ($current_page - 1) * $items_per_page;
$paged_logs = array_slice($audit_logs, $offset, $items_per_page);

// Get unique values for filters
$all_logs = read_json_file(DATA_DIR . '/audit_logs.json');
$unique_actions = array_unique(array_column($all_logs, 'action'));
$unique_users = array_unique(array_column($all_logs, 'user'));

// Include the centralized header
require_once '../includes/header.php';
?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-clipboard-list me-2"></i>
        Audit Log
    </h1>
    <p class="mb-0 opacity-75">View system activity and logs for security and compliance</p>
</div>

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo $error_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Statistics Overview -->
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
                        <h4 class="fw-bold mb-1"><?php echo $stats['unique_users']; ?></h4>
                        <p class="mb-0 small">Active Users</p>
                    </div>
                    <i class="fas fa-users stat-icon"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-lg-2 col-md-4 col-sm-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h4 class="fw-bold mb-1"><?php echo $total_pages; ?></h4>
                        <p class="mb-0 small">Pages</p>
                    </div>
                    <i class="fas fa-file-alt stat-icon text-muted"></i>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Filters -->
<div class="card mb-4">
    <div class="card-header bg-light">
        <h5 class="mb-0">
            <i class="fas fa-filter me-2"></i>
            Filter Logs
        </h5>
    </div>
    <div class="card-body">
        <form method="get" class="row g-3">
            <div class="col-md-3">
                <label for="action" class="form-label">Action</label>
                <select class="form-select" id="action" name="action">
                    <option value="">All Actions</option>
                    <?php foreach ($unique_actions as $action): ?>
                    <option value="<?php echo htmlspecialchars($action); ?>" 
                            <?php echo $filter_action === $action ? 'selected' : ''; ?>>
                        <?php echo ucfirst($action); ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3">
                <label for="user" class="form-label">User</label>
                <select class="form-select" id="user" name="user">
                    <option value="">All Users</option>
                    <?php foreach ($unique_users as $user): ?>
                    <option value="<?php echo htmlspecialchars($user); ?>" 
                            <?php echo $filter_user === $user ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($user); ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3">
                <label for="date" class="form-label">Date</label>
                <input type="date" class="form-control" id="date" name="date" 
                       value="<?php echo htmlspecialchars($filter_date); ?>">
            </div>
            <div class="col-md-3">
                <label class="form-label">&nbsp;</label>
                <div class="d-flex gap-2">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search me-1"></i> Filter
                    </button>
                    <a href="audit_log.php" class="btn btn-outline-secondary">
                        <i class="fas fa-times me-1"></i> Clear
                    </a>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Audit Log Table -->
<div class="card">
    <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <h5 class="mb-0">
            <i class="fas fa-list me-2"></i> 
            Audit Entries
            <?php if (!empty($filter_action) || !empty($filter_user) || !empty($filter_date)): ?>
                <span class="badge bg-info ms-2">Filtered</span>
            <?php endif; ?>
        </h5>
        <small class="text-muted">
            Showing <?php echo count($paged_logs); ?> of <?php echo number_format($total_logs); ?> entries
        </small>
    </div>
    <div class="card-body">
        <?php if (empty($paged_logs)): ?>
            <div class="text-center py-5">
                <i class="fas fa-clipboard-list fa-3x text-muted mb-3"></i>
                <h4>No Audit Logs Found</h4>
                <p class="text-muted">
                    <?php if (!empty($filter_action) || !empty($filter_user) || !empty($filter_date)): ?>
                        Try adjusting your filters or <a href="audit_log.php">clear all filters</a>.
                    <?php else: ?>
                        No system activity has been logged yet.
                    <?php endif; ?>
                </p>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Action</th>
                            <th>Entry</th>
                            <th>User</th>
                            <th>Details</th>
                            <th>Comments</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($paged_logs as $log): ?>
                        <tr class="log-entry action-<?php echo $log['action'] ?? ''; ?>">
                            <td>
                                <small class="text-muted">
                                    <?php echo date('M j, Y', strtotime($log['timestamp'] ?? '')); ?><br>
                                    <?php echo date('H:i:s', strtotime($log['timestamp'] ?? '')); ?>
                                </small>
                            </td>
                            <td>
                                <span class="badge bg-<?php 
                                    echo match($log['action'] ?? '') {
                                        'submit' => 'info',
                                        'approve' => 'success', 
                                        'deny' => 'danger',
                                        'remove_denial' => 'warning',
                                        'manual_denial' => 'secondary',
                                        default => 'light text-dark'
                                    };
                                ?>">
                                    <i class="fas fa-<?php 
                                        echo match($log['action'] ?? '') {
                                            'submit' => 'paper-plane',
                                            'approve' => 'check-circle',
                                            'deny' => 'times-circle', 
                                            'remove_denial' => 'undo',
                                            'manual_denial' => 'ban',
                                            default => 'circle'
                                        };
                                    ?> me-1"></i>
                                    <?php echo ucfirst($log['action'] ?? 'Unknown'); ?>
                                </span>
                            </td>
                            <td>
                                <?php if (!empty($log['entry'])): ?>
                                    <code><?php echo htmlspecialchars($log['entry']); ?></code>
                                <?php else: ?>
                                    <span class="text-muted">N/A</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?php echo htmlspecialchars($log['user'] ?? 'System'); ?></strong>
                            </td>
                            <td>
                                <small><?php echo htmlspecialchars($log['details'] ?? 'No details'); ?></small>
                            </td>
                            <td>
                                <small class="text-muted">
                                    <?php echo htmlspecialchars($log['admin_comment'] ?? '-'); ?>
                                </small>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
            <nav aria-label="Audit log pagination" class="mt-4">
                <ul class="pagination justify-content-center">
                    <!-- Previous -->
                    <li class="page-item <?php echo $current_page <= 1 ? 'disabled' : ''; ?>">
                        <a class="page-link" href="?page=<?php echo max(1, $current_page - 1); ?><?php 
                            echo !empty($filter_action) ? '&action=' . urlencode($filter_action) : '';
                            echo !empty($filter_user) ? '&user=' . urlencode($filter_user) : '';
                            echo !empty($filter_date) ? '&date=' . urlencode($filter_date) : '';
                        ?>">
                            <i class="fas fa-chevron-left"></i> Previous
                        </a>
                    </li>
                    
                    <!-- Page numbers -->
                    <?php
                    $start_page = max(1, $current_page - 2);
                    $end_page = min($total_pages, $current_page + 2);
                    
                    if ($start_page > 1): ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=1<?php 
                                echo !empty($filter_action) ? '&action=' . urlencode($filter_action) : '';
                                echo !empty($filter_user) ? '&user=' . urlencode($filter_user) : '';
                                echo !empty($filter_date) ? '&date=' . urlencode($filter_date) : '';
                            ?>">1</a>
                        </li>
                        <?php if ($start_page > 2): ?>
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                        <?php endif;
                    endif;
                    
                    for ($i = $start_page; $i <= $end_page; $i++): ?>
                        <li class="page-item <?php echo $i === $current_page ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?><?php 
                                echo !empty($filter_action) ? '&action=' . urlencode($filter_action) : '';
                                echo !empty($filter_user) ? '&user=' . urlencode($filter_user) : '';
                                echo !empty($filter_date) ? '&date=' . urlencode($filter_date) : '';
                            ?>"><?php echo $i; ?></a>
                        </li>
                    <?php endfor;
                    
                    if ($end_page < $total_pages): 
                        if ($end_page < $total_pages - 1): ?>
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                        <?php endif; ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=<?php echo $total_pages; ?><?php 
                                echo !empty($filter_action) ? '&action=' . urlencode($filter_action) : '';
                                echo !empty($filter_user) ? '&user=' . urlencode($filter_user) : '';
                                echo !empty($filter_date) ? '&date=' . urlencode($filter_date) : '';
                            ?>"><?php echo $total_pages; ?></a>
                        </li>
                    <?php endif; ?>
                    
                    <!-- Next -->
                    <li class="page-item <?php echo $current_page >= $total_pages ? 'disabled' : ''; ?>">
                        <a class="page-link" href="?page=<?php echo min($total_pages, $current_page + 1); ?><?php 
                            echo !empty($filter_action) ? '&action=' . urlencode($filter_action) : '';
                            echo !empty($filter_user) ? '&user=' . urlencode($filter_user) : '';
                            echo !empty($filter_date) ? '&date=' . urlencode($filter_date) : '';
                        ?>">
                            Next <i class="fas fa-chevron-right"></i>
                        </a>
                    </li>
                </ul>
            </nav>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>

<style>
/* Page-specific audit log styles */
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

<?php require_once '../includes/footer.php'; ?>