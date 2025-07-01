<?php
// Load required files in correct order
require_once 'config/config.php';
require_once 'includes/functions.php';
require_once 'includes/auth.php';

$auth = new EDLAuth();
$auth->require_auth();

$page_title = 'Dashboard';

// Get statistics
$pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
$denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
$audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');

$stats = [
    'pending' => count(array_filter($pending_requests, function($r) { 
        return isset($r['status']) && $r['status'] === 'pending'; 
    })),
    'approved' => count(array_filter($approved_entries, function($e) { 
        return isset($e['status']) && $e['status'] === 'active'; 
    })),
    'denied' => count($denied_entries),
    'total_requests' => count($pending_requests)
];

// Count by type
$type_counts = ['ip' => 0, 'domain' => 0, 'url' => 0];
foreach ($approved_entries as $entry) {
    if (isset($entry['status'], $entry['type']) && 
        $entry['status'] === 'active' && 
        isset($type_counts[$entry['type']])) {
        $type_counts[$entry['type']]++;
    }
}

// Recent activity (last 10 items)
$recent_logs = array_slice(array_reverse($audit_logs), 0, 10);

// Safe session variable access
$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];
$login_time = $_SESSION['login_time'] ?? time();

// Include centralized header
include 'includes/header.php';
?>

<div class="container mt-4">
    <!-- Page Header -->
    <div class="page-header">
        <h1 class="mb-2">
            <i class="fas fa-tachometer-alt me-2"></i> 
            Dashboard
        </h1>
        <p class="mb-0 opacity-75">Welcome back, <?php echo htmlspecialchars($user_name); ?>!</p>
    </div>
    
    <!-- Statistics Cards -->
    <div class="row mb-4">
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card stat-card bg-primary">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h3 class="fw-bold mb-1"><?php echo $type_counts['ip']; ?></h3>
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
                            <h3 class="fw-bold mb-1"><?php echo $type_counts['domain']; ?></h3>
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
                            <h3 class="fw-bold mb-1"><?php echo $type_counts['url']; ?></h3>
                            <p class="mb-0">URLs</p>
                        </div>
                        <div>
                            <i class="fas fa-link stat-icon"></i>
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
                            <h3 class="fw-bold mb-1 text-dark"><?php echo $stats['pending']; ?></h3>
                            <p class="mb-0 text-dark">Pending</p>
                        </div>
                        <div>
                            <i class="fas fa-clock stat-icon text-dark"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="card mb-4">
        <div class="card-header bg-light">
            <h5 class="mb-0">
                <i class="fas fa-bolt text-warning me-2"></i> Quick Actions
            </h5>
        </div>
        <div class="card-body">
            <div class="row">
                <?php if (in_array('submit', $user_permissions)): ?>
                <div class="col-lg-3 col-md-6 mb-2">
                    <a href="pages/submit_request.php" class="btn btn-primary w-100">
                        <i class="fas fa-plus me-2"></i> Submit Request
                    </a>
                </div>
                <?php endif; ?>
                
                <?php if (in_array('approve', $user_permissions)): ?>
                <div class="col-lg-3 col-md-6 mb-2">
                    <a href="pages/approvals.php" class="btn btn-success w-100">
                        <i class="fas fa-check me-2"></i> 
                        Review Requests
                        <?php if ($stats['pending'] > 0): ?>
                            <span class="badge bg-light text-dark ms-1"><?php echo $stats['pending']; ?></span>
                        <?php endif; ?>
                    </a>
                </div>
                <?php endif; ?>
                
                <div class="col-lg-3 col-md-6 mb-2">
                    <a href="pages/edl_viewer.php" class="btn btn-info w-100">
                        <i class="fas fa-list me-2"></i> View EDL
                    </a>
                </div>
                
                <div class="col-lg-3 col-md-6 mb-2">
                    <div class="dropup w-100">
                        <button class="btn btn-secondary dropdown-toggle w-100" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-download me-2"></i> Download EDL
                        </button>
                        <ul class="dropdown-menu w-100">
                            <li><a class="dropdown-item" href="http://<?php echo $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']); ?>/edl-files/ip_blocklist.txt" target="_blank">
                                <i class="fas fa-network-wired me-2"></i> IP Blocklist
                            </a></li>
                            <li><a class="dropdown-item" href="http://<?php echo $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']); ?>/edl-files/domain_blocklist.txt" target="_blank">
                                <i class="fas fa-globe me-2"></i> Domain Blocklist
                            </a></li>
                            <li><a class="dropdown-item" href="http://<?php echo $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']); ?>/edl-files/url_blocklist.txt" target="_blank">
                                <i class="fas fa-link me-2"></i> URL Blocklist
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Content Row -->
    <div class="row">
        <!-- System Information -->
        <div class="col-md-6">
            <div class="card h-100">
                <div class="card-header bg-light">
                    <h6 class="mb-0">
                        <i class="fas fa-info-circle text-primary me-2"></i> System Status
                    </h6>
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold text-success">✅ Online</div>
                                <small class="text-muted">System Status</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold"><?php echo ucfirst($user_role); ?></div>
                                <small class="text-muted">Your Role</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold"><?php echo count($user_permissions); ?></div>
                                <small class="text-muted">Permissions</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold"><?php echo PHP_VERSION; ?></div>
                                <small class="text-muted">PHP Version</small>
                            </div>
                        </div>
                    </div>
                    
                    <hr>
                    
                    <div class="small">
                        <p class="mb-1"><strong>Login Time:</strong> <?php echo date('Y-m-d H:i:s', $login_time); ?></p>
                        <p class="mb-1"><strong>Username:</strong> <?php echo htmlspecialchars($user_username); ?></p>
                        <p class="mb-0"><strong>Email:</strong> <?php echo htmlspecialchars($user_email); ?></p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="col-md-6">
            <div class="card h-100">
                <div class="card-header bg-light">
                    <h6 class="mb-0">
                        <i class="fas fa-chart-bar text-success me-2"></i> EDL Statistics
                    </h6>
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold text-primary"><?php echo $stats['approved']; ?></div>
                                <small class="text-muted">Active Entries</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold text-warning"><?php echo $stats['pending']; ?></div>
                                <small class="text-muted">Pending</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold text-danger"><?php echo $stats['denied']; ?></div>
                                <small class="text-muted">Denied</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="text-center p-3 bg-light rounded">
                                <div class="fw-bold text-info"><?php echo $stats['total_requests']; ?></div>
                                <small class="text-muted">Total Requests</small>
                            </div>
                        </div>
                    </div>
                    
                    <hr>
                    
                    <div class="small">
                        <div class="d-flex justify-content-between mb-1">
                            <span>IPs:</span>
                            <span class="fw-bold"><?php echo $type_counts['ip']; ?></span>
                        </div>
                        <div class="d-flex justify-content-between mb-1">
                            <span>Domains:</span>
                            <span class="fw-bold"><?php echo $type_counts['domain']; ?></span>
                        </div>
                        <div class="d-flex justify-content-between">
                            <span>URLs:</span>
                            <span class="fw-bold"><?php echo $type_counts['url']; ?></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <?php if (!empty($recent_logs)): ?>
    <!-- Recent Activity -->
    <div class="card mt-4">
        <div class="card-header bg-light">
            <h6 class="mb-0">
                <i class="fas fa-history text-info me-2"></i> Recent Activity
            </h6>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm table-hover">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Entry</th>
                            <th>User</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_logs as $log): ?>
                            <tr>
                                <td>
                                    <?php
                                    $action_colors = [
                                        'submit' => 'info',
                                        'approve' => 'success', 
                                        'deny' => 'danger'
                                    ];
                                    $color = $action_colors[$log['action'] ?? ''] ?? 'secondary';
                                    ?>
                                    <span class="badge bg-<?php echo $color; ?>">
                                        <?php echo ucfirst($log['action'] ?? 'unknown'); ?>
                                    </span>
                                </td>
                                <td>
                                    <code class="small"><?php echo htmlspecialchars($log['entry'] ?? ''); ?></code>
                                </td>
                                <td><?php echo htmlspecialchars($log['user'] ?? ''); ?></td>
                                <td>
                                    <small class="text-muted">
                                        <?php 
                                        if (isset($log['timestamp'])) {
                                            $time = strtotime($log['timestamp']);
                                            echo $time ? date('M j, H:i', $time) : 'Unknown';
                                        } else {
                                            echo 'Unknown';
                                        }
                                        ?>
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
</div>

<?php include 'includes/footer.php'; ?>

<script>
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