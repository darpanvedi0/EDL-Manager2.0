<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_auth();

$page_title = 'My Request History';

// Get filter parameters
$filter_status = $_GET['status'] ?? 'all';
$filter_type = $_GET['type'] ?? 'all';
$search_term = $_GET['search'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';

// Get current user's requests
$all_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$user_requests = array_filter($all_requests, function($request) {
    return $request['submitted_by'] === $_SESSION['username'];
});

// Apply filters
$filtered_requests = $user_requests;

// Status filter
if ($filter_status !== 'all') {
    $filtered_requests = array_filter($filtered_requests, function($request) use ($filter_status) {
        return isset($request['status']) && $request['status'] === $filter_status;
    });
}

// Type filter
if ($filter_type !== 'all') {
    $filtered_requests = array_filter($filtered_requests, function($request) use ($filter_type) {
        return isset($request['type']) && $request['type'] === $filter_type;
    });
}

// Search filter
if (!empty($search_term)) {
    $filtered_requests = array_filter($filtered_requests, function($request) use ($search_term) {
        $searchable = implode(' ', [
            $request['entry'] ?? '',
            $request['comment'] ?? '',
            $request['justification'] ?? '',
            $request['servicenow_ticket'] ?? ''
        ]);
        return stripos($searchable, $search_term) !== false;
    });
}

// Date range filter
if (!empty($date_from)) {
    $filtered_requests = array_filter($filtered_requests, function($request) use ($date_from) {
        $request_date = isset($request['submitted_at']) ? date('Y-m-d', strtotime($request['submitted_at'])) : '';
        return $request_date >= $date_from;
    });
}

if (!empty($date_to)) {
    $filtered_requests = array_filter($filtered_requests, function($request) use ($date_to) {
        $request_date = isset($request['submitted_at']) ? date('Y-m-d', strtotime($request['submitted_at'])) : '';
        return $request_date <= $date_to;
    });
}

// Sort by date (newest first)
usort($filtered_requests, function($a, $b) {
    return strtotime($b['submitted_at'] ?? '0') - strtotime($a['submitted_at'] ?? '0');
});

// Pagination
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 20;
$total_requests = count($filtered_requests);
$total_pages = ceil($total_requests / $per_page);
$offset = ($page - 1) * $per_page;
$paged_requests = array_slice($filtered_requests, $offset, $per_page);

// Get statistics
$stats = [
    'total' => count($user_requests),
    'pending' => count(array_filter($user_requests, fn($r) => ($r['status'] ?? '') === 'pending')),
    'approved' => count(array_filter($user_requests, fn($r) => ($r['status'] ?? '') === 'approved')),
    'denied' => count(array_filter($user_requests, fn($r) => ($r['status'] ?? '') === 'denied'))
];

// Get additional details for approved/denied requests
$approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
$denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');

// Include the centralized header
require_once '../includes/header.php';
?>

<div class="container mt-4">

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-history me-2"></i>
        My Request History
    </h1>
    <p class="mb-0 opacity-75">View and track all your EDL requests</p>
</div>

<!-- Statistics -->
<div class="row mb-4">
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card stat-card bg-primary">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="fw-bold mb-1"><?php echo $stats['total']; ?></h3>
                        <p class="mb-0">Total Requests</p>
                    </div>
                    <div>
                        <i class="fas fa-list stat-icon"></i>
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
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card stat-card bg-success">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3 class="fw-bold mb-1"><?php echo $stats['approved']; ?></h3>
                        <p class="mb-0">Approved</p>
                    </div>
                    <div>
                        <i class="fas fa-check-circle stat-icon"></i>
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
                        <h3 class="fw-bold mb-1"><?php echo $stats['denied']; ?></h3>
                        <p class="mb-0">Denied</p>
                    </div>
                    <div>
                        <i class="fas fa-times-circle stat-icon"></i>
                    </div>
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
                <label for="status" class="form-label">Status</label>
                <select class="form-select" id="status" name="status">
                    <option value="all" <?php echo $filter_status === 'all' ? 'selected' : ''; ?>>All Status</option>
                    <option value="pending" <?php echo $filter_status === 'pending' ? 'selected' : ''; ?>>Pending</option>
                    <option value="approved" <?php echo $filter_status === 'approved' ? 'selected' : ''; ?>>Approved</option>
                    <option value="denied" <?php echo $filter_status === 'denied' ? 'selected' : ''; ?>>Denied</option>
                </select>
            </div>
            
            <div class="col-md-2">
                <label for="type" class="form-label">Type</label>
                <select class="form-select" id="type" name="type">
                    <option value="all" <?php echo $filter_type === 'all' ? 'selected' : ''; ?>>All Types</option>
                    <option value="ip" <?php echo $filter_type === 'ip' ? 'selected' : ''; ?>>IP Address</option>
                    <option value="domain" <?php echo $filter_type === 'domain' ? 'selected' : ''; ?>>Domain</option>
                    <option value="url" <?php echo $filter_type === 'url' ? 'selected' : ''; ?>>URL</option>
                </select>
            </div>
            
            <div class="col-md-2">
                <label for="date_from" class="form-label">From Date</label>
                <input type="date" class="form-control" id="date_from" name="date_from" 
                       value="<?php echo htmlspecialchars($date_from); ?>">
            </div>
            
            <div class="col-md-2">
                <label for="date_to" class="form-label">To Date</label>
                <input type="date" class="form-control" id="date_to" name="date_to" 
                       value="<?php echo htmlspecialchars($date_to); ?>">
            </div>
            
            <div class="col-md-2">
                <label for="search" class="form-label">Search</label>
                <input type="text" class="form-control" id="search" name="search" 
                       value="<?php echo htmlspecialchars($search_term); ?>" 
                       placeholder="Search...">
            </div>
            
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid gap-2">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> Search
                    </button>
                    <a href="request_history.php" class="btn btn-outline-secondary">
                        <i class="fas fa-times"></i> Clear
                    </a>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Request History Table -->
<div class="card">
    <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <h5 class="mb-0">
            <i class="fas fa-list me-2"></i> Your Requests
        </h5>
        <small class="text-muted">
            Showing <?php echo number_format($offset + 1); ?>-<?php echo number_format(min($offset + $per_page, $total_requests)); ?> 
            of <?php echo number_format($total_requests); ?> requests
        </small>
    </div>
    <div class="card-body">
        <?php if (empty($paged_requests)): ?>
            <div class="text-center py-5">
                <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                <h4>No Requests Found</h4>
                <p class="text-muted">
                    <?php if (empty($user_requests)): ?>
                        You haven't submitted any requests yet.
                    <?php else: ?>
                        No requests match your current filters.
                    <?php endif; ?>
                </p>
                <?php if (in_array('submit', $_SESSION['permissions'] ?? [])): ?>
                    <a href="submit_request.php" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Submit New Request
                    </a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Request ID</th>
                            <th>Entry</th>
                            <th>Type</th>
                            <th>Priority</th>
                            <th>Status</th>
                            <th>Submitted</th>
                            <th>ServiceNow</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($paged_requests as $request): ?>
                            <tr class="<?php echo $request['status'] === 'denied' ? 'table-danger' : ($request['status'] === 'approved' ? 'table-success' : ''); ?>">
                                <td>
                                    <small><code><?php echo htmlspecialchars(substr($request['id'], 0, 16) . '...'); ?></code></small>
                                </td>
                                <td>
                                    <code class="user-select-all"><?php echo htmlspecialchars($request['entry']); ?></code>
                                </td>
                                <td>
                                    <?php
                                    $type_icons = [
                                        'ip' => 'fas fa-network-wired',
                                        'domain' => 'fas fa-globe',
                                        'url' => 'fas fa-link'
                                    ];
                                    $icon = $type_icons[$request['type']] ?? 'fas fa-question-circle';
                                    ?>
                                    <span class="badge bg-secondary">
                                        <i class="<?php echo $icon; ?>"></i>
                                        <?php echo strtoupper($request['type']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php
                                    $priority_colors = [
                                        'critical' => 'danger',
                                        'high' => 'warning text-dark',
                                        'medium' => 'info',
                                        'low' => 'success'
                                    ];
                                    $color = $priority_colors[$request['priority']] ?? 'secondary';
                                    ?>
                                    <span class="badge bg-<?php echo $color; ?>">
                                        <?php echo ucfirst($request['priority']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php
                                    $status_colors = [
                                        'pending' => 'warning text-dark',
                                        'approved' => 'success',
                                        'denied' => 'danger'
                                    ];
                                    $status_icons = [
                                        'pending' => 'fas fa-clock',
                                        'approved' => 'fas fa-check-circle',
                                        'denied' => 'fas fa-times-circle'
                                    ];
                                    $color = $status_colors[$request['status']] ?? 'secondary';
                                    $icon = $status_icons[$request['status']] ?? 'fas fa-question-circle';
                                    ?>
                                    <span class="badge bg-<?php echo $color; ?>">
                                        <i class="<?php echo $icon; ?>"></i>
                                        <?php echo ucfirst($request['status']); ?>
                                    </span>
                                </td>
                                <td>
                                    <small>
                                        <?php 
                                        $time = strtotime($request['submitted_at']);
                                        echo $time ? date('Y-m-d H:i', $time) : 'Unknown';
                                        ?>
                                    </small>
                                </td>
                                <td>
                                    <?php if (!empty($request['servicenow_ticket'])): ?>
                                        <small><code><?php echo htmlspecialchars($request['servicenow_ticket']); ?></code></small>
                                    <?php else: ?>
                                        <small class="text-muted">N/A</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button type="button" class="btn btn-outline-primary btn-sm" 
                                            data-bs-toggle="modal" 
                                            data-bs-target="#detailModal<?php echo md5($request['id']); ?>"
                                            title="View details">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button type="button" class="btn btn-outline-info btn-sm" 
                                            onclick="copyToClipboard('<?php echo htmlspecialchars($request['entry']); ?>')"
                                            title="Copy entry">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <nav aria-label="Request history pagination" class="mt-3">
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

<!-- Detail Modals -->
<?php foreach ($paged_requests as $request): 
    $modal_id = md5($request['id']);
    
    // Find additional details if approved or denied
    $additional_details = null;
    if ($request['status'] === 'approved') {
        foreach ($approved_entries as $entry) {
            if (isset($entry['request_id']) && $entry['request_id'] === $request['id']) {
                $additional_details = $entry;
                break;
            }
        }
    } elseif ($request['status'] === 'denied') {
        foreach ($denied_entries as $entry) {
            if (isset($entry['request_id']) && $entry['request_id'] === $request['id']) {
                $additional_details = $entry;
                break;
            }
        }
    }
?>
    <div class="modal fade" id="detailModal<?php echo $modal_id; ?>" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-info-circle"></i> Request Details
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Request Information</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>Request ID:</strong></td>
                                    <td><code class="small"><?php echo htmlspecialchars($request['id']); ?></code></td>
                                </tr>
                                <tr>
                                    <td><strong>Entry:</strong></td>
                                    <td><code class="user-select-all"><?php echo htmlspecialchars($request['entry']); ?></code></td>
                                </tr>
                                <tr>
                                    <td><strong>Type:</strong></td>
                                    <td>
                                        <?php
                                        $type_icons = [
                                            'ip' => 'fas fa-network-wired',
                                            'domain' => 'fas fa-globe',
                                            'url' => 'fas fa-link'
                                        ];
                                        $icon = $type_icons[$request['type']] ?? 'fas fa-question-circle';
                                        ?>
                                        <span class="badge bg-secondary">
                                            <i class="<?php echo $icon; ?>"></i>
                                            <?php echo strtoupper($request['type']); ?>
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>Priority:</strong></td>
                                    <td>
                                        <?php
                                        $priority_colors = [
                                            'critical' => 'danger',
                                            'high' => 'warning text-dark',
                                            'medium' => 'info',
                                            'low' => 'success'
                                        ];
                                        $color = $priority_colors[$request['priority']] ?? 'secondary';
                                        ?>
                                        <span class="badge bg-<?php echo $color; ?>">
                                            <?php echo ucfirst($request['priority']); ?>
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>Status:</strong></td>
                                    <td>
                                        <?php
                                        $status_colors = [
                                            'pending' => 'warning text-dark',
                                            'approved' => 'success',
                                            'denied' => 'danger'
                                        ];
                                        $color = $status_colors[$request['status']] ?? 'secondary';
                                        ?>
                                        <span class="badge bg-<?php echo $color; ?>">
                                            <?php echo ucfirst($request['status']); ?>
                                        </span>
                                    </td>
                                </tr>
                                <?php if (!empty($request['servicenow_ticket'])): ?>
                                <tr>
                                    <td><strong>ServiceNow:</strong></td>
                                    <td><code><?php echo htmlspecialchars($request['servicenow_ticket']); ?></code></td>
                                </tr>
                                <?php endif; ?>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <h6>Timeline</h6>
                            <table class="table table-sm">
                                <tr>
                                    <td><strong>Submitted:</strong></td>
                                    <td>
                                        <?php 
                                        $time = strtotime($request['submitted_at']);
                                        echo $time ? date('Y-m-d H:i:s', $time) : 'Unknown';
                                        ?>
                                    </td>
                                </tr>
                                <?php if ($request['status'] === 'approved' && $additional_details): ?>
                                <tr>
                                    <td><strong>Approved By:</strong></td>
                                    <td><?php echo htmlspecialchars($additional_details['approved_by'] ?? 'Unknown'); ?></td>
                                </tr>
                                <tr>
                                    <td><strong>Approved At:</strong></td>
                                    <td>
                                        <?php 
                                        $time = isset($additional_details['approved_at']) ? strtotime($additional_details['approved_at']) : false;
                                        echo $time ? date('Y-m-d H:i:s', $time) : 'Unknown';
                                        ?>
                                    </td>
                                </tr>
                                <?php elseif ($request['status'] === 'denied' && $additional_details): ?>
                                <tr>
                                    <td><strong>Denied By:</strong></td>
                                    <td><?php echo htmlspecialchars($additional_details['denied_by'] ?? 'Unknown'); ?></td>
                                </tr>
                                <tr>
                                    <td><strong>Denied At:</strong></td>
                                    <td>
                                        <?php 
                                        $time = isset($additional_details['denied_at']) ? strtotime($additional_details['denied_at']) : false;
                                        echo $time ? date('Y-m-d H:i:s', $time) : 'Unknown';
                                        ?>
                                    </td>
                                </tr>
                                <?php endif; ?>
                            </table>
                        </div>
                    </div>
                    
                    <?php if (!empty($request['justification'])): ?>
                        <div class="row mt-3">
                            <div class="col-12">
                                <h6>Business Justification</h6>
                                <div class="bg-light p-3 rounded">
                                    <?php echo nl2br(htmlspecialchars($request['justification'])); ?>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($request['comment'])): ?>
                        <div class="row mt-3">
                            <div class="col-12">
                                <h6>Additional Comments</h6>
                                <div class="bg-light p-3 rounded">
                                    <?php echo nl2br(htmlspecialchars($request['comment'])); ?>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($request['status'] === 'approved' && !empty($additional_details['admin_comment'])): ?>
                        <div class="row mt-3">
                            <div class="col-12">
                                <h6>Approval Notes</h6>
                                <div class="bg-success bg-opacity-10 p-3 rounded border-start border-success border-3">
                                    <?php echo nl2br(htmlspecialchars($additional_details['admin_comment'])); ?>
                                </div>
                            </div>
                        </div>
                    <?php elseif ($request['status'] === 'denied' && $additional_details && !empty($additional_details['reason'])): ?>
                        <div class="row mt-3">
                            <div class="col-12">
                                <h6>Denial Reason</h6>
                                <div class="bg-danger bg-opacity-10 p-3 rounded border-start border-danger border-3">
                                    <?php echo nl2br(htmlspecialchars($additional_details['reason'])); ?>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-primary" onclick="copyToClipboard('<?php echo htmlspecialchars($request['entry']); ?>')">
                        <i class="fas fa-copy"></i> Copy Entry
                    </button>
                    <?php if ($request['status'] === 'pending' && in_array('submit', $_SESSION['permissions'] ?? [])): ?>
                        <span class="text-warning">
                            <i class="fas fa-clock"></i> Awaiting approval
                        </span>
                    <?php endif; ?>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
<?php endforeach; ?>

</div>
<!-- End container -->

<?php require_once '../includes/footer.php'; ?>