<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_auth();

$page_title = 'EDL Viewer';

// Get filter parameters
$filter_type = $_GET['type'] ?? 'all';
$search_term = $_GET['search'] ?? '';

// Load all approved entries
$approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
$active_entries = array_filter($approved_entries, function($entry) {
    return isset($entry['status']) && $entry['status'] === 'active';
});

// Apply filters
$filtered_entries = $active_entries;

if ($filter_type !== 'all') {
    $filtered_entries = array_filter($filtered_entries, function($entry) use ($filter_type) {
        return isset($entry['type']) && $entry['type'] === $filter_type;
    });
}

if (!empty($search_term)) {
    $filtered_entries = array_filter($filtered_entries, function($entry) use ($search_term) {
        return stripos($entry['entry'] ?? '', $search_term) !== false ||
               stripos($entry['comment'] ?? '', $search_term) !== false;
    });
}

// Sort entries
usort($filtered_entries, function($a, $b) {
    return strcmp($a['entry'] ?? '', $b['entry'] ?? '');
});

// Pagination
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 50;
$total_entries = count($filtered_entries);
$total_pages = ceil($total_entries / $per_page);
$offset = ($page - 1) * $per_page;
$paged_entries = array_slice($filtered_entries, $offset, $per_page);

// Count by type
$type_counts = ['ip' => 0, 'domain' => 0, 'url' => 0];
foreach ($active_entries as $entry) {
    if (isset($entry['type']) && isset($type_counts[$entry['type']])) {
        $type_counts[$entry['type']]++;
    }
}

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
                        <a class="nav-link active" href="edl_viewer.php">
                            <i class="fas fa-list me-1"></i> EDL Viewer
                        </a>
                    </li>
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
                <i class="fas fa-list me-2"></i>
                EDL Viewer
            </h1>
            <p class="mb-0 opacity-75">View and search External Dynamic List entries</p>
        </div>
        
        <!-- Statistics -->
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
                                <h3 class="fw-bold mb-1 text-dark"><?php echo count($active_entries); ?></h3>
                                <p class="mb-0 text-dark">Total Active</p>
                            </div>
                            <div>
                                <i class="fas fa-shield-alt stat-icon text-dark"></i>
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
                    <div class="col-md-3">
                        <label for="type" class="form-label">Entry Type</label>
                        <select class="form-select" id="type" name="type">
                            <option value="all" <?php echo $filter_type === 'all' ? 'selected' : ''; ?>>All Types</option>
                            <option value="ip" <?php echo $filter_type === 'ip' ? 'selected' : ''; ?>>IP Addresses</option>
                            <option value="domain" <?php echo $filter_type === 'domain' ? 'selected' : ''; ?>>Domains</option>
                            <option value="url" <?php echo $filter_type === 'url' ? 'selected' : ''; ?>>URLs</option>
                        </select>
                    </div>
                    
                    <div class="col-md-6">
                        <label for="search" class="form-label">Search</label>
                        <input type="text" class="form-control" id="search" name="search" 
                               value="<?php echo htmlspecialchars($search_term); ?>" 
                               placeholder="Search entries or comments...">
                    </div>
                    
                    <div class="col-md-3">
                        <label class="form-label">&nbsp;</label>
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> Search
                            </button>
                            <a href="edl_viewer.php" class="btn btn-outline-secondary">
                                <i class="fas fa-times"></i> Clear
                            </a>
                        </div>
                    </div>
                </form>
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
                    <div class="col-md-3">
                        <a href="../edl-files/ip_blocklist.txt" target="_blank" class="btn btn-primary w-100 mb-2">
                            <i class="fas fa-download me-2"></i> Download IP List
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="../edl-files/domain_blocklist.txt" target="_blank" class="btn btn-success w-100 mb-2">
                            <i class="fas fa-download me-2"></i> Download Domain List
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="../edl-files/url_blocklist.txt" target="_blank" class="btn btn-info w-100 mb-2">
                            <i class="fas fa-download me-2"></i> Download URL List
                        </a>
                    </div>
                    <div class="col-md-3">
                        <button onclick="exportToCSV()" class="btn btn-secondary w-100 mb-2">
                            <i class="fas fa-file-csv me-2"></i> Export CSV
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- EDL Entries Table -->
        <div class="card">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="fas fa-table me-2"></i> EDL Entries
                </h5>
                <small class="text-muted">
                    Showing <?php echo number_format($offset + 1); ?>-<?php echo number_format(min($offset + $per_page, $total_entries)); ?> 
                    of <?php echo number_format($total_entries); ?> entries
                </small>
            </div>
            <div class="card-body">
                <?php if (empty($paged_entries)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-search fa-3x text-muted mb-3"></i>
                        <h4>No Entries Found</h4>
                        <p class="text-muted">No EDL entries match your current filters.</p>
                        <a href="edl_viewer.php" class="btn btn-primary">
                            <i class="fas fa-undo"></i> Clear Filters
                        </a>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover" id="edlTable">
                            <thead>
                                <tr>
                                    <th>Entry</th>
                                    <th>Type</th>
                                    <th>Comment</th>
                                    <th>Submitted By</th>
                                    <th>Date Added</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($paged_entries as $entry): ?>
                                    <tr>
                                        <td>
                                            <code class="user-select-all"><?php echo htmlspecialchars($entry['entry'] ?? ''); ?></code>
                                        </td>
                                        <td>
                                            <?php
                                            $type = $entry['type'] ?? 'unknown';
                                            $icons = [
                                                'ip' => 'fas fa-network-wired',
                                                'domain' => 'fas fa-globe', 
                                                'url' => 'fas fa-link'
                                            ];
                                            $icon = $icons[$type] ?? 'fas fa-question-circle';
                                            ?>
                                            <span class="badge bg-secondary">
                                                <i class="<?php echo $icon; ?>"></i>
                                                <?php echo strtoupper($type); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="text-truncate d-inline-block" style="max-width: 200px;" 
                                                  title="<?php echo htmlspecialchars($entry['comment'] ?? ''); ?>">
                                                <?php echo htmlspecialchars($entry['comment'] ?? 'No comment'); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($entry['submitted_by'] ?? 'Unknown'); ?></td>
                                        <td>
                                            <small>
                                                <?php 
                                                $time = isset($entry['submitted_at']) ? strtotime($entry['submitted_at']) : false;
                                                echo $time ? date('Y-m-d H:i', $time) : 'Unknown';
                                                ?>
                                            </small>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-info" 
                                                        onclick="copyToClipboard('<?php echo htmlspecialchars($entry['entry'] ?? ''); ?>')"
                                                        title="Copy to clipboard">
                                                    <i class="fas fa-copy"></i>
                                                </button>
                                                <button type="button" class="btn btn-outline-primary" 
                                                        data-bs-toggle="modal" 
                                                        data-bs-target="#detailModal<?php echo md5($entry['id'] ?? uniqid()); ?>"
                                                        title="View details">
                                                    <i class="fas fa-eye"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="EDL entries pagination" class="mt-3">
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
    <?php foreach ($paged_entries as $entry): 
        $modal_id = md5($entry['id'] ?? uniqid());
    ?>
        <div class="modal fade" id="detailModal<?php echo $modal_id; ?>" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Entry Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Entry Information</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>Entry:</strong></td>
                                        <td><code class="user-select-all"><?php echo htmlspecialchars($entry['entry'] ?? ''); ?></code></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Type:</strong></td>
                                        <td>
                                            <?php
                                            $type = $entry['type'] ?? 'unknown';
                                            $icons = [
                                                'ip' => 'fas fa-network-wired',
                                                'domain' => 'fas fa-globe', 
                                                'url' => 'fas fa-link'
                                            ];
                                            $icon = $icons[$type] ?? 'fas fa-question-circle';
                                            ?>
                                            <span class="badge bg-secondary">
                                                <i class="<?php echo $icon; ?>"></i>
                                                <?php echo strtoupper($type); ?>
                                            </span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><strong>Status:</strong></td>
                                        <td>
                                            <span class="badge bg-success">
                                                <?php echo ucfirst($entry['status'] ?? 'active'); ?>
                                            </span>
                                        </td>
                                    </tr>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6>Submission Details</h6>
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>Submitted By:</strong></td>
                                        <td><?php echo htmlspecialchars($entry['submitted_by'] ?? 'Unknown'); ?></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Submitted At:</strong></td>
                                        <td>
                                            <?php 
                                            $time = isset($entry['submitted_at']) ? strtotime($entry['submitted_at']) : false;
                                            echo $time ? date('Y-m-d H:i:s', $time) : 'Unknown';
                                            ?>
                                        </td>
                                    </tr>
                                    <?php if (isset($entry['approved_by']) && $entry['approved_by']): ?>
                                    <tr>
                                        <td><strong>Approved By:</strong></td>
                                        <td><?php echo htmlspecialchars($entry['approved_by']); ?></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Approved At:</strong></td>
                                        <td>
                                            <?php 
                                            $time = isset($entry['approved_at']) ? strtotime($entry['approved_at']) : false;
                                            echo $time ? date('Y-m-d H:i:s', $time) : 'Unknown';
                                            ?>
                                        </td>
                                    </tr>
                                    <?php endif; ?>
                                </table>
                            </div>
                        </div>
                        
                        <?php if (!empty($entry['comment'])): ?>
                            <div class="row mt-3">
                                <div class="col-12">
                                    <h6>Comment</h6>
                                    <div class="bg-light p-3 rounded">
                                        <?php echo nl2br(htmlspecialchars($entry['comment'])); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($entry['justification'])): ?>
                            <div class="row mt-3">
                                <div class="col-12">
                                    <h6>Business Justification</h6>
                                    <div class="bg-light p-3 rounded">
                                        <?php echo nl2br(htmlspecialchars($entry['justification'])); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="copyToClipboard('<?php echo htmlspecialchars($entry['entry'] ?? ''); ?>')">
                            <i class="fas fa-copy"></i> Copy Entry
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
        
        // Export to CSV
        function exportToCSV() {
            const table = document.getElementById('edlTable');
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
            link.download = 'edl_entries_' + new Date().toISOString().split('T')[0] + '.csv';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
            
            showNotification('EDL entries exported to CSV', 'success');
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
        });
    </script>
</body>
</html>