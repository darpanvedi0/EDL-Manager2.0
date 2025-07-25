<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_auth();

$page_title = 'EDL Viewer';
$error_message = '';
$success_message = '';

$is_admin = has_permission('manage');

// Handle delete action (Admin only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $is_admin) {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'delete_entry') {
            $entry_id = sanitize_input($_POST['entry_id'] ?? '');
            if (!empty($entry_id)) {
                $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
                $entry_deleted = false;
                $deleted_entry = null;
                
                foreach ($approved_entries as $key => $entry) {
                    if ($entry['id'] === $entry_id && $entry['status'] === 'active') {
                        $deleted_entry = $entry;
                        
                        // Mark as deleted instead of removing completely (for audit purposes)
                        $approved_entries[$key]['status'] = 'deleted';
                        $approved_entries[$key]['deleted_by'] = $_SESSION['username'];
                        $approved_entries[$key]['deleted_at'] = date('c');
                        
                        $entry_deleted = true;
                        break;
                    }
                }
                
                if ($entry_deleted && $deleted_entry) {
                    // Save updated approved entries JSON
                    if (write_json_file(DATA_DIR . '/approved_entries.json', $approved_entries)) {
                        // Regenerate EDL files (this will exclude deleted entries)
                        $regenerate_result = regenerate_edl_files();
                        
                        // Add audit log
                        $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                        $audit_logs[] = [
                            'id' => uniqid('audit_', true),
                            'timestamp' => date('c'),
                            'action' => 'delete_entry',
                            'entry' => $deleted_entry['entry'],
                            'user' => $_SESSION['username'],
                            'details' => "Deleted {$deleted_entry['type']} entry from active EDL",
                            'admin_comment' => "Entry removed from blocklist and marked as deleted"
                        ];
                        write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                        
                        show_flash("Entry deleted successfully and removed from EDL files. Updated files: IP({$regenerate_result['ip_count']}), Domain({$regenerate_result['domain_count']}), URL({$regenerate_result['url_count']})", 'success');
                        header('Location: edl_viewer.php');
                        exit;
                    } else {
                        $error_message = 'Failed to update JSON file. Please check file permissions.';
                    }
                } else {
                    $error_message = 'Entry not found or already deleted.';
                }
            } else {
                $error_message = 'Invalid entry ID provided.';
            }
        }
    }
}

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

// Helper function to regenerate EDL files
function regenerate_edl_files() {
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $active_entries = array_filter($approved_entries, function($e) {
        return isset($e['status']) && $e['status'] === 'active';
    });
    
    $ip_list = [];
    $domain_list = [];
    $url_list = [];
    
    foreach ($active_entries as $entry) {
        switch ($entry['type'] ?? '') {
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
    
    // Ensure EDL files directory exists
    if (!is_dir(EDL_FILES_DIR)) {
        mkdir(EDL_FILES_DIR, 0755, true);
    }
    
    // Write EDL files with error checking
    $ip_result = file_put_contents(EDL_FILES_DIR . '/ip_blocklist.txt', implode("\n", $ip_list));
    $domain_result = file_put_contents(EDL_FILES_DIR . '/domain_blocklist.txt', implode("\n", $domain_list));
    $url_result = file_put_contents(EDL_FILES_DIR . '/url_blocklist.txt', implode("\n", $url_list));
    
    if ($ip_result === false || $domain_result === false || $url_result === false) {
        error_log('Failed to write EDL files in edl_viewer.php');
    }
    
    return [
        'ip_count' => count($ip_list),
        'domain_count' => count($domain_list),
        'url_count' => count($url_list),
        'total_active' => count($active_entries)
    ];
}

// Include the centralized header
require_once '../includes/header.php';
?>

<div class="container mt-4">

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo htmlspecialchars($error_message); ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-list me-2"></i>
        EDL Viewer<?php echo $is_admin ? ' & Management' : ''; ?>
    </h1>
    <p class="mb-0 opacity-75">
        <?php if ($is_admin): ?>
            View, search, and manage External Dynamic List entries
        <?php else: ?>
            View and search External Dynamic List entries
        <?php endif; ?>
    </p>
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
        <?php if ($is_admin): ?>
        <div class="alert alert-info mt-3">
            <i class="fas fa-user-shield"></i>
            <strong>Admin Actions:</strong> You can delete entries from the EDL. Deleted entries are marked as inactive and removed from all blocklist files.
        </div>
        <?php endif; ?>
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
                                        <?php if ($is_admin): ?>
                                        <button type="button" class="btn btn-outline-danger" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#deleteModal<?php echo md5($entry['id'] ?? uniqid()); ?>"
                                                title="Delete entry">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                        <?php endif; ?>
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
    
    <!-- Delete Modal (Admin Only) -->
    <?php if ($is_admin): ?>
    <div class="modal fade" id="deleteModal<?php echo $modal_id; ?>" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-trash text-danger"></i> Delete EDL Entry
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                        <input type="hidden" name="action" value="delete_entry">
                        <input type="hidden" name="entry_id" value="<?php echo htmlspecialchars($entry['id'] ?? ''); ?>">
                        
                        <div class="alert alert-danger">
                            <h6 class="alert-heading">
                                <i class="fas fa-exclamation-triangle"></i> Confirm Deletion
                            </h6>
                            <hr>
                            <div class="row">
                                <div class="col-sm-3"><strong>Entry:</strong></div>
                                <div class="col-sm-9"><code><?php echo htmlspecialchars($entry['entry'] ?? ''); ?></code></div>
                            </div>
                            <div class="row">
                                <div class="col-sm-3"><strong>Type:</strong></div>
                                <div class="col-sm-9"><?php echo strtoupper($entry['type'] ?? 'unknown'); ?></div>
                            </div>
                            <div class="row">
                                <div class="col-sm-3"><strong>Submitted:</strong></div>
                                <div class="col-sm-9"><?php echo htmlspecialchars($entry['submitted_by'] ?? 'Unknown'); ?></div>
                            </div>
                        </div>
                        
                        <div class="bg-light p-3 rounded">
                            <p class="mb-0 text-danger">
                                <i class="fas fa-exclamation-triangle"></i>
                                <strong>Warning:</strong> This action will:
                            </p>
                            <ul class="mb-0 mt-2">
                                <li>Mark the entry as <strong>deleted</strong> in the JSON database</li>
                                <li>Remove it from all EDL text files</li>
                                <li>Remove it from firewall blocklists</li>
                                <li>Create an audit log entry</li>
                                <li>Keep the record for audit purposes</li>
                            </ul>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-trash"></i> Delete Entry
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
<?php endforeach; ?>

<script>
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

// Show notification function
function showNotification(message, type = 'info') {
    const alertClass = 'alert-' + type;
    const notification = document.createElement('div');
    notification.className = `alert ${alertClass} alert-dismissible position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    
    const icons = {
        'success': 'fas fa-check-circle',
        'danger': 'fas fa-exclamation-triangle',
        'warning': 'fas fa-exclamation-circle',
        'info': 'fas fa-info-circle'
    };
    const icon = icons[type] || icons['info'];
    
    notification.innerHTML = `
        <i class="${icon} me-2"></i>
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

</div>
<!-- End container -->

<?php require_once '../includes/footer.php'; ?>