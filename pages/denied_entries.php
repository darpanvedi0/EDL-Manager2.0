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

<script>
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
</script>

</div>
<!-- End container -->

<?php require_once '../includes/footer.php'; ?>