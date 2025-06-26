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
                $removed_entry = null;
                
                foreach ($denied_entries as $key => $entry) {
                    if ($entry['id'] === $entry_id) {
                        $removed_entry = $entry;
                        
                        // Add audit log before removal
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
                        
                        // Remove the entry from array
                        unset($denied_entries[$key]);
                        $removed = true;
                        break;
                    }
                }
                
                if ($removed && $removed_entry) {
                    // Reindex array and save
                    $denied_entries_reindexed = array_values($denied_entries);
                    if (write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries_reindexed)) {
                        show_flash("Entry '{$removed_entry['entry']}' removed from denied list successfully.", 'success');
                        header('Location: denied_entries.php');
                        exit;
                    } else {
                        $error_message = 'Failed to update denied entries file. Please check file permissions.';
                    }
                } else {
                    $error_message = 'Entry not found in denied list.';
                }
            } else {
                $error_message = 'Invalid entry ID provided.';
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
                } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                    $type = 'ip';
                } else {
                    $type = 'domain';
                }
            }
            
            if (empty($errors)) {
                $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
                
                // Check if already denied
                $already_denied = false;
                foreach ($denied_entries as $existing) {
                    if ($existing['entry'] === $entry && $existing['type'] === $type) {
                        $already_denied = true;
                        break;
                    }
                }
                
                if (!$already_denied) {
                    $new_denial = [
                        'id' => uniqid('denied_', true),
                        'entry' => $entry,
                        'type' => $type,
                        'reason' => $reason,
                        'denied_by' => $_SESSION['username'],
                        'denied_at' => date('c'),
                        'source' => 'manual'
                    ];
                    
                    $denied_entries[] = $new_denial;
                    
                    if (write_json_file(DATA_DIR . '/denied_entries.json', $denied_entries)) {
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
                        
                        show_flash("Entry '{$entry}' added to denied list successfully.", 'success');
                        header('Location: denied_entries.php');
                        exit;
                    } else {
                        $error_message = 'Failed to save denied entries file. Please check file permissions.';
                    }
                } else {
                    $error_message = 'This entry is already in the denied list.';
                }
            } else {
                $error_message = implode(', ', $errors);
            }
        }
    }
}

// Load denied entries
$denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');

// Calculate statistics
$stats = [
    'total_denied' => count($denied_entries),
    'ip_count' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'ip')),
    'domain_count' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'domain')),
    'url_count' => count(array_filter($denied_entries, fn($e) => $e['type'] === 'url'))
];

// Include the centralized header
require_once '../includes/header.php';
?>

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

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo $error_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

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
                        <h3 class="fw-bold mb-1"><?php echo $stats['ip_count']; ?></h3>
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
                        <h3 class="fw-bold mb-1"><?php echo $stats['domain_count']; ?></h3>
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
                        <h3 class="fw-bold mb-1"><?php echo $stats['url_count']; ?></h3>
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

<!-- Admin Actions -->
<?php if ($is_admin): ?>
<div class="card mb-4">
    <div class="card-header bg-light">
        <h5 class="mb-0">
            <i class="fas fa-plus me-2"></i>
            Add Manual Denial
        </h5>
    </div>
    <div class="card-body">
        <form method="post" class="needs-validation" novalidate>
            <input type="hidden" name="action" value="add_manual_denial">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            
            <div class="row g-3">
                <div class="col-md-4">
                    <label for="entry" class="form-label">Entry <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="entry" name="entry" 
                           placeholder="192.168.1.100, malicious.com, or https://bad-site.com" required>
                </div>
                <div class="col-md-2">
                    <label for="type" class="form-label">Type</label>
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
                <p class="text-muted">No entries have been denied yet.</p>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Entry</th>
                            <th>Type</th>
                            <th>Reason</th>
                            <th>Denied By</th>
                            <th>Date</th>
                            <th>Source</th>
                            <?php if ($is_admin): ?>
                            <th width="100">Actions</th>
                            <?php endif; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($denied_entries as $entry): ?>
                        <tr class="denied-entry">
                            <td>
                                <code class="text-danger"><?php echo htmlspecialchars($entry['entry']); ?></code>
                            </td>
                            <td>
                                <span class="badge bg-secondary">
                                    <i class="fas fa-<?php 
                                        echo $entry['type'] === 'ip' ? 'network-wired' : 
                                             ($entry['type'] === 'domain' ? 'globe' : 'link'); 
                                    ?> me-1"></i>
                                    <?php echo strtoupper($entry['type']); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($entry['reason'] ?? 'No reason provided'); ?></td>
                            <td><?php echo htmlspecialchars($entry['denied_by'] ?? 'System'); ?></td>
                            <td>
                                <small class="text-muted">
                                    <?php echo date('M j, Y H:i', strtotime($entry['denied_at'] ?? '')); ?>
                                </small>
                            </td>
                            <td>
                                <span class="badge bg-<?php echo ($entry['source'] ?? '') === 'manual' ? 'warning' : 'info'; ?>">
                                    <?php echo ucfirst($entry['source'] ?? 'auto'); ?>
                                </span>
                            </td>
                            <?php if ($is_admin): ?>
                            <td>
                                <form method="post" class="d-inline" 
                                      onsubmit="return confirm('Remove this entry from the denied list? It will become available for submission again.');">
                                    <input type="hidden" name="action" value="remove_denial">
                                    <input type="hidden" name="entry_id" value="<?php echo $entry['id']; ?>">
                                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-success" 
                                            title="Remove from denied list">
                                        <i class="fas fa-undo"></i>
                                    </button>
                                </form>
                            </td>
                            <?php endif; ?>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
// Form validation
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

// Auto-detect entry type
document.getElementById('entry')?.addEventListener('input', function() {
    const entry = this.value.trim();
    const typeSelect = document.getElementById('type');
    
    if (entry && typeSelect.value === 'auto') {
        if (/^https?:\/\//.test(entry)) {
            typeSelect.value = 'url';
        } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(entry)) {
            typeSelect.value = 'ip';
        } else if (/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/.test(entry)) {
            typeSelect.value = 'domain';
        }
    }
});
</script>

<?php require_once '../includes/footer.php'; ?>