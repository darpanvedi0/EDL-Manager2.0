<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/validation.php';

// Load Teams notifications if file exists (optional)
if (file_exists('../includes/teams_notifications.php')) {
    require_once '../includes/teams_notifications.php';
}

$auth = new EDLAuth();
$auth->require_permission('submit');

$page_title = 'Submit Request';
$error_message = '';
$success_message = '';

// Enhanced ServiceNow ticket validation function
function validate_servicenow_ticket_enhanced($ticket) {
    if (empty($ticket)) {
        return ['valid' => false, 'error' => 'ServiceNow ticket is required'];
    }
    
    $pattern = '/^(INC|REQ|CHG|RITM|TASK|SCTASK|SIR)[0-9]{7}$/';
    if (!preg_match($pattern, $ticket)) {
        return ['valid' => false, 'error' => 'Invalid ServiceNow ticket format. Use: INC1234567, REQ1234567, CHG1234567, SIR1234567, etc.'];
    }
    
    return ['valid' => true, 'type' => 'ServiceNow Ticket'];
}

// Function to parse bulk entries from uploaded file or text
function parse_bulk_entries($content) {
    $entries = [];
    $lines = explode("\n", $content);
    
    foreach ($lines as $line_num => $line) {
        $line = trim($line);
        
        // Skip empty lines and comments
        if (empty($line) || str_starts_with($line, '#') || str_starts_with($line, '//')) {
            continue;
        }
        
        // Auto-detect type
        if (preg_match('/^https?:\/\//', $line)) {
            $type = 'url';
        } elseif (filter_var($line, FILTER_VALIDATE_IP)) {
            $type = 'ip';
        } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $line)) {
            $type = 'domain';
        } else {
            $type = 'unknown';
        }
        
        $entries[] = [
            'entry' => $line,
            'type' => $type,
            'line_number' => $line_num + 1
        ];
    }
    
    return $entries;
}

// Function to process entry existence check results from validation.php
function process_entry_check($entry, $type) {
    $check_result = check_entry_exists($entry, $type);
    
    if (!$check_result['exists']) {
        return ['exists' => false];
    }
    
    $location = $check_result['location'];
    
    if ($location === 'denied') {
        return [
            'exists' => true,
            'status' => 'denied',
            'details' => [
                'reason' => $check_result['denied_reason'] ?? 'No reason provided'
            ]
        ];
    } elseif ($location === 'approved') {
        return [
            'exists' => true,
            'status' => 'approved',
            'details' => []
        ];
    } elseif ($location === 'pending') {
        return [
            'exists' => true,
            'status' => 'pending',
            'details' => []
        ];
    }
    
    return ['exists' => false];
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $submission_type = sanitize_input($_POST['submission_type'] ?? 'individual');
        $justification = sanitize_input($_POST['justification'] ?? '');
        $priority = sanitize_input($_POST['priority'] ?? 'medium');
        $servicenow_ticket = sanitize_input($_POST['servicenow_ticket'] ?? '');
        $comment = sanitize_input($_POST['comment'] ?? '');
        
        $errors = [];
        $entries_to_submit = [];
        
        // Validate common required fields
        if (empty($justification)) $errors[] = 'Justification is required';
        if (empty($servicenow_ticket)) $errors[] = 'ServiceNow ticket is required';
        
        // Validate ServiceNow ticket format
        if (!empty($servicenow_ticket)) {
            $snow_validation = validate_servicenow_ticket_enhanced($servicenow_ticket);
            if (!$snow_validation['valid']) {
                $errors[] = $snow_validation['error'];
            }
        }
        
        if ($submission_type === 'individual') {
            // Handle individual entry submission (existing logic)
            $entry = sanitize_input($_POST['entry'] ?? '');
            $type = sanitize_input($_POST['type'] ?? '');
            
            if (empty($entry)) $errors[] = 'Entry is required';
            
            // Auto-detect type if not specified
            if (empty($type) || $type === 'auto') {
                if (preg_match('/^https?:\/\//', $entry)) {
                    $type = 'url';
                } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                    $type = 'ip';
                } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $entry)) {
                    $type = 'domain';
                } else {
                    $errors[] = 'Could not determine entry type. Please select manually.';
                }
            }
            
            // Check if entry already exists
            if (!empty($entry) && !empty($type)) {
                $exists_check = process_entry_check($entry, $type);
                if ($exists_check['exists']) {
                    $details = $exists_check['details'] ?? [];
                    if ($exists_check['status'] === 'denied') {
                        $errors[] = "⚠️ This entry was previously DENIED. Reason: {$details['reason']}";
                    } elseif ($exists_check['status'] === 'approved') {
                        $errors[] = "This entry is already approved and active in the blocklist.";
                    } elseif ($exists_check['status'] === 'pending') {
                        $errors[] = "This entry is already pending approval.";
                    }
                }
            }
            
            if (empty($errors) && !empty($entry)) {
                $entries_to_submit[] = [
                    'entry' => $entry,
                    'type' => $type,
                    'submitted_by' => $_SESSION['username']
                ];
            }
            
        } elseif ($submission_type === 'bulk') {
            // Handle bulk submission
            $bulk_content = '';
            
            if (isset($_FILES['bulk_file']) && $_FILES['bulk_file']['error'] === UPLOAD_ERR_OK) {
                // Handle file upload
                $file_info = $_FILES['bulk_file'];
                $allowed_types = ['text/plain', 'text/csv', 'application/csv'];
                $max_size = 5 * 1024 * 1024; // 5MB
                
                if ($file_info['size'] > $max_size) {
                    $errors[] = 'File size too large. Maximum 5MB allowed.';
                } elseif (!in_array($file_info['type'], $allowed_types)) {
                    $errors[] = 'Invalid file type. Only .txt and .csv files are allowed.';
                } else {
                    $bulk_content = file_get_contents($file_info['tmp_name']);
                }
            } elseif (!empty($_POST['bulk_text'])) {
                // Handle text area input
                $bulk_content = sanitize_input($_POST['bulk_text']);
            } else {
                $errors[] = 'Please provide entries either via file upload or text input.';
            }
            
            if (!empty($bulk_content) && empty($errors)) {
                $parsed_entries = parse_bulk_entries($bulk_content);
                
                if (empty($parsed_entries)) {
                    $errors[] = 'No valid entries found in the provided content.';
                } else {
                    $duplicate_count = 0;
                    $invalid_count = 0;
                    $denied_count = 0;
                    
                    foreach ($parsed_entries as $parsed_entry) {
                        if ($parsed_entry['type'] === 'unknown') {
                            $invalid_count++;
                            continue;
                        }
                        
                        $exists_check = process_entry_check($parsed_entry['entry'], $parsed_entry['type']);
                        if ($exists_check['exists']) {
                            if ($exists_check['status'] === 'denied') {
                                $denied_count++;
                            } else {
                                $duplicate_count++;
                            }
                            continue;
                        }
                        
                        $parsed_entry['submitted_by'] = $_SESSION['username'];
                        $entries_to_submit[] = $parsed_entry;
                    }
                    
                    // Show summary of skipped entries
                    $summary_messages = [];
                    if ($duplicate_count > 0) {
                        $summary_messages[] = "{$duplicate_count} duplicate/existing entries skipped";
                    }
                    if ($invalid_count > 0) {
                        $summary_messages[] = "{$invalid_count} invalid entries skipped";
                    }
                    if ($denied_count > 0) {
                        $summary_messages[] = "{$denied_count} previously denied entries skipped";
                    }
                    
                    if (!empty($summary_messages)) {
                        $success_message = implode(', ', $summary_messages) . '. ';
                    }
                    
                    if (empty($entries_to_submit)) {
                        $errors[] = 'No new valid entries to submit after filtering duplicates and invalid entries.';
                    }
                }
            }
        }
        
        // Submit valid entries
        if (empty($errors) && !empty($entries_to_submit)) {
            $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
            $submitted_count = 0;
            
            foreach ($entries_to_submit as $entry_data) {
                $request = [
                    'id' => uniqid(),
                    'entry' => $entry_data['entry'],
                    'type' => $entry_data['type'],
                    'justification' => $justification,
                    'comment' => $comment,
                    'priority' => $priority,
                    'servicenow_ticket' => $servicenow_ticket,
                    'submitted_by' => $_SESSION['username'],
                    'submitted_at' => date('Y-m-d H:i:s'),
                    'status' => 'pending',
                    'submission_type' => $submission_type
                ];
                
                $pending_requests[] = $request;
                $submitted_count++;
            }
            
            if (write_json_file(DATA_DIR . '/pending_requests.json', $pending_requests)) {
                // Log audit entry
                $audit_entry = [
                    'timestamp' => date('Y-m-d H:i:s'),
                    'user' => $_SESSION['username'],
                    'action' => $submission_type === 'bulk' ? 'bulk_request_submitted' : 'request_submitted',
                    'details' => $submission_type === 'bulk' ? 
                        "Submitted {$submitted_count} entries in bulk" : 
                        "Submitted entry: {$entries_to_submit[0]['entry']}",
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
                ];
                
                $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                $audit_logs[] = $audit_entry;
                write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                
                // Send Teams notification if available
                if (function_exists('send_teams_notification')) {
                    if ($submission_type === 'bulk') {
                        // Send bulk notification
                        if (function_exists('notify_teams_bulk_submitted')) {
                            notify_teams_bulk_submitted($entries_to_submit, $_SESSION['username']);
                        }
                    } else {
                        // Send individual notification
                        send_teams_notification('new_request', $entries_to_submit[0]);
                    }
                }
                
                if ($submission_type === 'bulk') {
                    $success_message .= "Successfully submitted {$submitted_count} entries for review.";
                } else {
                    $success_message .= 'Request submitted successfully! You will be notified when reviewed.';
                }
                
                show_flash($success_message, 'success');
                header('Location: submit_request.php');
                exit;
            } else {
                $error_message = 'Failed to save request(s). Please try again.';
            }
        } else {
            $error_message = implode('<br>', $errors);
        }
    }
}

// Get user's recent requests
$user_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$user_requests = array_filter($user_requests, function($r) {
    return $r['submitted_by'] === $_SESSION['username'];
});
$user_requests = array_slice(array_reverse($user_requests), 0, 5);

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

<?php if ($success_message): ?>
<div class="alert alert-success alert-dismissible fade show">
    <i class="fas fa-check-circle"></i>
    <?php echo $success_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-plus me-2"></i>
        Submit EDL Request
    </h1>
    <p class="mb-0 opacity-75">Submit individual entries or bulk upload for review and approval to the External Dynamic List</p>
</div>

<!-- Submission Type Toggle -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card">
            <div class="card-body">
                <div class="btn-group w-100" role="group" aria-label="Submission Type">
                    <input type="radio" class="btn-check" name="submission_type_radio" id="individual_radio" value="individual" checked>
                    <label class="btn btn-outline-primary" for="individual_radio">
                        <i class="fas fa-plus-circle me-1"></i> Individual Entry
                    </label>
                    
                    <input type="radio" class="btn-check" name="submission_type_radio" id="bulk_radio" value="bulk">
                    <label class="btn btn-outline-primary" for="bulk_radio">
                        <i class="fas fa-upload me-1"></i> Bulk Upload
                    </label>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Form -->
<div class="row">
    <div class="col-lg-8">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">
                    <i class="fas fa-edit me-1"></i> Request Information
                </h5>
            </div>
            <div class="card-body">
                <form method="POST" class="needs-validation" novalidate enctype="multipart/form-data">
                    <?php echo csrf_token_field(); ?>
                    
                    <!-- Hidden field to track submission type -->
                    <input type="hidden" name="submission_type" id="submission_type" value="individual">
                    
                    <!-- Individual Entry Section -->
                    <div id="individual_section">
                        <div class="row mb-3">
                            <div class="col-md-8">
                                <label for="entry" class="form-label fw-bold">Entry <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="entry" name="entry" 
                                       value="<?php echo htmlspecialchars($_POST['entry'] ?? ''); ?>"
                                       placeholder="e.g., 192.168.1.100, malicious.com, or https://bad-site.com">
                                <div class="form-text">Enter the IP address, domain, or URL to be blocked</div>
                            </div>
                            <div class="col-md-4">
                                <label for="type" class="form-label fw-bold">Type</label>
                                <select class="form-select" id="type" name="type">
                                    <option value="auto" <?php echo ($_POST['type'] ?? '') === 'auto' ? 'selected' : ''; ?>>Auto-detect</option>
                                    <option value="ip" <?php echo ($_POST['type'] ?? '') === 'ip' ? 'selected' : ''; ?>>IP Address</option>
                                    <option value="domain" <?php echo ($_POST['type'] ?? '') === 'domain' ? 'selected' : ''; ?>>Domain</option>
                                    <option value="url" <?php echo ($_POST['type'] ?? '') === 'url' ? 'selected' : ''; ?>>URL</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Bulk Upload Section -->
                    <div id="bulk_section" style="display: none;">
                        <div class="mb-3">
                            <label class="form-label fw-bold">Bulk Entry Method</label>
                            <div class="btn-group w-100" role="group">
                                <input type="radio" class="btn-check" name="bulk_method" id="file_upload" value="file" checked>
                                <label class="btn btn-outline-secondary" for="file_upload">
                                    <i class="fas fa-file-upload me-1"></i> File Upload
                                </label>
                                
                                <input type="radio" class="btn-check" name="bulk_method" id="text_input" value="text">
                                <label class="btn btn-outline-secondary" for="text_input">
                                    <i class="fas fa-keyboard me-1"></i> Text Input
                                </label>
                            </div>
                        </div>
                        
                        <!-- File Upload -->
                        <div id="file_upload_section" class="mb-3">
                            <label for="bulk_file" class="form-label fw-bold">Upload File</label>
                            <input type="file" class="form-control" id="bulk_file" name="bulk_file" 
                                   accept=".txt,.csv" aria-describedby="fileHelp">
                            <div id="fileHelp" class="form-text">
                                Upload a .txt or .csv file containing one entry per line. Maximum file size: 5MB
                            </div>
                        </div>
                        
                        <!-- Text Input -->
                        <div id="text_input_section" class="mb-3" style="display: none;">
                            <label for="bulk_text" class="form-label fw-bold">Bulk Entries</label>
                            <textarea class="form-control" id="bulk_text" name="bulk_text" rows="10" 
                                      placeholder="Enter one entry per line:&#10;192.168.1.100&#10;malicious.com&#10;https://bad-site.com/malware&#10;&#10;# Comments and empty lines will be ignored"><?php echo htmlspecialchars($_POST['bulk_text'] ?? ''); ?></textarea>
                            <div class="form-text">Enter one entry per line. Comments starting with # will be ignored.</div>
                        </div>
                        
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-1"></i>
                            <strong>Bulk Upload Notes:</strong>
                            <ul class="mb-0 mt-2">
                                <li>Each entry will be auto-detected as IP, domain, or URL</li>
                                <li>Duplicate and invalid entries will be automatically skipped</li>
                                <li>Comments (lines starting with #) and empty lines are ignored</li>
                                <li>All entries will share the same justification and ServiceNow ticket</li>
                            </ul>
                        </div>
                    </div>
                    
                    <!-- Common Fields -->
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label for="priority" class="form-label fw-bold">Priority</label>
                            <select class="form-select" id="priority" name="priority">
                                <option value="low" <?php echo ($_POST['priority'] ?? 'medium') === 'low' ? 'selected' : ''; ?>>🔵 Low</option>
                                <option value="medium" <?php echo ($_POST['priority'] ?? 'medium') === 'medium' ? 'selected' : ''; ?>>🟡 Medium</option>
                                <option value="high" <?php echo ($_POST['priority'] ?? 'medium') === 'high' ? 'selected' : ''; ?>>🟠 High</option>
                                <option value="critical" <?php echo ($_POST['priority'] ?? 'medium') === 'critical' ? 'selected' : ''; ?>>🔴 Critical</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label for="servicenow_ticket" class="form-label fw-bold">ServiceNow Ticket <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="servicenow_ticket" name="servicenow_ticket" 
                                   value="<?php echo htmlspecialchars($_POST['servicenow_ticket'] ?? ''); ?>"
                                   placeholder="e.g., INC1234567, REQ1234567, SIR1234567"
                                   required>
                            <div class="form-text">Required for audit and tracking purposes</div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="justification" class="form-label fw-bold">Justification <span class="text-danger">*</span></label>
                        <textarea class="form-control" id="justification" name="justification" rows="3" 
                                  placeholder="Explain why this entry/these entries should be blocked..."
                                  required><?php echo htmlspecialchars($_POST['justification'] ?? ''); ?></textarea>
                        <div class="form-text">Provide a clear business justification for blocking</div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="comment" class="form-label fw-bold">Additional Comments</label>
                        <textarea class="form-control" id="comment" name="comment" rows="2" 
                                  placeholder="Any additional context or technical details..."><?php echo htmlspecialchars($_POST['comment'] ?? ''); ?></textarea>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <a href="../index.php" class="btn btn-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Dashboard
                            </a>
                        </div>
                        <div class="col-md-6 text-end">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-paper-plane"></i> <span id="submit_button_text">Submit Request</span>
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-lg-4">
        <!-- Guidelines -->
        <div class="card">
            <div class="card-header bg-light">
                <h6 class="mb-0">
                    <i class="fas fa-info-circle text-info"></i> Entry Format Examples
                </h6>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <h6><i class="fas fa-network-wired text-primary"></i> IP Address:</h6>
                    <code class="small d-block">192.168.1.100</code>
                    <code class="small d-block">10.0.0.0/24</code>
                    <code class="small d-block">2001:db8::1</code>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-globe text-success"></i> Domain:</h6>
                    <code class="small d-block">malicious.com</code>
                    <code class="small d-block">*.suspicious.net</code>
                    <code class="small d-block">bad-domain.org</code>
                </div>
                
                <div class="mb-3">
                    <h6><i class="fas fa-link text-warning"></i> URL:</h6>
                    <code class="small d-block">https://bad-site.com/malware</code>
                    <code class="small d-block">http://phishing.net/login</code>
                </div>
                
                <div class="alert alert-warning small">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Note:</strong> All entries are subject to approval. Duplicates and previously denied entries will be automatically filtered.
                </div>
            </div>
        </div>
        
        <!-- Recent Requests -->
        <?php if (!empty($user_requests)): ?>
        <div class="card mt-4">
            <div class="card-header bg-light">
                <h6 class="mb-0">
                    <i class="fas fa-clock text-secondary"></i> Your Recent Requests
                </h6>
            </div>
            <div class="card-body">
                <?php foreach ($user_requests as $request): ?>
                <div class="d-flex justify-content-between align-items-center py-2 border-bottom">
                    <div>
                        <div class="fw-bold small">
                            <?php echo htmlspecialchars($request['entry']); ?>
                        </div>
                        <small class="text-muted">
                            <?php echo format_datetime($request['submitted_at'], 'M j, H:i'); ?>
                        </small>
                    </div>
                    <span class="badge bg-warning">Pending</span>
                </div>
                <?php endforeach; ?>
                
                <div class="text-center mt-3">
                    <a href="edl_viewer.php?filter=pending" class="btn btn-sm btn-outline-primary">
                        View All Pending
                    </a>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<script>
// Submission type toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    const individualRadio = document.getElementById('individual_radio');
    const bulkRadio = document.getElementById('bulk_radio');
    const individualSection = document.getElementById('individual_section');
    const bulkSection = document.getElementById('bulk_section');
    const submissionTypeField = document.getElementById('submission_type');
    const submitButtonText = document.getElementById('submit_button_text');
    const entryField = document.getElementById('entry');
    
    // Bulk method toggle
    const fileUploadRadio = document.getElementById('file_upload');
    const textInputRadio = document.getElementById('text_input');
    const fileUploadSection = document.getElementById('file_upload_section');
    const textInputSection = document.getElementById('text_input_section');
    
    function toggleSubmissionType() {
        if (bulkRadio.checked) {
            individualSection.style.display = 'none';
            bulkSection.style.display = 'block';
            submissionTypeField.value = 'bulk';
            submitButtonText.textContent = 'Submit Bulk Request';
            if (entryField) entryField.removeAttribute('required');
        } else {
            individualSection.style.display = 'block';
            bulkSection.style.display = 'none';
            submissionTypeField.value = 'individual';
            submitButtonText.textContent = 'Submit Request';
            if (entryField) entryField.setAttribute('required', 'required');
        }
    }
    
    function toggleBulkMethod() {
        if (textInputRadio.checked) {
            fileUploadSection.style.display = 'none';
            textInputSection.style.display = 'block';
        } else {
            fileUploadSection.style.display = 'block';
            textInputSection.style.display = 'none';
        }
    }
    
    individualRadio.addEventListener('change', toggleSubmissionType);
    bulkRadio.addEventListener('change', toggleSubmissionType);
    fileUploadRadio.addEventListener('change', toggleBulkMethod);
    textInputRadio.addEventListener('change', toggleBulkMethod);
    
    // Initialize state
    toggleSubmissionType();
    toggleBulkMethod();
});

// ServiceNow ticket validation
document.getElementById('servicenow_ticket')?.addEventListener('input', function() {
    const ticket = this.value.trim().toUpperCase();
    const pattern = /^(INC|REQ|CHG|RITM|TASK|SCTASK|SIR)[0-9]{7}$/;
    
    if (ticket && !pattern.test(ticket)) {
        this.classList.add('is-invalid');
        
        // Create feedback element
        const feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = 'Invalid format. Use: INC1234567, REQ1234567, CHG1234567, SIR1234567, etc.';
        
        // Remove existing feedback
        const existingFeedback = this.parentNode.querySelector('.invalid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }
        
        this.parentNode.appendChild(feedback);
    } else {
        this.classList.remove('is-invalid');
        // Remove feedback
        const existingFeedback = this.parentNode.querySelector('.invalid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }
    }
});

// Auto-detect entry type for individual entries
document.getElementById('entry')?.addEventListener('input', function() {
    const entry = this.value.trim();
    const typeSelect = document.getElementById('type');
    
    if (entry && typeSelect.value === 'auto') {
        if (/^https?:\/\//.test(entry)) {
            typeSelect.value = 'url';
        } else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(entry)) {
            typeSelect.value = 'ip';
        } else if (/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/.test(entry)) {
            typeSelect.value = 'domain';
        }
    }
});

// Bootstrap form validation
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
</script>

<?php require_once '../includes/footer.php'; ?>
