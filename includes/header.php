<?php
// includes/header.php - Complete Fixed Version
// Determine correct paths
$is_in_pages = strpos($_SERVER['PHP_SELF'], '/pages/') !== false;
$base_path = $is_in_pages ? '../' : '';

// Get flash message
$flash = get_flash();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? $page_title . ' - ' . APP_NAME : APP_NAME; ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="<?php echo $base_path; ?>assets/css/style.css" rel="stylesheet">
    
    <meta name="description" content="EDL Manager - External Dynamic List Management">
    <meta name="robots" content="noindex, nofollow">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand fw-bold" href="<?php echo $base_path; ?>index.php">
                <i class="fas fa-shield-alt me-2"></i>
                <?php echo APP_NAME; ?>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'index.php' ? 'active' : ''; ?>" 
                           href="<?php echo $base_path; ?>index.php">
                            <i class="fas fa-tachometer-alt me-1"></i> Dashboard
                        </a>
                    </li>
                    
                    <?php if (has_permission('submit')): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'submit_request.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>submit_request.php">
                            <i class="fas fa-plus me-1"></i> Submit Request
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <?php if (has_permission('approve')): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'approvals.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>approvals.php">
                            <i class="fas fa-check-circle me-1"></i> Approvals
                            <?php
                            $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
                            $pending_count = count(array_filter($pending_requests, fn($r) => ($r['status'] ?? '') === 'pending'));
                            if ($pending_count > 0):
                            ?>
                                <span class="badge bg-warning text-dark pending-count"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'request_history.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>request_history.php">
                            <i class="fas fa-history me-1"></i> My Requests
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'edl_viewer.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>edl_viewer.php">
                            <i class="fas fa-list me-1"></i> EDL Viewer
                        </a>
                    </li>
                    
                    <!-- Downloads Dropdown -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="downloadsDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-download me-1"></i> Downloads
                        </a>
                        <ul class="dropdown-menu" aria-labelledby="downloadsDropdown">
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-shield-alt text-primary me-1"></i> Blocklist Files
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/ip_blocklist.txt" target="_blank">
                                <i class="fas fa-network-wired text-primary me-2"></i> IP Blocklist
                                <small class="text-muted d-block">List of blocked IP addresses</small>
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/domain_blocklist.txt" target="_blank">
                                <i class="fas fa-globe text-success me-2"></i> Domain Blocklist
                                <small class="text-muted d-block">List of blocked domains</small>
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/url_blocklist.txt" target="_blank">
                                <i class="fas fa-link text-info me-2"></i> URL Blocklist
                                <small class="text-muted d-block">List of blocked URLs</small>
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-tools text-secondary me-1"></i> Tools
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="#" onclick="downloadAllFiles()">
                                <i class="fas fa-download text-warning me-2"></i> Download All Files
                                <small class="text-muted d-block">ZIP archive of all blocklists</small>
                            </a></li>
                            <li><a class="dropdown-item" href="#" onclick="copyApiUrls()">
                                <i class="fas fa-code text-secondary me-2"></i> Copy API URLs
                                <small class="text-muted d-block">Direct URLs for automation</small>
                            </a></li>
                        </ul>
                    </li>
                    
                    <?php if (has_permission('manage')): ?>
                    <!-- Admin Dropdown -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle <?php echo in_array(basename($_SERVER['PHP_SELF']), ['okta_config.php', 'denied_entries.php', 'audit_log.php']) ? 'active' : ''; ?>" 
                           href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu" aria-labelledby="adminDropdown">
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-shield-alt text-primary me-1"></i> System Management
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'okta_config.php' ? 'active' : ''; ?>" 
                                   href="<?php echo $is_in_pages ? '' : 'pages/'; ?>okta_config.php">
                                <i class="fas fa-cloud text-primary me-2"></i> Okta SSO Configuration
                                <small class="text-muted d-block">Configure Single Sign-On</small>
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-database text-secondary me-1"></i> Data Management
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'denied_entries.php' ? 'active' : ''; ?>" 
                                   href="<?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                                <i class="fas fa-ban text-danger me-2"></i> Denied Entries
                                <small class="text-muted d-block">View rejected requests</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'audit_log.php' ? 'active' : ''; ?>" 
                                   href="<?php echo $is_in_pages ? '' : 'pages/'; ?>audit_log.php">
                                <i class="fas fa-clipboard-list text-info me-2"></i> Audit Log
                                <small class="text-muted d-block">System activity log</small>
                            </a></li>
                            <?php if (has_permission('audit')): ?>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-tools text-warning me-1"></i> System Tools
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="#" onclick="regenerateEDLFiles()">
                                <i class="fas fa-sync text-warning me-2"></i> Regenerate EDL Files
                                <small class="text-muted d-block">Rebuild all blocklist files</small>
                            </a></li>
                            <li><a class="dropdown-item" href="#" onclick="exportSystemData()">
                                <i class="fas fa-file-export text-success me-2"></i> Export System Data
                                <small class="text-muted d-block">Backup configuration</small>
                            </a></li>
                            <?php endif; ?>
                        </ul>
                    </li>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav">
                    <!-- User Menu -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-user me-1"></i>
                            <?php echo htmlspecialchars($_SESSION['name'] ?? $_SESSION['username'] ?? 'User'); ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li class="dropdown-item-text">
                                <div class="fw-bold"><?php echo htmlspecialchars($_SESSION['username'] ?? 'Unknown'); ?></div>
                                <small class="text-muted"><?php echo htmlspecialchars($_SESSION['email'] ?? 'No email'); ?></small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li class="dropdown-item-text">
                                <small class="text-muted">
                                    Role: <span class="badge bg-primary"><?php echo ucfirst($_SESSION['role'] ?? 'user'); ?></span>
                                    <?php if (isset($_SESSION['login_method'])): ?>
                                    <br>Login: <span class="badge bg-secondary"><?php echo ucfirst($_SESSION['login_method']); ?></span>
                                    <?php endif; ?>
                                </small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i> Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <!-- Flash Messages -->
    <?php if ($flash): ?>
    <div class="container mt-3">
        <div class="alert alert-<?php echo $flash['type']; ?> alert-dismissible fade show">
            <?php
            $icons = [
                'success' => 'fas fa-check-circle',
                'danger' => 'fas fa-exclamation-triangle',
                'warning' => 'fas fa-exclamation-circle',
                'info' => 'fas fa-info-circle'
            ];
            $icon = $icons[$flash['type']] ?? $icons['info'];
            ?>
            <i class="<?php echo $icon; ?> me-2"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Main Content Container -->
    <main class="py-4">
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Download all files as ZIP
        function downloadAllFiles() {
            const files = [
                '<?php echo $base_path; ?>edl-files/ip_blocklist.txt',
                '<?php echo $base_path; ?>edl-files/domain_blocklist.txt',
                '<?php echo $base_path; ?>edl-files/url_blocklist.txt'
            ];
            
            files.forEach((url, index) => {
                setTimeout(() => {
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = url.split('/').pop();
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }, index * 500);
            });
            
            showNotification('Downloading all EDL files...', 'info');
        }
        
        // Copy API URLs to clipboard
        function copyApiUrls() {
            const baseUrl = window.location.origin + '<?php echo $base_path; ?>';
            const urls = [
                'IP Blocklist: ' + baseUrl + 'edl-files/ip_blocklist.txt',
                'Domain Blocklist: ' + baseUrl + 'edl-files/domain_blocklist.txt',
                'URL Blocklist: ' + baseUrl + 'edl-files/url_blocklist.txt'
            ].join('\n');
            
            if (navigator.clipboard) {
                navigator.clipboard.writeText(urls).then(() => {
                    showNotification('API URLs copied to clipboard', 'success');
                });
            } else {
                const textArea = document.createElement('textarea');
                textArea.value = urls;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showNotification('API URLs copied to clipboard', 'success');
            }
        }
        
        // Regenerate EDL files
        function regenerateEDLFiles() {
            if (confirm('This will regenerate all EDL files from approved entries. Continue?')) {
                fetch('<?php echo $base_path; ?>api/regenerate_edl.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showNotification('EDL files regenerated successfully', 'success');
                    } else {
                        showNotification('Failed to regenerate EDL files: ' + data.error, 'danger');
                    }
                })
                .catch(error => {
                    showNotification('Error regenerating EDL files', 'danger');
                });
            }
        }
        
        // Export system data
        function exportSystemData() {
            const link = document.createElement('a');
            link.href = '<?php echo $base_path; ?>api/export_data.php';
            link.download = 'edl_manager_backup_' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showNotification('Exporting system data...', 'info');
        }
        
        // Show notification
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
            }, 4000);
        }
        
        // Auto-refresh pending count every 30 seconds
        setInterval(() => {
            fetch('<?php echo $base_path; ?>api/get_stats.php')
                .then(response => response.json())
                .then(data => {
                    if (data.pending !== undefined) {
                        const pendingElements = document.querySelectorAll('.pending-count');
                        pendingElements.forEach(el => {
                            el.textContent = data.pending;
                            el.style.display = data.pending > 0 ? 'inline' : 'none';
                        });
                    }
                })
                .catch(error => console.warn('Failed to update stats:', error));
        }, 30000);
    </script>