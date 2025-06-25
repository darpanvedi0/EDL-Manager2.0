<?php
// includes/header.php - Master Template with SSL Config and Standardized Navigation
// Determine correct paths
$is_in_pages = strpos($_SERVER['PHP_SELF'], '/pages/') !== false;
$is_in_api = strpos($_SERVER['PHP_SELF'], '/api/') !== false;
$is_in_okta = strpos($_SERVER['PHP_SELF'], '/okta/') !== false;

// Calculate base path
if ($is_in_pages) {
    $base_path = '../';
} elseif ($is_in_api) {
    $base_path = '../';
} elseif ($is_in_okta) {
    $base_path = '../';
} else {
    $base_path = '';
}

// Get flash message
$flash = get_flash();

// Get pending requests count for nav badge
$pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
$pending_count = count(array_filter($pending_requests, fn($r) => ($r['status'] ?? '') === 'pending'));

// Ensure session variables are set
$user_name = $_SESSION['name'] ?? $_SESSION['username'] ?? 'User';
$user_username = $_SESSION['username'] ?? 'unknown';
$user_email = $_SESSION['email'] ?? 'user@company.com';
$user_role = $_SESSION['role'] ?? 'user';
$user_permissions = $_SESSION['permissions'] ?? [];

// Determine current page for active navigation highlighting
$current_page = basename($_SERVER['PHP_SELF']);
$current_dir = basename(dirname($_SERVER['PHP_SELF']));

// Navigation helper function
function isActive($page_name, $current_page, $current_dir = '') {
    if ($current_page === $page_name) {
        return 'active';
    }
    // Special cases for pages in subdirectories
    if ($current_dir === 'pages' && $page_name === $current_page) {
        return 'active';
    }
    return '';
}

// Admin pages for dropdown highlighting
$admin_pages = ['okta_config.php', 'teams_config.php', 'ssl_config.php', 'audit_log.php', 'user_management.php'];
$is_admin_page_active = in_array($current_page, $admin_pages);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? $page_title . ' - ' . APP_NAME : APP_NAME; ?></title>
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
        .alert-danger {
            border-left-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
        }
        .alert-warning {
            border-left-color: #ffc107;
            background-color: rgba(255, 193, 7, 0.1);
        }
        .alert-info {
            border-left-color: #0dcaf0;
            background-color: rgba(13, 202, 240, 0.1);
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
        .priority-critical { border-left: 4px solid #dc3545; }
        .priority-high { border-left: 4px solid #fd7e14; }
        .priority-medium { border-left: 4px solid #ffc107; }
        .priority-low { border-left: 4px solid #28a745; }
        .request-card {
            transition: all 0.3s ease;
            border-radius: 10px;
        }
        .request-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        .denied-entry {
            border-left: 4px solid #dc3545;
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
        .status-indicator {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 50px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        .status-enabled {
            background-color: rgba(25, 135, 84, 0.1);
            color: #198754;
        }
        .status-disabled {
            background-color: rgba(220, 53, 69, 0.1);
            color: #dc3545;
        }
        .teams-section, .ssl-section, .group-mapping-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #0078D4;
        }
        .ssl-section {
            border-left-color: #28a745;
        }
        .group-mapping-section {
            border-left-color: #007bff;
        }
        .webhook-preview, .config-preview {
            background: #1e1e1e;
            color: #ffffff;
            border-radius: 10px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
        .teams-card, .ssl-card {
            background: linear-gradient(135deg, #0078D4 0%, #005a9e 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        .ssl-card {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }
        .pending-count {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
        
        /* Navigation Enhancements */
        .navbar-brand {
            font-weight: 700;
            font-size: 1.25rem;
        }
        
        .nav-link {
            transition: all 0.3s ease;
            border-radius: 5px;
            margin: 0 2px;
        }
        
        .nav-link:hover {
            background-color: rgba(255,255,255,0.1);
            transform: translateY(-1px);
        }
        
        .nav-link.active {
            background-color: rgba(255,255,255,0.2);
            font-weight: 600;
        }
        
        /* Enhanced Dropdown Menus */
        .dropdown-menu {
            border: none;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            padding: 0.5rem 0;
            min-width: 300px;
            animation: dropdownFadeIn 0.3s ease;
        }
        
        @keyframes dropdownFadeIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .dropdown-header {
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 0.5rem 1rem;
            margin-bottom: 0.25rem;
            border-bottom: 1px solid #e9ecef;
        }
        
        .dropdown-item {
            padding: 0.75rem 1rem;
            transition: all 0.2s ease;
            border-radius: 5px;
            margin: 2px 8px;
        }
        
        .dropdown-item:hover {
            background-color: #f8f9fa;
            transform: translateX(5px);
        }
        
        .dropdown-item.active {
            background-color: #007bff;
            color: white;
        }
        
        .dropdown-item small {
            display: block;
            font-size: 0.75rem;
            opacity: 0.7;
            margin-top: 2px;
        }
        
        .dropdown-divider {
            margin: 0.5rem 0;
            border-color: #e9ecef;
        }
        
        /* Role-based styling */
        .role-admin { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
        .role-approver { background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); }
        .role-operator { background: linear-gradient(135deg, #ffc107 0%, #d39e00 100%); color: #212529; }
        .role-viewer { background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); }
    </style>
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
                    <!-- Dashboard - Always visible -->
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('index.php', $current_page); ?>" href="<?php echo $base_path; ?>index.php">
                            <i class="fas fa-tachometer-alt me-1"></i> Dashboard
                        </a>
                    </li>
                    
                    <!-- Submit Request - For users with submit permission -->
                    <?php if (in_array('submit', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('submit_request.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>submit_request.php">
                            <i class="fas fa-plus me-1"></i> Submit Request
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <!-- Approvals - For users with approve permission -->
                    <?php if (in_array('approve', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('approvals.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>approvals.php">
                            <i class="fas fa-check-circle me-1"></i> Approvals
                            <?php if ($pending_count > 0): ?>
                                <span class="badge bg-warning text-dark pending-count ms-1"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <!-- My Requests - For authenticated users -->
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('request_history.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>request_history.php">
                            <i class="fas fa-history me-1"></i> My Requests
                        </a>
                    </li>
                    
                    <!-- EDL Viewer - Always visible to authenticated users -->
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('edl_viewer.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>edl_viewer.php">
                            <i class="fas fa-list me-1"></i> EDL Viewer
                        </a>
                    </li>
                    
                    <!-- Denied Entries - Always visible to authenticated users -->
                    <li class="nav-item">
                        <a class="nav-link <?php echo isActive('denied_entries.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                            <i class="fas fa-ban me-1"></i> Denied Entries
                        </a>
                    </li>
                    
                    <!-- Admin Dropdown - For users with manage permission -->
                    <?php if (in_array('manage', $user_permissions)): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle <?php echo $is_admin_page_active ? 'active' : ''; ?>" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu" aria-labelledby="adminDropdown">
                            <!-- Integration Section -->
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-server text-primary me-1"></i> Integration & Security
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo isActive('okta_config.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>okta_config.php">
                                <i class="fas fa-cloud text-primary me-2"></i> Okta SSO Configuration
                                <small class="text-muted d-block">Configure Single Sign-On authentication</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo isActive('teams_config.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>teams_config.php">
                                <i class="fab fa-microsoft text-info me-2"></i> Teams Notifications
                                <small class="text-muted d-block">Configure Microsoft Teams webhooks</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo isActive('ssl_config.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>ssl_config.php">
                                <i class="fas fa-lock text-success me-2"></i> SSL/TLS Configuration
                                <small class="text-muted d-block">Configure HTTPS and certificates</small>
                            </a></li>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- Data Management Section -->
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-database text-secondary me-1"></i> Data Management
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo isActive('denied_entries.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                                <i class="fas fa-ban text-danger me-2"></i> Denied Entries
                                <small class="text-muted d-block">Manage rejected requests</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo isActive('audit_log.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>audit_log.php">
                                <i class="fas fa-clipboard-list text-warning me-2"></i> Audit Log
                                <small class="text-muted d-block">View system activity and logs</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo isActive('user_management.php', $current_page); ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>user_management.php">
                                <i class="fas fa-users text-success me-2"></i> User Management
                                <small class="text-muted d-block">Manage local user accounts</small>
                            </a></li>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- System Tools Section -->
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-tools text-info me-1"></i> System Tools
                                </h6>
                            </li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>api/export_data.php" target="_blank">
                                <i class="fas fa-download text-primary me-2"></i> Export Data
                                <small class="text-muted d-block">Download system backup</small>
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>api/regenerate_edl.php" onclick="return confirm('Regenerate EDL files from approved entries?')">
                                <i class="fas fa-sync text-warning me-2"></i> Regenerate EDL Files
                                <small class="text-muted d-block">Rebuild blocklist files</small>
                            </a></li>
                        </ul>
                    </li>
                    <?php endif; ?>
                </ul>
                
                <!-- User Menu -->
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-user me-1"></i>
                            <?php echo htmlspecialchars($user_name); ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <!-- User Info -->
                            <li class="dropdown-item-text">
                                <div class="d-flex align-items-center">
                                    <div class="me-3">
                                        <i class="fas fa-user-circle fa-2x text-muted"></i>
                                    </div>
                                    <div>
                                        <div class="fw-bold"><?php echo htmlspecialchars($user_username); ?></div>
                                        <small class="text-muted"><?php echo htmlspecialchars($user_email); ?></small>
                                    </div>
                                </div>
                            </li>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- Role and Permissions -->
                            <li class="dropdown-item-text">
                                <div class="d-flex justify-content-between align-items-center">
                                    <small class="text-muted">Role:</small>
                                    <span class="badge role-<?php echo $user_role; ?>"><?php echo ucfirst($user_role); ?></span>
                                </div>
                                <?php if (isset($_SESSION['login_method'])): ?>
                                <div class="d-flex justify-content-between align-items-center mt-1">
                                    <small class="text-muted">Login:</small>
                                    <span class="badge bg-secondary"><?php echo ucfirst(str_replace('_', ' ', $_SESSION['login_method'])); ?></span>
                                </div>
                                <?php endif; ?>
                                <div class="mt-2">
                                    <small class="text-muted d-block">Permissions:</small>
                                    <div class="d-flex flex-wrap gap-1 mt-1">
                                        <?php foreach ($user_permissions as $permission): ?>
                                            <span class="badge bg-light text-dark" style="font-size: 0.65rem;"><?php echo ucfirst($permission); ?></span>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </li>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- Session Info -->
                            <li class="dropdown-item-text">
                                <small class="text-muted">
                                    <i class="fas fa-clock me-1"></i>
                                    Logged in: <?php echo date('M j, H:i', $_SESSION['login_time'] ?? time()); ?>
                                </small>
                            </li>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- Quick Actions -->
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>edl_viewer.php">
                                <i class="fas fa-list text-info me-2"></i> View EDL Files
                            </a></li>
                            <?php if (in_array('submit', $user_permissions)): ?>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>submit_request.php">
                                <i class="fas fa-plus text-success me-2"></i> New Request
                            </a></li>
                            <?php endif; ?>
                            
                            <li><hr class="dropdown-divider"></li>
                            
                            <!-- Logout -->
                            <li><a class="dropdown-item text-danger" href="<?php echo $base_path; ?>logout.php">
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