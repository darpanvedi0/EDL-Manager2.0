<?php
// includes/header.php - Master Template based on index.php
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
        .teams-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #0078D4;
        }
        .webhook-preview {
            background: #1e1e1e;
            color: #ffffff;
            border-radius: 10px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
        .teams-card {
            background: linear-gradient(135deg, #0078D4 0%, #005a9e 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        .group-mapping-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #007bff;
        }
        .pending-count {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
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
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'index.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?>index.php">
                            <i class="fas fa-tachometer-alt me-1"></i> Dashboard
                        </a>
                    </li>
                    <?php if (in_array('submit', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'submit_request.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>submit_request.php">
                            <i class="fas fa-plus me-1"></i> Submit Request
                        </a>
                    </li>
                    <?php endif; ?>
                    <?php if (in_array('approve', $user_permissions)): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'approvals.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>approvals.php">
                            <i class="fas fa-check-circle me-1"></i> Approvals
                            <?php if ($pending_count > 0): ?>
                                <span class="badge bg-warning text-dark pending-count"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'request_history.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>request_history.php">
                            <i class="fas fa-history me-1"></i> My Requests
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'edl_viewer.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>edl_viewer.php">
                            <i class="fas fa-list me-1"></i> EDL Viewer
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'denied_entries.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                            <i class="fas fa-ban me-1"></i> Denied Entries
                        </a>
                    </li>
                    <?php if (in_array('manage', $user_permissions)): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle <?php echo in_array(basename($_SERVER['PHP_SELF']), ['okta_config.php', 'teams_config.php', 'audit_log.php', 'user_management.php']) ? 'active' : ''; ?>" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-cog me-1"></i> Admin
                        </a>
                        <ul class="dropdown-menu" aria-labelledby="adminDropdown">
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-server text-primary me-1"></i> Integration
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'okta_config.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>okta_config.php">
                                <i class="fas fa-cloud text-primary me-2"></i> Okta SSO Configuration
                                <small class="text-muted d-block">Configure Single Sign-On</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'teams_config.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>teams_config.php">
                                <i class="fab fa-microsoft text-info me-2"></i> Teams Notifications
                                <small class="text-muted d-block">Configure Teams webhooks</small>
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="fas fa-database text-secondary me-1"></i> Data Management
                                </h6>
                            </li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'denied_entries.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                                <i class="fas fa-ban text-danger me-2"></i> Denied Entries
                                <small class="text-muted d-block">View rejected requests</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'audit_log.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>audit_log.php">
                                <i class="fas fa-clipboard-list text-warning me-2"></i> Audit Log
                                <small class="text-muted d-block">System activity log</small>
                            </a></li>
                            <li><a class="dropdown-item <?php echo basename($_SERVER['PHP_SELF']) === 'user_management.php' ? 'active' : ''; ?>" href="<?php echo $base_path; ?><?php echo $is_in_pages ? '' : 'pages/'; ?>user_management.php">
                                <i class="fas fa-users text-success me-2"></i> User Management
                                <small class="text-muted d-block">Manage local accounts</small>
                            </a></li>
                        </ul>
                    </li>
                    <?php endif; ?>
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