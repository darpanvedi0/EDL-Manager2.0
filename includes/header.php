<?php
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
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="<?php echo $base_path; ?>index.php">
                <i class="fas fa-shield-alt"></i>
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
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    
                    <?php if (has_permission('submit')): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'submit_request.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>submit_request.php">
                            <i class="fas fa-plus"></i> Submit Request
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <?php if (has_permission('approve')): ?>
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'approvals.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>approvals.php">
                            <i class="fas fa-check-circle"></i> Approvals
                            <?php
                            $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
                            $pending_count = count(array_filter($pending_requests, fn($r) => $r['status'] === 'pending'));
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
                            <i class="fas fa-history"></i> My Requests
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) === 'edl_viewer.php' ? 'active' : ''; ?>" 
                           href="<?php echo $is_in_pages ? '' : 'pages/'; ?>edl_viewer.php">
                            <i class="fas fa-list"></i> EDL Viewer
                        </a>
                    </li>
                    
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-download"></i> Downloads
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/ip_blocklist.txt" target="_blank">
                                <i class="fas fa-network-wired"></i> IP Blocklist
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/domain_blocklist.txt" target="_blank">
                                <i class="fas fa-globe"></i> Domain Blocklist
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>edl-files/url_blocklist.txt" target="_blank">
                                <i class="fas fa-link"></i> URL Blocklist
                            </a></li>
                        </ul>
                    </li>
                    
                    <?php if (has_permission('manage')): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-cog"></i> Admin
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="<?php echo $is_in_pages ? '' : 'pages/'; ?>denied_entries.php">
                                <i class="fas fa-ban"></i> Denied Entries
                            </a></li>
                            <li><a class="dropdown-item" href="<?php echo $is_in_pages ? '' : 'pages/'; ?>audit_log.php">
                                <i class="fas fa-clipboard-list"></i> Audit Log
                            </a></li>
                        </ul>
                    </li>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav">
                    <!-- Dark Mode Toggle -->
                    <li class="nav-item">
                        <div class="theme-toggle">
                            <i class="fas fa-sun theme-icon"></i>
                            <label class="theme-switch">
                                <input type="checkbox" id="themeToggle">
                                <span class="theme-slider"></span>
                            </label>
                            <i class="fas fa-moon theme-icon"></i>
                        </div>
                    </li>
                    
                    <!-- User Menu -->
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i>
                            <?php echo htmlspecialchars($_SESSION['name']); ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li class="dropdown-item-text">
                                <div class="fw-bold"><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                                <small class="text-muted"><?php echo htmlspecialchars($_SESSION['email']); ?></small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li class="dropdown-item-text">
                                <small class="text-muted">
                                    Role: <span class="badge bg-primary"><?php echo ucfirst($_SESSION['role']); ?></span>
                                </small>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="<?php echo $base_path; ?>logout.php">
                                <i class="fas fa-sign-out-alt"></i> Logout
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
            <i class="<?php echo $icon; ?>"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Main Content Container -->
    <main class="py-4">