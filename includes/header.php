<?php
// includes/header.php - Master Template with Reduced Navigation Spacing + Favicon
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
$admin_pages = ['okta_config.php', 'teams_config.php', 'ssl_config.php', 'audit_log.php'];
$is_admin_page_active = in_array($current_page, $admin_pages);

// Generate base64 encoded security shield favicon
$favicon_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
    <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea"/>
            <stop offset="100%" style="stop-color:#764ba2"/>
        </linearGradient>
    </defs>
    <path d="M16 2L6 6v8c0 6.5 4.2 12.6 10 14.8 5.8-2.2 10-8.3 10-14.8V6L16 2z" fill="url(#shieldGradient)" stroke="#fff" stroke-width="1"/>
    <path d="M16 8c-2.2 0-4 1.8-4 4v2h-1v6h10v-6h-1v-2c0-2.2-1.8-4-4-4zm0 2c1.1 0 2 0.9 2 2v2h-4v-2c0-1.1 0.9-2 2-2z" fill="#fff"/>
</svg>';
$favicon_base64 = 'data:image/svg+xml;base64,' . base64_encode($favicon_svg);

// Generate ICO format for better browser support
$favicon_ico_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
    <defs>
        <linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea"/>
            <stop offset="100%" style="stop-color:#764ba2"/>
        </linearGradient>
    </defs>
    <path d="M8 1L3 3v4c0 3.25 2.1 6.3 5 7.4 2.9-1.1 5-4.15 5-7.4V3L8 1z" fill="url(#sg)" stroke="#fff" stroke-width="0.5"/>
    <path d="M8 4c-1.1 0-2 0.9-2 2v1h-0.5v3h5v-3H10V6c0-1.1-0.9-2-2-2zm0 1c0.55 0 1 0.45 1 1v1H7V6c0-0.55 0.45-1 1-1z" fill="#fff"/>
</svg>';
$favicon_ico_base64 = 'data:image/svg+xml;base64,' . base64_encode($favicon_ico_svg);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? $page_title . ' - ' . APP_NAME : APP_NAME; ?></title>
    
    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="<?php echo $favicon_base64; ?>">
    <link rel="icon" type="image/png" href="<?php echo $favicon_ico_base64; ?>">
    <link rel="shortcut icon" href="<?php echo $favicon_ico_base64; ?>">
    <link rel="apple-touch-icon" href="<?php echo $favicon_base64; ?>">
    <meta name="theme-color" content="#667eea">
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    
    <!-- Custom CSS -->
    <link rel="stylesheet" href="<?php echo $base_path; ?>assets/css/style.css">
    
    <style>
        /* Force light theme override */
        body {
            background-color: #f8f9fa !important;
            color: #212529 !important;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .card {
            background-color: white !important;
            color: #212529 !important;
        }
        
        /* FIXED Navigation Container Alignment with Reduced Spacing */
        .navbar {
            padding: 0.75rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .navbar-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 15px;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        /* Brand positioning */
        .navbar-brand {
            font-size: 1.3rem;
            font-weight: 600;
            letter-spacing: -0.5px;
            padding: 0.5rem 0;
            margin-right: 0;
            white-space: nowrap;
            flex-shrink: 0;
        }
        
        .navbar-brand i {
            font-size: 1.2rem;
            margin-right: 8px;
        }
        
        /* Main navigation centering with reduced spacing */
        .navbar-nav-center {
            display: flex;
            justify-content: center;
            flex-grow: 1;
            margin: 0 1rem; /* Reduced from 2rem */
        }
        
        .navbar-nav-center .navbar-nav {
            display: flex;
            align-items: center;
            gap: 0; /* Removed gap */
        }
        
        /* User navigation - always right */
        .navbar-nav-right {
            flex-shrink: 0;
            margin-left: auto;
        }
        
        .navbar-nav .nav-item {
            margin: 0; /* Reduced from 0 1px */
        }
        
        .navbar-nav .nav-link {
            font-size: 0.925rem;
            font-weight: 500;
            padding: 0.75rem 0.75rem !important; /* Reduced from 1rem */
            border-radius: 6px;
            transition: all 0.2s ease;
            color: rgba(255,255,255,0.9) !important;
            letter-spacing: 0.02em;
            white-space: nowrap;
            display: flex;
            align-items: center;
            margin: 0 2px; /* Added small margin between items */
        }
        
        .navbar-nav .nav-link:hover {
            background-color: rgba(255,255,255,0.1);
            color: white !important;
            transform: translateY(-1px);
        }
        
        .navbar-nav .nav-link.active {
            background-color: rgba(255,255,255,0.15);
            color: white !important;
            font-weight: 600;
        }
        
        .navbar-nav .nav-link i {
            font-size: 0.875rem;
            margin-right: 6px; /* Reduced from 8px */
            width: 16px;
            text-align: center;
            flex-shrink: 0;
        }
        
        /* Mobile hamburger positioning */
        .navbar-toggler {
            order: 2;
            margin-left: 1rem;
        }
        
        /* Mobile navigation */
        .navbar-collapse {
            order: 3;
            flex-basis: 100%;
        }
        
        /* Dropdown Menu Professional Styling */
        .dropdown-menu {
            background-color: white !important;
            color: #212529 !important;
            border: none;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            border-radius: 8px;
            padding: 0.5rem 0;
            margin-top: 0.5rem;
            min-width: 280px;
        }
        
        .dropdown-item {
            color: #212529 !important;
            padding: 0.75rem 1.25rem;
            font-size: 0.9rem;
            transition: all 0.2s ease;
            border: none;
        }
        
        .dropdown-item:hover {
            background-color: #f8f9fa !important;
            color: #212529 !important;
            padding-left: 1.5rem;
        }
        
        .dropdown-item.active {
            background-color: #e3f2fd !important;
            color: #1976d2 !important;
            font-weight: 600;
        }
        
        .dropdown-item i {
            width: 20px;
            text-align: center;
            margin-right: 8px;
        }
        
        .dropdown-item small {
            font-size: 0.8rem;
            margin-top: 2px;
            opacity: 0.7;
        }
        
        .dropdown-header {
            font-weight: 600;
            color: #6c757d;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            padding: 0.5rem 1.25rem 0.25rem;
            margin-bottom: 0.25rem;
        }
        
        .dropdown-divider {
            margin: 0.5rem 0;
            opacity: 0.1;
        }
        
        /* Badge Styling */
        .pending-count {
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            animation: pulse 2s infinite;
            margin-left: 4px;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        /* Role Badge Professional Styling */
        .role-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            font-size: 0.7rem;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-left: 6px;
        }
        
        /* Role-based styling */
        .role-admin { 
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
            color: white;
        }
        .role-approver { 
            background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); 
            color: white;
        }
        .role-operator { 
            background: linear-gradient(135deg, #ffc107 0%, #d39e00 100%); 
            color: #212529; 
        }
        .role-viewer { 
            background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); 
            color: white;
        }
        
        /* User Dropdown Styling */
        .navbar-nav .nav-link.dropdown-toggle::after {
            margin-left: 0.5rem;
        }
        
        /* Restore Stat Card Colors */
        .stat-card.bg-primary,
        .bg-primary {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%) !important;
            color: white !important;
        }
        
        .stat-card.bg-success,
        .bg-success {
            background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%) !important;
            color: white !important;
        }
        
        .stat-card.bg-info,
        .bg-info {
            background: linear-gradient(135deg, #17a2b8 0%, #117a8b 100%) !important;
            color: white !important;
        }
        
        .stat-card.bg-warning,
        .bg-warning {
            background: linear-gradient(135deg, #ffc107 0%, #d39e00 100%) !important;
            color: #212529 !important;
        }
        
        .stat-card.bg-danger,
        .bg-danger {
            background: linear-gradient(135deg, #dc3545 0%, #bd2130 100%) !important;
            color: white !important;
        }
        
        /* Page Header - Professional Purple Gradient */
        .page-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
            color: white !important;
            border-radius: 12px;
            padding: 2.5rem 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        
        .page-header h1 {
            margin-bottom: 0.5rem;
            font-weight: 300;
            font-size: 2.25rem;
            letter-spacing: -0.5px;
        }
        
        .page-header .opacity-75 {
            opacity: 0.85;
            font-size: 1.1rem;
        }
        
        /* Container spacing improvements */
        .container {
            max-width: 1200px;
        }
        
        /* Main content container alignment */
        .main-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 15px;
        }
        
        /* Responsive improvements */
        @media (max-width: 1200px) {
            .navbar-container {
                padding: 0 20px;
            }
            
            .main-container {
                padding: 0 20px;
            }
            
            .navbar-nav .nav-link {
                padding: 0.6rem 0.6rem !important; /* Adjusted for smaller screens */
                font-size: 0.9rem;
            }
            
            .navbar-nav-center {
                margin: 0 0.5rem; /* Further reduced for smaller screens */
            }
        }
        
        @media (max-width: 992px) {
            .navbar-nav .nav-link {
                padding: 0.5rem 0.75rem !important;
            }
            
            .dropdown-menu {
                min-width: 250px;
            }
            
            .navbar-nav-center {
                flex-direction: column;
                margin: 1rem 0;
            }
            
            .navbar-nav-right {
                margin-left: 0;
                margin-top: 1rem;
            }
            
            .navbar-collapse {
                text-align: center;
            }
        }
        
        @media (max-width: 768px) {
            .navbar-brand {
                font-size: 1.2rem;
            }
            
            .page-header {
                padding: 1.5rem 1rem;
            }
            
            .page-header h1 {
                font-size: 1.75rem;
            }
            
            .navbar-container {
                padding: 0 15px;
            }
            
            .main-container {
                padding: 0 15px;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="navbar-container">
            <!-- Brand -->
            <a class="navbar-brand" href="<?php echo $base_path; ?>index.php">
                <i class="fas fa-shield-alt"></i>
                <?php echo APP_NAME; ?>
            </a>
            
            <!-- Mobile toggle button -->
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <!-- Collapsible content -->
            <div class="collapse navbar-collapse" id="navbarNav">
                <!-- Centered main navigation -->
                <div class="navbar-nav-center">
                    <ul class="navbar-nav">
                        <!-- Dashboard - Always visible -->
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('index.php', $current_page); ?>" href="<?php echo $base_path; ?>index.php">
                                <i class="fas fa-tachometer-alt"></i>Dashboard
                            </a>
                        </li>
                        
                        <!-- Submit Request - For users with submit permission -->
                        <?php if (in_array('submit', $user_permissions)): ?>
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('submit_request.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'submit_request.php' : 'pages/submit_request.php'; ?>">
                                <i class="fas fa-plus"></i>Submit Request
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <!-- Approvals - For users with approve permission -->
                        <?php if (in_array('approve', $user_permissions)): ?>
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('approvals.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'approvals.php' : 'pages/approvals.php'; ?>">
                                <i class="fas fa-check-circle"></i>Approvals
                                <?php if ($pending_count > 0): ?>
                                    <span class="badge bg-warning text-dark pending-count"><?php echo $pending_count; ?></span>
                                <?php endif; ?>
                            </a>
                        </li>
                        <?php endif; ?>
                        
                        <!-- My Requests - For authenticated users -->
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('request_history.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'request_history.php' : 'pages/request_history.php'; ?>">
                                <i class="fas fa-history"></i>My Requests
                            </a>
                        </li>
                        
                        <!-- EDL Viewer - Always visible to authenticated users -->
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('edl_viewer.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'edl_viewer.php' : 'pages/edl_viewer.php'; ?>">
                                <i class="fas fa-list"></i>EDL Viewer
                            </a>
                        </li>
                        
                        <!-- Denied Entries - Always visible to authenticated users -->
                        <li class="nav-item">
                            <a class="nav-link <?php echo isActive('denied_entries.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'denied_entries.php' : 'pages/denied_entries.php'; ?>">
                                <i class="fas fa-ban"></i>Denied Entries
                            </a>
                        </li>
                        
                        <!-- Admin Dropdown - For users with manage permission -->
                        <?php if (in_array('manage', $user_permissions)): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle <?php echo $is_admin_page_active ? 'active' : ''; ?>" href="#" id="adminDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fas fa-cog"></i>Admin
                            </a>
                            <ul class="dropdown-menu" aria-labelledby="adminDropdown">
                                <!-- Integration Section -->
                                <li>
                                    <h6 class="dropdown-header">
                                        <i class="fas fa-server text-primary"></i>Integration
                                    </h6>
                                </li>
                                <li><a class="dropdown-item <?php echo isActive('okta_config.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'okta_config.php' : 'pages/okta_config.php'; ?>">
                                    <i class="fas fa-cloud text-primary"></i>Okta SSO Configuration
                                    <small class="text-muted d-block">Configure Single Sign-On</small>
                                </a></li>
                                <li><a class="dropdown-item <?php echo isActive('teams_config.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'teams_config.php' : 'pages/teams_config.php'; ?>">
                                    <i class="fab fa-microsoft text-info"></i>Teams Notifications
                                    <small class="text-muted d-block">Configure Teams webhooks</small>
                                </a></li>
                                <li><a class="dropdown-item <?php echo isActive('ssl_config.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'ssl_config.php' : 'pages/ssl_config.php'; ?>">
                                    <i class="fas fa-lock text-warning"></i>SSL/TLS Configuration
                                    <small class="text-muted d-block">Configure HTTPS encryption</small>
                                </a></li>
                                
                                <li><hr class="dropdown-divider"></li>
                                
                                <!-- Data Management Section -->
                                <li>
                                    <h6 class="dropdown-header">
                                        <i class="fas fa-database text-secondary"></i>Data Management
                                    </h6>
                                </li>
                                <li><a class="dropdown-item <?php echo isActive('denied_entries.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'denied_entries.php' : 'pages/denied_entries.php'; ?>">
                                    <i class="fas fa-ban text-danger"></i>Denied Entries
                                    <small class="text-muted d-block">View rejected requests</small>
                                </a></li>
                                <li><a class="dropdown-item <?php echo isActive('audit_log.php', $current_page); ?>" href="<?php echo $is_in_pages ? 'audit_log.php' : 'pages/audit_log.php'; ?>">
                                    <i class="fas fa-clipboard-list text-warning"></i>Audit Log
                                    <small class="text-muted d-block">System activity log</small>
                                </a></li>
                            </ul>
                        </li>
                        <?php endif; ?>
                    </ul>
                </div>
                
                <!-- Right side user navigation -->
                <div class="navbar-nav-right">
                    <ul class="navbar-nav">
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fas fa-user-circle"></i><?php echo htmlspecialchars($user_name); ?>
                                <span class="role-badge role-<?php echo $user_role; ?>"><?php echo strtoupper($user_role); ?></span>
                            </a>
                            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                                <li>
                                    <h6 class="dropdown-header">
                                        <i class="fas fa-id-card text-primary"></i>User Profile
                                    </h6>
                                </li>
                                <li class="px-3 py-2">
                                    <small class="text-muted">Username:</small><br>
                                    <strong><?php echo htmlspecialchars($user_username); ?></strong>
                                </li>
                                <li class="px-3 py-2">
                                    <small class="text-muted">Email:</small><br>
                                    <strong><?php echo htmlspecialchars($user_email); ?></strong>
                                </li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item text-danger" href="<?php echo $base_path; ?>logout.php">
                                    <i class="fas fa-sign-out-alt"></i>Logout
                                </a></li>
                            </ul>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>
    
    <!-- Flash Messages -->
    <?php if ($flash): ?>
    <div class="main-container mt-3">
        <div class="alert alert-<?php echo $flash['type']; ?> alert-dismissible fade show" role="alert">
            <i class="fas fa-<?php echo $flash['type'] === 'success' ? 'check-circle' : ($flash['type'] === 'danger' ? 'exclamation-triangle' : 'info-circle'); ?>"></i>
            <?php echo htmlspecialchars($flash['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Dropdown Initialization Script -->
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize all dropdowns
        var dropdownElementList = [].slice.call(document.querySelectorAll('.dropdown-toggle'));
        var dropdownList = dropdownElementList.map(function (dropdownToggleEl) {
            return new bootstrap.Dropdown(dropdownToggleEl);
        });
        
        // Debug: Log if dropdowns are found
        console.log('Dropdowns initialized:', dropdownList.length);
        
        // Additional click handlers as fallback
        document.querySelectorAll('.dropdown-toggle').forEach(function(element) {
            element.addEventListener('click', function(e) {
                e.preventDefault();
                var dropdown = bootstrap.Dropdown.getInstance(this) || new bootstrap.Dropdown(this);
                dropdown.toggle();
            });
        });
    });
    </script>
    
    <!-- Main Content Container - DO NOT CLOSE THIS DIV - It's closed in footer.php -->
    <div class="main-container mt-4">