<?php
// okta/login.php - Updated for org-level Okta auth
require_once '../config/config.php';
require_once '../includes/functions.php';

session_start();

try {
    // Try org-level Okta auth first
    $okta_auth = null;
    if (file_exists('../includes/okta_auth_org.php')) {
        require_once '../includes/okta_auth_org.php';
        if (class_exists('OktaAuthOrg')) {
            $okta_auth = new OktaAuthOrg();
            error_log('DEBUG: Using OktaAuthOrg for login');
        }
    }
    
    // Fallback to regular Okta auth
    if (!$okta_auth && file_exists('../includes/okta_auth.php')) {
        require_once '../includes/okta_auth.php';
        if (class_exists('OktaAuth')) {
            $okta_auth = new OktaAuth();
            error_log('DEBUG: Using OktaAuth for login');
        }
    }
    
    if (!$okta_auth) {
        throw new Exception('No Okta authentication class available');
    }
    
    if (!$okta_auth->is_enabled()) {
        show_flash('Okta SSO is not enabled', 'warning');
        $base_path = get_app_base_path();
        header('Location: ' . $base_path . 'login.php');
        exit;
    }
    
    $auth_url = $okta_auth->get_authorization_url();
    error_log('DEBUG: Redirecting to authorization URL: ' . $auth_url);
    header("Location: {$auth_url}");
    exit;
    
} catch (Exception $e) {
    error_log('Okta Login Error: ' . $e->getMessage());
    show_flash('SSO authentication failed: ' . $e->getMessage(), 'danger');
    $base_path = get_app_base_path();
    header('Location: ' . $base_path . 'login.php?error=okta_failed');
    exit;
}

// Helper function to get base path
function get_app_base_path() {
    $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
    
    if (strpos($script_name, '/') !== false) {
        $path_parts = explode('/', trim($script_name, '/'));
        if (count($path_parts) > 2) { // Remove filename and okta directory
            array_pop($path_parts); // Remove filename
            array_pop($path_parts); // Remove okta directory
            return '/' . implode('/', $path_parts) . '/';
        }
    }
    
    return '/';
}
?>
