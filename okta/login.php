<?php
// okta/login.php - FIXED with correct paths
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/okta_auth.php';

session_start();

try {
    $okta_auth = new OktaAuth();
    
    if (!$okta_auth->is_enabled()) {
        show_flash('Okta SSO is not enabled', 'warning');
        $base_path = get_app_base_path();
        header('Location: ' . $base_path . 'login.php');
        exit;
    }
    
    $auth_url = $okta_auth->get_authorization_url();
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
