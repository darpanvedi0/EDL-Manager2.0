<?php
// okta/callback.php - FIXED with correct paths
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/okta_auth.php';

session_start();

try {
    $code = $_GET['code'] ?? '';
    $state = $_GET['state'] ?? '';
    $error = $_GET['error'] ?? '';
    
    if ($error) {
        throw new Exception("Okta Error: {$error}");
    }
    
    if (empty($code)) {
        throw new Exception('No authorization code received');
    }
    
    $okta_auth = new OktaAuth();
    $okta_auth->handle_callback($code, $state);
    
    // Successful authentication
    show_flash('Successfully logged in via Okta SSO', 'success');
    $base_path = get_app_base_path();
    header('Location: ' . $base_path . 'index.php');
    exit;
    
} catch (Exception $e) {
    error_log('Okta Callback Error: ' . $e->getMessage());
    show_flash('SSO authentication failed: ' . $e->getMessage(), 'danger');
    $base_path = get_app_base_path();
    header('Location: ' . $base_path . 'login.php');
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