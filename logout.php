<?php
// logout.php - FIXED with correct paths
require_once 'config/config.php';
require_once 'includes/functions.php';

session_start();

// Check if user was logged in via Okta
$was_okta_user = isset($_SESSION['okta_authenticated']) && $_SESSION['okta_authenticated'];

// Clear the session
session_destroy();

// Get the correct base path
function get_app_base_path() {
    $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
    
    if (strpos($script_name, '/') !== false) {
        $path_parts = explode('/', trim($script_name, '/'));
        if (count($path_parts) > 1) {
            // Remove the last part (filename) and keep directory structure
            array_pop($path_parts);
            return '/' . implode('/', $path_parts) . '/';
        }
    }
    
    return '/';
}

$base_path = get_app_base_path();

// Redirect to login page with logged out message
header('Location: ' . $base_path . 'login.php?message=logged_out');
exit;
?>