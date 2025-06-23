<?php
require_once 'config/config.php';
require_once 'includes/auth.php';

$auth = new EDLAuth();
$auth->logout();

// Redirect to login page
header('Location: login.php');
exit;
?>