<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

$auth = new EDLAuth();
if (!$auth->check_session() || !has_permission('manage')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Access denied']);
    exit;
}

try {
    $stats = generate_edl_files();
    
    // Log the regeneration
    add_audit_log(
        'regenerate',
        'EDL Files',
        $_SESSION['username'],
        "Regenerated EDL files: {$stats['ip_count']} IPs, {$stats['domain_count']} domains, {$stats['url_count']} URLs"
    );
    
    echo json_encode([
        'success' => true,
        'message' => 'EDL files regenerated successfully',
        'stats' => $stats
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>