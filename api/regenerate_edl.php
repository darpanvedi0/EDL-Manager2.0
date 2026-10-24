<?php
// api/regenerate_edl.php - Regenerate EDL files endpoint
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/edl_lists.php';

header('Content-Type: application/json');

$auth = new EDLAuth();
if (!$auth->check_session() || !has_permission('manage')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Access denied']);
    exit;
}

// Lock so an approval can't land between reading the entries and writing the files
acquire_data_lock();

try {
    $result = write_edl_lists();
    if (!$result['written']) {
        throw new Exception('Failed to write EDL files. Check that edl-files/ is writable.');
    }
    
    $stats = [
        'ip_count' => $result['ip_count'],
        'domain_count' => $result['domain_count'],
        'url_count' => $result['url_count']
    ];
    
    // Log the regeneration
    append_audit_log([
        'id' => uniqid('audit_', true),
        'timestamp' => date('c'),
        'action' => 'regenerate_edl',
        'entry' => 'EDL Files',
        'user' => $_SESSION['username'],
        'details' => "Regenerated EDL files: {$stats['ip_count']} IPs, {$stats['domain_count']} domains, {$stats['url_count']} URLs"
    ]);
    
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

release_data_lock();
?>