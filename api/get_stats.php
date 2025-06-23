<?php
// api/get_stats.php - Get statistics endpoint (updated)
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

session_start();

$auth = new EDLAuth();
if (!$auth->check_session()) {
    http_response_code(403);
    echo json_encode(['error' => 'Not authenticated']);
    exit;
}

try {
    $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
    $pending_count = count(array_filter($pending_requests, fn($r) => ($r['status'] ?? '') === 'pending'));
    
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $active_count = count(array_filter($approved_entries, fn($e) => ($e['status'] ?? '') === 'active'));
    
    $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
    $denied_count = count($denied_entries);
    
    // Count by type
    $type_counts = ['ip' => 0, 'domain' => 0, 'url' => 0];
    foreach ($approved_entries as $entry) {
        if (($entry['status'] ?? '') === 'active' && isset($entry['type']) && isset($type_counts[$entry['type']])) {
            $type_counts[$entry['type']]++;
        }
    }
    
    echo json_encode([
        'pending' => $pending_count,
        'active' => $active_count,
        'denied' => $denied_count,
        'type_counts' => $type_counts,
        'timestamp' => time()
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
?>