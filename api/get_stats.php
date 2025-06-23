<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

$auth = new EDLAuth();
if (!$auth->check_session()) {
    http_response_code(403);
    echo json_encode(['error' => 'Not authenticated']);
    exit;
}

try {
    $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
    $pending_count = count(array_filter($pending_requests, fn($r) => $r['status'] === 'pending'));
    
    echo json_encode([
        'pending' => $pending_count,
        'timestamp' => time()
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
?>