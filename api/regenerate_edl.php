<?php
// api/regenerate_edl.php - Regenerate EDL files endpoint
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

session_start();

$auth = new EDLAuth();
if (!$auth->check_session() || !has_permission('manage')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Access denied']);
    exit;
}

try {
    // Load approved entries
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $active_entries = array_filter($approved_entries, fn($e) => ($e['status'] ?? '') === 'active');
    
    $ip_list = [];
    $domain_list = [];
    $url_list = [];
    
    foreach ($active_entries as $entry) {
        switch ($entry['type'] ?? '') {
            case 'ip':
                $ip_list[] = $entry['entry'];
                break;
            case 'domain':
                $domain_list[] = $entry['entry'];
                break;
            case 'url':
                $url_list[] = $entry['entry'];
                break;
        }
    }
    
    // Ensure EDL files directory exists
    if (!is_dir(EDL_FILES_DIR)) {
        mkdir(EDL_FILES_DIR, 0755, true);
    }
    
    // Write EDL files
    file_put_contents(EDL_FILES_DIR . '/ip_blocklist.txt', implode("\n", $ip_list));
    file_put_contents(EDL_FILES_DIR . '/domain_blocklist.txt', implode("\n", $domain_list));
    file_put_contents(EDL_FILES_DIR . '/url_blocklist.txt', implode("\n", $url_list));
    
    $stats = [
        'ip_count' => count($ip_list),
        'domain_count' => count($domain_list),
        'url_count' => count($url_list)
    ];
    
    // Log the regeneration
    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
    $audit_logs[] = [
        'id' => uniqid('audit_', true),
        'timestamp' => date('c'),
        'action' => 'regenerate_edl',
        'entry' => 'EDL Files',
        'user' => $_SESSION['username'],
        'details' => "Regenerated EDL files: {$stats['ip_count']} IPs, {$stats['domain_count']} domains, {$stats['url_count']} URLs"
    ];
    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
    
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