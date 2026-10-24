<?php
// api/regenerate_edl.php - Regenerate EDL files endpoint
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

// Lock so an approval can't land between reading the entries and writing the files
acquire_data_lock();

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
    
    // Write EDL files atomically so firewalls never fetch a partial list
    $written = write_file_atomic(EDL_FILES_DIR . '/ip_blocklist.txt', implode("\n", $ip_list), 0644)
        && write_file_atomic(EDL_FILES_DIR . '/domain_blocklist.txt', implode("\n", $domain_list), 0644)
        && write_file_atomic(EDL_FILES_DIR . '/url_blocklist.txt', implode("\n", $url_list), 0644);
    if (!$written) {
        throw new Exception('Failed to write EDL files. Check that edl-files/ is writable.');
    }
    
    $stats = [
        'ip_count' => count($ip_list),
        'domain_count' => count($domain_list),
        'url_count' => count($url_list)
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