<?php
// api/export_data.php - Export system data endpoint
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

session_start();

$auth = new EDLAuth();
if (!$auth->check_session() || !has_permission('manage')) {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied']);
    exit;
}

try {
    // Collect all system data
    $export_data = [
        'export_info' => [
            'version' => APP_VERSION ?? '2.0.0',
            'exported_at' => date('c'),
            'exported_by' => $_SESSION['username']
        ],
        'approved_entries' => read_json_file(DATA_DIR . '/approved_entries.json'),
        'pending_requests' => read_json_file(DATA_DIR . '/pending_requests.json'),
        'denied_entries' => read_json_file(DATA_DIR . '/denied_entries.json'),
        'audit_logs' => read_json_file(DATA_DIR . '/audit_logs.json'),
        'okta_config' => read_json_file(DATA_DIR . '/okta_config.json'),
        'users' => read_json_file(DATA_DIR . '/users.json')
    ];
    
    // Remove sensitive information
    if (isset($export_data['okta_config']['client_secret'])) {
        $export_data['okta_config']['client_secret'] = '***REDACTED***';
    }
    
    if (isset($export_data['users'])) {
        foreach ($export_data['users'] as &$user) {
            if (isset($user['password'])) {
                $user['password'] = '***REDACTED***';
            }
        }
    }
    
    // Set headers for download
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="edl_manager_backup_' . date('Y-m-d_H-i-s') . '.json"');
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Log the export
    $audit_logs = $export_data['audit_logs'];
    $audit_logs[] = [
        'id' => uniqid('audit_', true),
        'timestamp' => date('c'),
        'action' => 'export_data',
        'entry' => 'System Data',
        'user' => $_SESSION['username'],
        'details' => 'Exported system data backup'
    ];
    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
    
    echo json_encode($export_data, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
?>
