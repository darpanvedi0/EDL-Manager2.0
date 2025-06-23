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

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['entry']) || !isset($input['type'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

$entry = trim($input['entry']);
$type = $input['type'];

// Auto-detect type if needed
if ($type === 'auto' && !empty($entry)) {
    if (preg_match('/^https?:\/\//', $entry)) {
        $type = 'url';
    } elseif (filter_var($entry, FILTER_VALIDATE_IP) || preg_match('/^[\d\.\/]+$/', $entry)) {
        $type = 'ip';
    } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $entry)) {
        $type = 'domain';
    }
}

try {
    $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
    
    foreach ($denied_entries as $denied) {
        if ($denied['entry'] === $entry && $denied['type'] === $type) {
            // Found a match - entry is denied
            $denied_date = isset($denied['denied_at']) ? date('M j, Y', strtotime($denied['denied_at'])) : 'Unknown';
            
            echo json_encode([
                'denied' => true,
                'reason' => $denied['reason'] ?? 'No reason provided',
                'denied_by' => $denied['denied_by'] ?? 'Admin',
                'denied_date' => $denied_date,
                'entry' => $entry,
                'type' => $type
            ]);
            exit;
        }
    }
    
    // Not found in denied list
    echo json_encode([
        'denied' => false,
        'entry' => $entry,
        'type' => $type
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
?>