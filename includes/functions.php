<?php
// includes/functions.php - Complete EDL Manager Functions

function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function csrf_token_field() {
    return '<input type="hidden" name="csrf_token" value="' . generate_csrf_token() . '">';
}

function read_json_file($file) {
    if (!file_exists($file)) {
        return [];
    }
    $content = file_get_contents($file);
    return $content ? json_decode($content, true) : [];
}

function write_json_file($file, $data) {
    $dir = dirname($file);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    return file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

function show_flash($message, $type = 'info') {
    $_SESSION['flash_message'] = $message;
    $_SESSION['flash_type'] = $type;
}

function get_flash() {
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        $type = $_SESSION['flash_type'] ?? 'info';
        unset($_SESSION['flash_message'], $_SESSION['flash_type']);
        return ['message' => $message, 'type' => $type];
    }
    return null;
}

// Additional utility functions for EDL Manager

function validate_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function validate_domain($domain) {
    return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
           preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $domain);
}

function validate_url($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

function get_entry_type($entry) {
    if (validate_url($entry)) {
        return 'url';
    } elseif (validate_ip($entry)) {
        return 'ip';
    } elseif (validate_domain($entry)) {
        return 'domain';
    }
    return 'unknown';
}

function format_datetime($datetime, $format = 'M j, Y H:i') {
    if (empty($datetime)) {
        return 'Unknown';
    }
    $timestamp = is_numeric($datetime) ? $datetime : strtotime($datetime);
    return $timestamp ? date($format, $timestamp) : 'Invalid Date';
}

function get_priority_badge($priority) {
    $badges = [
        'low' => '<span class="badge bg-secondary">🔵 Low</span>',
        'medium' => '<span class="badge bg-warning text-dark">🟡 Medium</span>',
        'high' => '<span class="badge bg-danger">🟠 High</span>',
        'critical' => '<span class="badge bg-dark">🔴 Critical</span>'
    ];
    return $badges[$priority] ?? '<span class="badge bg-secondary">Unknown</span>';
}

function get_status_badge($status) {
    $badges = [
        'pending' => '<span class="badge bg-warning text-dark">⏳ Pending</span>',
        'approved' => '<span class="badge bg-success">✅ Approved</span>',
        'denied' => '<span class="badge bg-danger">❌ Denied</span>'
    ];
    return $badges[$status] ?? '<span class="badge bg-secondary">Unknown</span>';
}

function get_type_icon($type) {
    $icons = [
        'ip' => '<i class="fas fa-network-wired text-primary"></i>',
        'domain' => '<i class="fas fa-globe text-success"></i>',
        'url' => '<i class="fas fa-link text-info"></i>'
    ];
    return $icons[$type] ?? '<i class="fas fa-question-circle text-muted"></i>';
}

function generate_unique_id($prefix = 'id') {
    return $prefix . '_' . uniqid() . '_' . bin2hex(random_bytes(4));
}

function is_valid_servicenow_ticket($ticket) {
    $patterns = [
        '/^INC\d{7}$/',     // Incident
        '/^REQ\d{7}$/',     // Request
        '/^CHG\d{7}$/',     // Change
        '/^RITM\d{7}$/',    // Request Item
        '/^TASK\d{7}$/',    // Task
        '/^SCTASK\d{7}$/'   // Service Catalog Task
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, strtoupper($ticket))) {
            return true;
        }
    }
    return false;
}

function log_activity($action, $details = '', $entry = '', $user = null) {
    $user = $user ?? ($_SESSION['username'] ?? 'system');
    
    $log_entry = [
        'id' => generate_unique_id('audit'),
        'timestamp' => date('c'),
        'action' => $action,
        'entry' => $entry,
        'user' => $user,
        'details' => $details,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    
    $logs = read_json_file(DATA_DIR . '/audit_logs.json');
    $logs[] = $log_entry;
    
    // Keep only last 10,000 logs to prevent file from growing too large
    if (count($logs) > 10000) {
        $logs = array_slice($logs, -10000);
    }
    
    return write_json_file(DATA_DIR . '/audit_logs.json', $logs);
}

function clean_old_logs($days = 90) {
    $cutoff_date = strtotime("-{$days} days");
    
    $logs = read_json_file(DATA_DIR . '/audit_logs.json');
    $cleaned_logs = array_filter($logs, function($log) use ($cutoff_date) {
        $log_time = strtotime($log['timestamp'] ?? '');
        return $log_time && $log_time > $cutoff_date;
    });
    
    return write_json_file(DATA_DIR . '/audit_logs.json', array_values($cleaned_logs));
}

function backup_data($backup_dir = 'backups') {
    if (!is_dir($backup_dir)) {
        mkdir($backup_dir, 0755, true);
    }
    
    $timestamp = date('Y-m-d_H-i-s');
    $backup_file = "{$backup_dir}/edl_backup_{$timestamp}.zip";
    
    if (class_exists('ZipArchive')) {
        $zip = new ZipArchive();
        if ($zip->open($backup_file, ZipArchive::CREATE) === TRUE) {
            $files = glob(DATA_DIR . '/*.json');
            foreach ($files as $file) {
                $zip->addFile($file, basename($file));
            }
            $zip->close();
            return $backup_file;
        }
    }
    return false;
}

function get_system_stats() {
    $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
    
    return [
        'pending_requests' => count($pending_requests),
        'approved_entries' => count($approved_entries),
        'denied_entries' => count($denied_entries),
        'total_logs' => count($audit_logs),
        'recent_activity' => array_slice(array_reverse($audit_logs), 0, 5)
    ];
}

echo "<!-- EDL Manager Functions loaded successfully -->\n";
?>